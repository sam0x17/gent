//! Static dashboard graphics shared by the native desktop frontends.
use colors::{Color, Colors};
use serde::Deserialize;
use serde_json::Value;
use std::fmt::Write;

mod cartesian;
mod categories;
mod colors;
mod horizontal;
mod scale;
#[cfg(test)]
mod tests;

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Palette {
    pub(super) surface: [u8; 3],
    pub(super) text: [u8; 3],
    pub(super) secondary: [u8; 3],
    pub(super) accent: [u8; 3],
}

// Local fixtures predating palette negotiation use a neutral light surface.
impl Default for Palette {
    fn default() -> Self {
        Self {
            surface: [250, 250, 250],
            text: [36, 38, 40],
            secondary: [85, 88, 92],
            accent: [44, 94, 122],
        }
    }
}

pub(super) fn decorate(widget: &mut Value, palette: &Palette, width: usize) {
    let Some(fields) = widget.as_object_mut() else {
        return;
    };
    // Only the renderer can supply markup, including when reusing a widget.
    fields.remove("chart_svg");
    fields.remove("chart_description");
    let Some(kind) = fields.get("kind").and_then(Value::as_str) else {
        return;
    };
    let Some(values) = fields.get("value").and_then(Value::as_array) else {
        return;
    };
    let field = |name| fields.get(name).and_then(Value::as_str).map(clean_text);
    let label = field("label")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Value".into());
    let unit = field("unit").filter(|s| !s.is_empty());
    let width = width.clamp(160, 16_384);
    let chart = match kind {
        "graph" | "scatter" if values.len() <= 256 => cartesian::render(
            kind,
            values,
            &label,
            unit.as_deref(),
            field("x_unit").as_deref(),
            palette,
            width,
        ),
        "bar" | "pie" | "radar" if values.len() <= 16 => {
            categories::render(kind, values, &label, unit.as_deref(), palette, width)
        }
        _ => None,
    };
    if let Some(chart) = chart {
        fields.insert("chart_svg".into(), Value::String(chart.svg()));
        fields.insert("chart_description".into(), Value::String(chart.description));
    }
}

fn number(value: &Value) -> Option<f64> {
    value.as_f64().filter(|n| n.is_finite())
}

fn clean_text(input: &str) -> String {
    input
        .chars()
        .take(128)
        .map(|c| match c {
            '\u{fffe}' | '\u{ffff}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// Conservative advances at the native SVG font size of 10 logical pixels.
fn glyph_width(c: char) -> usize {
    match c {
        'm' | 'w' | 'M' | 'W' | '@' | '%' => 10,
        'i' | 'j' | 'l' | 'I' => 4,
        'A'..='Z' => 9,
        'a'..='z' | '0'..='9' => 7,
        ' ' | '.' | ',' | ':' | '-' | '·' => 4,
        _ => 11,
    }
}

fn text_width(input: &str) -> usize {
    input.chars().map(glyph_width).sum()
}

fn fit(input: &str, pixels: usize) -> String {
    if text_width(input) <= pixels {
        return input.to_owned();
    }
    let Some(mut remaining) = pixels.checked_sub(glyph_width('…')) else {
        return String::new();
    };
    let mut label = String::new();
    for c in input.chars() {
        let Some(next) = remaining.checked_sub(glyph_width(c)) else {
            break;
        };
        label.push(c);
        remaining = next;
    }
    label.push('…');
    label
}

struct Chart {
    width: usize,
    colors: Colors,
    height: usize,
    description: String,
    body: String,
}

impl Chart {
    fn new(width: usize, height: usize, description: String, palette: &Palette) -> Self {
        Self {
            width,
            height,
            description,
            body: String::new(),
            colors: Colors::new(palette),
        }
    }

    fn svg(&self) -> String {
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img"><title>{desc}</title><g font-family="sans-serif" font-size="10">{body}</g></svg>"##,
            w = self.width,
            h = self.height,
            desc = escape(&self.description),
            body = self.body,
        )
    }

    fn text(&mut self, x: f64, y: f64, anchor: &str, text: &str) {
        self.colored_text(x, y, anchor, text, self.colors.text);
    }

    fn secondary_text(&mut self, x: f64, y: f64, anchor: &str, text: &str) {
        self.colored_text(x, y, anchor, text, self.colors.secondary);
    }

    // Preserve every digit in origins and ring scales, wrapping only as needed.
    // Subsequent content starts below the returned baseline.
    fn caption(&mut self, x: f64, mut y: usize, anchor: &str, text: &str, pixels: usize) -> usize {
        let mut line = String::new();
        for word in text.split_whitespace() {
            if !line.is_empty() {
                if text_width(&line) + glyph_width(' ') + text_width(word) > pixels {
                    self.secondary_text(x, y as f64, anchor, &line);
                    y += 13;
                    line.clear();
                } else {
                    line.push(' ');
                }
            }
            for c in word.chars() {
                if text_width(&line) + glyph_width(c) > pixels {
                    self.secondary_text(x, y as f64, anchor, &line);
                    y += 13;
                    line.clear();
                }
                line.push(c);
            }
        }
        self.secondary_text(x, y as f64, anchor, &line);
        y
    }

    fn colored_text(&mut self, x: f64, y: f64, anchor: &str, text: &str, color: Color) {
        write!(
            self.body,
            r#"<text x="{x:.2}" y="{y:.2}" fill="{color}" text-anchor="{anchor}">{}</text>"#,
            escape(text)
        )
        .unwrap();
    }

    fn line(&mut self, x: f64, y: f64, end_x: f64, end_y: f64, color: Color) {
        write!(
            self.body,
            r#"<line x1="{x:.2}" y1="{y:.2}" x2="{end_x:.2}" y2="{end_y:.2}" stroke="{color}" stroke-width="0.6"/>"#
        )
        .unwrap();
    }

    // A narrow surface-colored rim separates samples that land on an axis,
    // a gridline or another sample.
    fn mark(&mut self, x: f64, y: f64) {
        write!(
            self.body,
            r#"<circle cx="{x:.2}" cy="{y:.2}" r="1.8" fill="{}" stroke="{}" stroke-width="0.4"/>"#,
            self.colors.accent, self.colors.surface
        )
        .unwrap();
    }

    fn dot(&mut self, x: f64, y: f64, radius: f64, color: Color) {
        write!(
            self.body,
            r#"<circle cx="{x:.2}" cy="{y:.2}" r="{radius}" fill="{color}"/>"#
        )
        .unwrap();
    }
}
