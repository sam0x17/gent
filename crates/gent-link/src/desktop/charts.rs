//! Static dashboard graphics shared by the native desktop frontends.
use colors::{Color, Colors};
use serde::Deserialize;
use serde_json::Value;
use std::fmt::Write;

mod cartesian;
mod categories;
mod colors;
mod scale;
#[cfg(test)]
mod tests;

const WIDTH: usize = 260;

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

pub(super) fn decorate(widget: &mut Value, palette: &Palette) {
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
    let chart = match kind {
        "graph" | "scatter" if values.len() <= 256 => cartesian::render(
            kind,
            values,
            &label,
            unit.as_deref(),
            field("x_unit").as_deref(),
            palette,
        ),
        "bar" | "pie" | "radar" if values.len() <= 16 => {
            categories::render(kind, values, &label, unit.as_deref(), palette)
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

// Conservative advances at the SVG's 12 px font size. Native font
// substitutions and full-width glyphs need room on a 260 px card.
fn glyph_width(c: char) -> usize {
    match c {
        'm' | 'w' | 'M' | 'W' | '@' => 12,
        'a'..='z' | '0'..='9' => 8,
        ' ' | '.' | ',' | ':' => 5,
        _ => 12,
    }
}

fn text_width(input: &str) -> usize {
    input.chars().map(glyph_width).sum()
}

fn fit(input: &str, pixels: usize) -> String {
    if text_width(input) <= pixels {
        return input.to_owned();
    }
    let mut remaining = pixels.saturating_sub(12);
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
    colors: Colors,
    height: usize,
    description: String,
    body: String,
}

impl Chart {
    fn new(height: usize, description: String, palette: &Palette) -> Self {
        Self {
            height,
            description,
            body: String::new(),
            colors: Colors::new(palette),
        }
    }

    fn svg(&self) -> String {
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{h}" viewBox="0 0 {WIDTH} {h}" role="img"><title>{desc}</title><g font-family="sans-serif" font-size="12">{body}</g></svg>"##,
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
            r#"<line x1="{x:.2}" y1="{y:.2}" x2="{end_x:.2}" y2="{end_y:.2}" stroke="{color}"/>"#
        )
        .unwrap();
    }

    // A narrow surface-colored rim separates samples that land on an axis,
    // a gridline or another sample.
    fn mark(&mut self, x: f64, y: f64) {
        write!(
            self.body,
            r#"<circle cx="{x:.2}" cy="{y:.2}" r="3" fill="{}" stroke="{}" stroke-width="0.8"/>"#,
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
