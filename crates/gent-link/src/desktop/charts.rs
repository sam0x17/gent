//! Static dashboard graphics shared by the native desktop frontends.
use serde_json::Value;
use std::fmt::Write;

mod cartesian;
mod categories;
mod scale;
#[cfg(test)]
mod tests;

const INK: &str = "#253342";
const GRID: &str = "#c8cfd6";
const SERIES: &str = "#245d78";
const WIDTH: usize = 260;

pub(super) fn decorate(widget: &mut Value) {
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
        ),
        "bar" | "pie" | "radar" if values.len() <= 16 => {
            categories::render(kind, values, &label, unit.as_deref())
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
    height: usize,
    description: String,
    body: String,
}

impl Chart {
    fn new(height: usize, description: String) -> Self {
        Self {
            height,
            description,
            body: String::new(),
        }
    }

    fn svg(&self) -> String {
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{h}" viewBox="0 0 {WIDTH} {h}" role="img"><title>{desc}</title><rect width="{WIDTH}" height="{h}" fill="#ffffff"/><g font-family="sans-serif" font-size="12" fill="{INK}">{body}</g></svg>"##,
            h = self.height,
            desc = escape(&self.description),
            body = self.body,
        )
    }

    fn text(&mut self, x: f64, y: f64, anchor: &str, text: &str) {
        write!(
            self.body,
            r#"<text x="{x:.2}" y="{y:.2}" text-anchor="{anchor}">{}</text>"#,
            escape(text)
        )
        .unwrap();
    }

    fn line(&mut self, x: f64, y: f64, end_x: f64, end_y: f64, color: &str) {
        write!(
            self.body,
            r#"<line x1="{x:.2}" y1="{y:.2}" x2="{end_x:.2}" y2="{end_y:.2}" stroke="{color}"/>"#
        )
        .unwrap();
    }

    fn dot(&mut self, x: f64, y: f64, radius: f64, color: &str) {
        write!(
            self.body,
            r#"<circle cx="{x:.2}" cy="{y:.2}" r="{radius}" fill="{color}"/>"#
        )
        .unwrap();
    }
}
