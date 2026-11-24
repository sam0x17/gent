use super::{CX, Category, Chart, RADIUS, format_number, polar, text_width};
use std::fmt::Write;

// Spokes above and below the center take centered labels. Labels to either
// side grow outwards so the text never covers the plotted values.
fn label_position(turn: f64, radius: f64) -> (f64, f64, &'static str) {
    let (x, y) = polar(turn, radius + 10.0);
    let anchor = if (x - CX).abs() < 1.0 {
        "middle"
    } else if x < CX {
        "end"
    } else {
        "start"
    };
    (x, y + 4.0, anchor)
}

fn names_fit(items: &[Category], radius: f64) -> bool {
    let mut occupied = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let (x, y, anchor) = label_position(i as f64 / items.len() as f64, radius);
        let width = text_width(&item.name) as f64;
        let left = match anchor {
            "end" => x - width,
            "middle" => x - width / 2.0,
            _ => x,
        };
        let right = left + width;
        if left < 5.0 || right > 255.0 || !(33.0..=187.0).contains(&y) {
            return false;
        }
        if occupied.iter().any(|&(l, r, baseline): &(f64, f64, f64)| {
            left < r + 4.0 && right + 4.0 > l && (baseline - y).abs() < 16.0
        }) {
            return false;
        }
        occupied.push((left, right, y));
    }
    true
}

pub(super) fn draw(chart: &mut Chart, items: &[Category], max: f64, unit: Option<&str>) -> bool {
    let named_radius = [RADIUS, 56.0, 48.0]
        .into_iter()
        .find(|&radius| items.len() <= 6 && names_fit(items, radius));
    let radius = named_radius.unwrap_or(RADIUS);
    let turn = |i: usize| i as f64 / items.len() as f64;
    let percentage = unit == Some("%") && max <= 100.0;
    let limit = if percentage { 100.0 } else { max };
    let rings: &[f64] = if percentage {
        &[0.25, 0.5, 0.75, 1.0]
    } else {
        &[0.5, 1.0]
    };
    for ring in rings {
        let mut coordinates = String::new();
        for i in 0..items.len() {
            let (x, y) = polar(turn(i), radius * ring);
            write!(coordinates, "{x:.2},{y:.2} ").unwrap();
        }
        write!(
            chart.body,
            r#"<polygon points="{coordinates}" fill="none" stroke="{}"/>"#,
            chart.colors.grid
        )
        .unwrap();
    }
    let mut shape = String::new();
    let mut markers = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let (x, y) = polar(turn(i), radius);
        chart.line(CX, super::CY, x, y, chart.colors.grid);
        let (x, y, anchor) = label_position(turn(i), radius);
        if named_radius.is_some() {
            chart.text(x, y, anchor, &item.name);
        } else {
            chart.secondary_text(x, y, "middle", &(i + 1).to_string());
        }
        let distance = if limit == 0.0 {
            0.0
        } else {
            radius * (item.value / limit)
        };
        let point = polar(turn(i), distance);
        write!(shape, "{:.2},{:.2} ", point.0, point.1).unwrap();
        markers.push(point);
    }
    write!(chart.body, r#"<polygon points="{shape}" fill="{0}" fill-opacity="0.18" stroke="{0}" stroke-width="2" stroke-linejoin="round"/>"#, chart.colors.accent).unwrap();
    for (x, y) in markers {
        chart.mark(x, y);
    }
    let scale = if percentage {
        "Center 0% · Rings 25%, 50%, 75%, 100%".to_owned()
    } else if max == 0.0 {
        "All values are zero".to_owned()
    } else {
        format!(
            "Rings: {} / {}",
            format_number(max / 2.0),
            format_number(max)
        )
    };
    chart.secondary_text(CX, 202.0, "middle", &scale);
    write!(chart.description, " {scale}.").unwrap();
    chart.height = 212;
    named_radius.is_none()
}
