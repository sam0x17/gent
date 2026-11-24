use super::{Category, Chart, PolarPlot, format_number, text_width};
use std::fmt::Write;

// Spokes above and below the center take centered labels. Labels to either
// side grow outwards so the text never covers the plotted values.
fn label_position(plot: PolarPlot, turn: f64, radius: f64) -> (f64, f64, &'static str) {
    let (x, y) = plot.point(turn, radius + 8.0);
    let anchor = if (x - plot.cx).abs() < 1.0 {
        "middle"
    } else if x < plot.cx {
        "end"
    } else {
        "start"
    };
    (x, y + 3.0, anchor)
}

fn names_fit(plot: PolarPlot, items: &[Category], radius: f64) -> bool {
    let mut occupied = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let (x, y, anchor) = label_position(plot, i as f64 / items.len() as f64, radius);
        let width = text_width(&item.name) as f64;
        let left = match anchor {
            "end" => x - width,
            "middle" => x - width / 2.0,
            _ => x,
        };
        let right = left + width;
        if left < (plot.left + 5) as f64 || right > (plot.left + plot.width - 5) as f64 {
            return false;
        }
        if occupied.iter().any(|&(l, r, baseline): &(f64, f64, f64)| {
            left < r + 4.0 && right + 4.0 > l && (baseline - y).abs() < 13.0
        }) {
            return false;
        }
        occupied.push((left, right, y));
    }
    true
}

pub(super) fn draw(
    chart: &mut Chart,
    plot: PolarPlot,
    items: &[Category],
    max: f64,
    unit: Option<&str>,
) -> (bool, usize) {
    let named_radius = [plot.radius, plot.radius * 0.86, plot.radius * 0.74]
        .into_iter()
        .find(|&radius| items.len() <= 6 && names_fit(plot, items, radius));
    let radius = named_radius.unwrap_or(plot.radius);
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
            let (x, y) = plot.point(turn(i), radius * ring);
            write!(coordinates, "{x:.2},{y:.2} ").unwrap();
        }
        write!(
            chart.body,
            r#"<polygon points="{coordinates}" fill="none" stroke="{}" stroke-width="0.6"/>"#,
            chart.colors.grid
        )
        .unwrap();
    }
    let mut shape = String::new();
    let mut markers = Vec::new();
    let mut lowest_label = plot.cy;
    for (i, item) in items.iter().enumerate() {
        let (x, y) = plot.point(turn(i), radius);
        chart.line(plot.cx, plot.cy, x, y, chart.colors.grid);
        let (x, y, anchor) = label_position(plot, turn(i), radius);
        lowest_label = lowest_label.max(y);
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
        let point = plot.point(turn(i), distance);
        write!(shape, "{:.2},{:.2} ", point.0, point.1).unwrap();
        markers.push(point);
    }
    write!(chart.body, r#"<polygon points="{shape}" fill="{0}" fill-opacity="0.18" stroke="{0}" stroke-width="1.25" stroke-linejoin="round"/>"#, chart.colors.accent).unwrap();
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
    write!(chart.description, " {scale}.").unwrap();
    let bottom = chart.caption(
        plot.cx,
        lowest_label.ceil() as usize + 15,
        "middle",
        &scale,
        plot.width - 12,
    ) + 3;
    (named_radius.is_none(), bottom)
}
