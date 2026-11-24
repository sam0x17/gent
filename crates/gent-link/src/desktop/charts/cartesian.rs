use super::{
    Chart, Palette, fit,
    horizontal::{EDGE, GAP, HorizontalAxis},
    number,
    scale::{Axis, exact_number},
    text_width,
};
use serde_json::Value;
use std::fmt::Write;

type Point = (f64, f64);
const TOP: usize = 26;

fn extent(points: &[Point], get: impl Fn(&Point) -> f64) -> (f64, f64) {
    points
        .iter()
        .map(get)
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), n| {
            (lo.min(n), hi.max(n))
        })
}

pub(super) fn render(
    kind: &str,
    values: &[Value],
    label: &str,
    unit: Option<&str>,
    x_unit: Option<&str>,
    palette: &Palette,
    width: usize,
) -> Option<Chart> {
    let graph = kind == "graph";
    let points = values
        .iter()
        .enumerate()
        .map(|(i, value)| {
            if graph {
                Some((i as f64 + 1.0, number(value)?))
            } else {
                let [x, y] = value.as_array()?.as_slice() else {
                    return None;
                };
                Some((number(x)?, number(y)?))
            }
        })
        .collect::<Option<Vec<Point>>>()?;
    let x_label = if graph {
        "Sample"
    } else {
        x_unit.filter(|s| !s.is_empty()).unwrap_or("X")
    };
    let y_label = unit.unwrap_or(label);
    if points.is_empty() {
        let mut chart = Chart::new(
            width,
            74,
            format!("{label}. No data. Axes: {x_label}, {y_label}."),
            palette,
        );
        chart.text(
            width as f64 / 2.0,
            18.0,
            "middle",
            &fit(y_label, width - 16),
        );
        chart.text(
            width as f64 / 2.0,
            42.0,
            "middle",
            if graph { "No samples" } else { "No points" },
        );
        chart.text(
            width as f64 / 2.0,
            66.0,
            "middle",
            &fit(x_label, width - 16),
        );
        return Some(chart);
    }
    let (min_x, max_x) = extent(&points, |p| p.0);
    let (min_y, max_y) = extent(&points, |p| p.1);
    let x_axis = Axis::new(min_x, max_x);
    let y_axis = Axis::new(min_y, max_y);
    let y_ticks: Vec<_> = y_axis
        .ticks(4)
        .into_iter()
        .map(|n| (n, y_axis.tick_label(n)))
        .collect();
    let y_tick_width = y_ticks
        .iter()
        .map(|(_, label)| text_width(label))
        .max()
        .unwrap();
    let layout = HorizontalAxis::new(
        x_axis,
        graph.then_some(points.len()),
        width,
        y_tick_width as f64 + GAP,
    );
    let (left, right) = (layout.left, layout.right);
    let plot_height = (width * 2 / 5).clamp(84, 176);
    let bottom = TOP + plot_height;
    let x = |n| left + x_axis.fraction(n) * (right - left);
    let y = |n| bottom as f64 - y_axis.fraction(n) * plot_height as f64;
    let description = format!(
        "{label}. {} {}. {x_label}: {} to {}. {y_label}: {} to {}.",
        points.len(),
        if graph { "samples" } else { "points" },
        exact_number(min_x),
        exact_number(max_x),
        exact_number(min_y),
        exact_number(max_y)
    );
    let mut chart = Chart::new(width, bottom, description, palette);
    let colors = chart.colors;
    chart.text(
        left,
        14.0,
        "start",
        &fit(y_label, (width as f64 - EDGE - left) as usize),
    );
    for (tick, label) in y_ticks {
        chart.line(left, y(tick), right, y(tick), colors.grid);
        chart.secondary_text(left - GAP, y(tick) + 3.0, "end", &label);
    }
    chart.line(left, TOP as f64, left, bottom as f64, colors.secondary);
    let caption_y = layout.draw(&mut chart, bottom) + 15;
    chart.text(
        (left + right) / 2.0,
        caption_y as f64,
        "middle",
        &fit(x_label, (right - left) as usize),
    );
    chart.height = caption_y + 5;
    for (axis_name, axis) in [("X", x_axis), ("Y", y_axis)] {
        if let Some(origin) = axis.origin_label() {
            chart.height = chart.caption(
                EDGE,
                chart.height + 10,
                "start",
                &format!("{axis_name} {origin}"),
                width - 12,
            ) + 5;
        }
    }
    let pixels: Vec<_> = points.iter().map(|&(a, b)| (x(a), y(b))).collect();
    if graph && pixels.len() > 1 {
        let path = spline(&pixels);
        write!(chart.body, r#"<path d="{path}" fill="none" stroke="{}" stroke-width="1.25" stroke-linejoin="round" stroke-linecap="round"/>"#, colors.accent).unwrap();
    }
    if !graph || pixels.len() <= 12 {
        for (a, b) in pixels {
            chart.mark(a, b);
        }
    }
    Some(chart)
}

// Uniform sample spacing permits the harmonic-mean PCHIP tangent. At a
// reversal or plateau the derivative is zero on both adjoining segments.
fn spline(points: &[Point]) -> String {
    let delta: Vec<_> = points.windows(2).map(|p| p[1].1 - p[0].1).collect();
    let mut tangents = vec![delta[0]];
    for pair in delta.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        tangents.push(if a * b > 0.0 {
            2.0 * a * b / (a + b)
        } else {
            0.0
        });
    }
    tangents.push(*delta.last().unwrap());
    let mut path = format!("M{:.2},{:.2}", points[0].0, points[0].1);
    for (i, pair) in points.windows(2).enumerate() {
        let ((x0, y0), (x1, y1)) = (pair[0], pair[1]);
        let dx = (x1 - x0) / 3.0;
        write!(
            path,
            " C{:.2},{:.2} {:.2},{:.2} {x1:.2},{y1:.2}",
            x0 + dx,
            y0 + tangents[i] / 3.0,
            x1 - dx,
            y1 - tangents[i + 1] / 3.0
        )
        .unwrap();
    }
    path
}
