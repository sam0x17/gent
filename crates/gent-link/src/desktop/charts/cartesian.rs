use super::{
    Chart, GRID, INK, SERIES, fit, number,
    scale::{Axis, exact_number},
};
use serde_json::Value;
use std::fmt::Write;

type Point = (f64, f64);
const LEFT: f64 = 76.0;
const RIGHT: f64 = 222.0;
const TOP: f64 = 32.0;
const BOTTOM: f64 = 135.0;

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
        let mut chart = Chart::new(84, format!("{label}. No data. Axes: {x_label}, {y_label}."));
        chart.text(130.0, 24.0, "middle", &fit(y_label, 244));
        chart.text(
            130.0,
            49.0,
            "middle",
            if graph { "No samples" } else { "No points" },
        );
        chart.text(130.0, 74.0, "middle", &fit(x_label, 244));
        return Some(chart);
    }
    let (min_x, max_x) = extent(&points, |p| p.0);
    let (min_y, max_y) = extent(&points, |p| p.1);
    let x_axis = Axis::new(min_x, max_x);
    let y_axis = Axis::new(min_y, max_y);
    let x = |n| LEFT + x_axis.fraction(n) * (RIGHT - LEFT);
    let y = |n| BOTTOM - y_axis.fraction(n) * (BOTTOM - TOP);
    let description = format!(
        "{label}. {} {}. {x_label}: {} to {}. {y_label}: {} to {}.",
        points.len(),
        if graph { "samples" } else { "points" },
        exact_number(min_x),
        exact_number(max_x),
        exact_number(min_y),
        exact_number(max_y)
    );
    let mut chart = Chart::new(178, description);
    chart.text(8.0, 17.0, "start", &fit(y_label, 244));
    for tick in y_axis.ticks(4) {
        chart.line(LEFT, y(tick), RIGHT, y(tick), GRID);
        chart.text(LEFT - 6.0, y(tick) + 4.0, "end", &y_axis.tick_label(tick));
    }
    chart.line(LEFT, TOP, LEFT, BOTTOM, INK);
    chart.line(LEFT, BOTTOM, RIGHT, BOTTOM, INK);
    let ticks = if graph {
        let mut samples = vec![1.0, (points.len() as f64 / 2.0).ceil(), points.len() as f64];
        samples.dedup();
        samples
    } else {
        x_axis.ticks(2)
    };
    for tick in ticks {
        chart.line(x(tick), BOTTOM, x(tick), BOTTOM + 4.0, INK);
        chart.text(x(tick), BOTTOM + 17.0, "middle", &x_axis.tick_label(tick));
    }
    chart.text((LEFT + RIGHT) / 2.0, 171.0, "middle", &fit(x_label, 206));
    for (axis_name, axis) in [("X", x_axis), ("Y", y_axis)] {
        if let Some(origin) = axis.origin_label() {
            chart.height += 18;
            chart.text(
                8.0,
                chart.height as f64 - 5.0,
                "start",
                &format!("{axis_name} {origin}"),
            );
        }
    }
    let pixels: Vec<_> = points.iter().map(|&(a, b)| (x(a), y(b))).collect();
    if graph && pixels.len() > 1 {
        let path = spline(&pixels);
        write!(chart.body, r#"<path d="{path}" fill="none" stroke="{SERIES}" stroke-width="2.2" stroke-linejoin="round"/>"#).unwrap();
    }
    if !graph || pixels.len() <= 12 {
        for (a, b) in pixels {
            chart.dot(a, b, 2.6, SERIES);
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
