use super::{
    Chart, Palette, WIDTH, fit, number,
    scale::{Axis, exact_number},
    text_width,
};
use serde_json::Value;
use std::fmt::Write;

type Point = (f64, f64);
const EDGE: f64 = 6.0;
const TICK_GAP: f64 = 6.0;
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

struct HorizontalLayout {
    left: f64,
    right: f64,
    ticks: Vec<(f64, String)>,
}

impl HorizontalLayout {
    fn measure(axis: Axis, values: &[f64], y_tick_width: usize) -> Self {
        let mut ticks: Vec<_> = values
            .iter()
            .map(|&n| (axis.fraction(n), axis.tick_label(n)))
            .collect();
        // Leave room for the right-aligned y ticks and the centered x labels
        // at either end of the plot.
        let half_label = |label: &str| text_width(label) as f64 / 2.0;
        let left = EDGE + (y_tick_width as f64 + TICK_GAP).max(half_label(&ticks[0].1));
        let right = WIDTH as f64 - EDGE - half_label(&ticks.last().unwrap().1);
        for (fraction, _) in &mut ticks {
            *fraction = left + *fraction * (right - left);
        }
        Self { left, right, ticks }
    }

    fn for_axis(axis: Axis, samples: Option<usize>, y_tick_width: usize) -> Self {
        let values = if let Some(count) = samples {
            let mut ticks = vec![1.0, count.div_ceil(2) as f64, count as f64];
            ticks.dedup();
            ticks
        } else {
            axis.ticks(2)
        };
        let layout = Self::measure(axis, &values, y_tick_width);
        // Two long scientific labels can crowd each other if the nice ticks
        // lie inside the domain. Give the endpoint labels the full plot span.
        if layout.ticks.windows(2).any(|pair| {
            let ((a, first), (b, second)) = (&pair[0], &pair[1]);
            b - a < (text_width(first) + text_width(second)) as f64 / 2.0 + TICK_GAP
        }) {
            Self::measure(axis, &[axis.low, axis.high], y_tick_width)
        } else {
            layout
        }
    }
}

pub(super) fn render(
    kind: &str,
    values: &[Value],
    label: &str,
    unit: Option<&str>,
    x_unit: Option<&str>,
    palette: &Palette,
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
            84,
            format!("{label}. No data. Axes: {x_label}, {y_label}."),
            palette,
        );
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
    let HorizontalLayout { left, right, ticks } =
        HorizontalLayout::for_axis(x_axis, graph.then_some(points.len()), y_tick_width);
    let x = |n| left + x_axis.fraction(n) * (right - left);
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
    let mut chart = Chart::new(178, description, palette);
    let colors = chart.colors;
    chart.text(
        left,
        17.0,
        "start",
        &fit(y_label, (WIDTH as f64 - EDGE - left) as usize),
    );
    for (tick, label) in y_ticks {
        chart.line(left, y(tick), right, y(tick), colors.grid);
        chart.secondary_text(left - TICK_GAP, y(tick) + 4.0, "end", &label);
    }
    chart.line(left, TOP, left, BOTTOM, colors.secondary);
    chart.line(left, BOTTOM, right, BOTTOM, colors.secondary);
    for (position, label) in ticks {
        chart.line(position, BOTTOM, position, BOTTOM + 4.0, colors.secondary);
        chart.secondary_text(position, BOTTOM + 17.0, "middle", &label);
    }
    chart.text(
        (left + right) / 2.0,
        171.0,
        "middle",
        &fit(x_label, (right - left) as usize),
    );
    for (axis_name, axis) in [("X", x_axis), ("Y", y_axis)] {
        if let Some(origin) = axis.origin_label() {
            chart.height += 18;
            chart.secondary_text(
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
        write!(chart.body, r#"<path d="{path}" fill="none" stroke="{}" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"/>"#, colors.accent).unwrap();
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
