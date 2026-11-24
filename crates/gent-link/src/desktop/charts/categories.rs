use super::{
    Chart, GRID, INK, SERIES, clean_text, fit, number,
    scale::{Axis, exact_number, format_number},
    text_width,
};
use serde_json::Value;
use std::{f64::consts::TAU, fmt::Write};

mod radar;

const COLORS: [&str; 16] = [
    "#23556c", "#934e36", "#496640", "#6e5481", "#805a24", "#397373", "#934761", "#485b87",
    "#605b35", "#915431", "#346459", "#764a62", "#536888", "#795f47", "#5c596b", "#435660",
];
const CX: f64 = 130.0;
const CY: f64 = 106.0;
const RADIUS: f64 = 65.0;

struct Category {
    name: String,
    value: f64,
}

pub(super) fn render(
    kind: &str,
    values: &[Value],
    label: &str,
    unit: Option<&str>,
) -> Option<Chart> {
    let items = values
        .iter()
        .map(|item| {
            let name = clean_text(item["label"].as_str()?);
            let value = number(&item["value"])?;
            (!name.is_empty() && (kind == "bar" || value >= 0.0))
                .then_some(Category { name, value })
        })
        .collect::<Option<Vec<_>>>()?;
    let max = items.iter().map(|item| item.value).fold(0.0, f64::max);
    if (kind == "pie" && max == 0.0) || (kind == "radar" && items.len() < 3) {
        return None;
    }
    let mut description = format!("{label}. {kind} chart.");
    if let Some(unit) = unit {
        write!(description, " Values in {unit}.").unwrap();
    }
    // Normalize before summing, including when values approach f64::MAX.
    let portions: Vec<f64> = if kind == "pie" {
        let total: f64 = items.iter().map(|item| item.value / max).sum();
        items
            .iter()
            .map(|item| (item.value / max) / total)
            .collect()
    } else {
        Vec::new()
    };
    let positive_count = items.iter().filter(|item| item.value > 0.0).count();
    let shares: Vec<_> = portions
        .iter()
        .zip(&items)
        .map(|(&portion, item)| {
            let percent = portion * 100.0;
            if item.value > 0.0 && percent < 0.1 {
                "<0.1%".to_owned()
            } else if positive_count > 1 && percent > 99.9 {
                ">99.9%".to_owned()
            } else {
                format!("{}%", format!("{percent:.1}").trim_end_matches(".0"))
            }
        })
        .collect();
    for (i, item) in items.iter().enumerate() {
        write!(description, " {}: {}", item.name, exact_number(item.value)).unwrap();
        if let Some(share) = shares.get(i) {
            write!(description, " ({share})").unwrap();
        }
        description.push('.');
    }
    let mut chart = Chart::new(52, description);
    if let Some(unit) = unit {
        chart.text(8.0, 18.0, "start", &fit(unit, 244));
    }
    match kind {
        "bar" => bars(&mut chart, &items, max),
        "pie" => {
            pie(&mut chart, &portions);
            legend(&mut chart, &items, true, &shares);
        }
        _ => {
            let numbered = radar::draw(&mut chart, &items, max, unit);
            legend(&mut chart, &items, numbered, &[]);
        }
    }
    Some(chart)
}

fn bars(chart: &mut Chart, items: &[Category], max: f64) {
    if items.is_empty() {
        chart.text(130.0, 42.0, "middle", "No categories");
        return;
    }
    let min = items.iter().map(|item| item.value).fold(0.0, f64::min);
    let axis = Axis::new(min, if min == 0.0 && max == 0.0 { 1.0 } else { max });
    let x = |n| 34.0 + 192.0 * axis.fraction(n);
    let zero = x(0.0);
    for (i, item) in items.iter().enumerate() {
        let y = 40.0 + 37.0 * i as f64;
        chart.text(8.0, y, "start", &fit(&item.name, 166));
        chart.text(252.0, y, "end", &format_number(item.value));
        let end = x(item.value);
        write!(
            chart.body,
            r#"<rect x="{:.2}" y="{:.2}" width="{:.2}" height="8" fill="{SERIES}"/>"#,
            zero.min(end),
            y + 5.0,
            (end - zero).abs()
        )
        .unwrap();
        chart.line(zero, y + 3.0, zero, y + 15.0, INK);
    }
    let base = 26.0 + items.len() as f64 * 37.0;
    chart.line(x(axis.low), base, x(axis.high), base, INK);
    for tick in axis.ticks(2) {
        chart.line(x(tick), base, x(tick), base + 4.0, INK);
        chart.text(x(tick), base + 17.0, "middle", &axis.tick_label(tick));
    }
    chart.height = base as usize + 24;
}

// Fractions start at twelve o'clock and increase clockwise on both plots.
fn polar(turn: f64, radius: f64) -> (f64, f64) {
    let (s, c) = (turn * TAU).sin_cos();
    (CX + radius * s, CY - radius * c)
}

fn pie(chart: &mut Chart, portions: &[f64]) {
    let mut start = 0.0;
    for (i, &portion) in portions.iter().enumerate() {
        if portion == 0.0 {
            continue;
        }
        let end = start + portion;
        let middle = start + portion / 2.0;
        let (x0, y0) = polar(start, RADIUS);
        let (xm, ym) = polar(middle, RADIUS);
        let (x1, y1) = polar(end, RADIUS);
        // Two arcs also draw a complete circle when one category owns the pie.
        write!(chart.body, r##"<path d="M{CX},{CY} L{x0:.2},{y0:.2} A{RADIUS},{RADIUS} 0 0 1 {xm:.2},{ym:.2} A{RADIUS},{RADIUS} 0 0 1 {x1:.2},{y1:.2} Z" fill="{}" stroke="#ffffff" stroke-width="1"/>"##, COLORS[i]).unwrap();
        if portion >= 0.075 {
            let (x, y) = polar(middle, RADIUS * 0.70);
            write!(
                chart.body,
                r##"<text x="{x:.2}" y="{:.2}" text-anchor="middle" fill="#ffffff">{}</text>"##,
                y + 4.0,
                i + 1
            )
            .unwrap();
        }
        start = end;
    }
    chart.height = 179;
}

fn legend(chart: &mut Chart, items: &[Category], numbered: bool, shares: &[String]) {
    let share_width = shares.iter().map(|s| text_width(s)).max().unwrap_or(0);
    let value_end = if shares.is_empty() {
        252
    } else {
        252 - share_width - 10
    };
    let value_width = items
        .iter()
        .map(|item| text_width(&format_number(item.value)))
        .max()
        .unwrap_or(0);
    let name_start = if numbered { 42 } else { 8 };
    let name_width = value_end - value_width - 8 - name_start;
    for (i, item) in items.iter().enumerate() {
        let baseline = chart.height as f64 + 14.0;
        if let Some(share) = shares.get(i) {
            chart.dot(10.0, baseline - 4.0, 4.5, COLORS[i]);
            chart.text(252.0, baseline, "end", share);
        }
        if numbered {
            chart.text(35.0, baseline, "end", &(i + 1).to_string());
        }
        chart.text(
            name_start as f64,
            baseline,
            "start",
            &fit(&item.name, name_width),
        );
        chart.text(
            value_end as f64,
            baseline,
            "end",
            &format_number(item.value),
        );
        chart.height += 21;
    }
    chart.height += 3;
}
