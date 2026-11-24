use super::{
    Chart, Color, Palette, clean_text, fit,
    horizontal::HorizontalAxis,
    number,
    scale::{Axis, exact_number, format_number},
    text_width,
};
use serde_json::Value;
use std::{f64::consts::TAU, fmt::Write};

mod radar;

// Wide cards place the legend beside a bounded, circular plot.
#[derive(Clone, Copy)]
struct PolarPlot {
    left: usize,
    width: usize,
    cx: f64,
    cy: f64,
    radius: f64,
}

impl PolarPlot {
    fn point(self, turn: f64, radius: f64) -> (f64, f64) {
        let (s, c) = (turn * TAU).sin_cos();
        (self.cx + radius * s, self.cy - radius * c)
    }
}

struct Category {
    name: String,
    value: f64,
}

struct Slice {
    portion: f64,
    share: String,
    fill: Color,
}

fn pie_slices(items: &[Category], max: f64, colors: super::Colors) -> Vec<Slice> {
    // Normalize before summing, including when values approach f64::MAX.
    let total: f64 = items.iter().map(|item| item.value / max).sum();
    let multiple = items.iter().filter(|item| item.value > 0.0).count() > 1;
    items
        .iter()
        .zip(colors.categories())
        .map(|(item, fill)| {
            let portion = (item.value / max) / total;
            let percent = portion * 100.0;
            let share = if item.value > 0.0 && percent < 0.1 {
                "<0.1%".to_owned()
            } else if multiple && percent > 99.9 {
                ">99.9%".to_owned()
            } else {
                format!("{}%", format!("{percent:.1}").trim_end_matches(".0"))
            };
            Slice {
                portion,
                share,
                fill,
            }
        })
        .collect()
}

pub(super) fn render(
    kind: &str,
    values: &[Value],
    label: &str,
    unit: Option<&str>,
    palette: &Palette,
    width: usize,
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
    let mut chart = Chart::new(width, 40, description, palette);
    let slices = if kind == "pie" {
        pie_slices(&items, max, chart.colors)
    } else {
        Vec::new()
    };
    for (i, item) in items.iter().enumerate() {
        write!(
            chart.description,
            " {}: {}",
            item.name,
            exact_number(item.value)
        )
        .unwrap();
        if let Some(slice) = slices.get(i) {
            write!(chart.description, " ({})", slice.share).unwrap();
        }
        chart.description.push('.');
    }
    let content_width = if kind == "bar" {
        width
    } else {
        width.min(1080)
    };
    let left = (width - content_width) / 2;
    let top = if let Some(unit) = unit {
        chart.text(
            (left + 6) as f64,
            14.0,
            "start",
            &fit(unit, content_width - 12),
        );
        22
    } else {
        6
    };
    if kind == "bar" {
        bars(&mut chart, &items, max, top);
    } else {
        let beside = content_width >= 480;
        let plot_width = if beside {
            content_width / 2
        } else {
            content_width
        };
        let radius = (plot_width as f64 / 4.0).clamp(40.0, 84.0);
        let spoke_margin = if kind == "radar" { 18 } else { 2 };
        let plot = PolarPlot {
            left,
            width: plot_width,
            cx: left as f64 + plot_width as f64 / 2.0,
            cy: (top + spoke_margin) as f64 + radius,
            radius,
        };
        let (numbered, bottom) = if kind == "pie" {
            pie(&mut chart, plot, &slices);
            (true, (plot.cy + radius).ceil() as usize + spoke_margin)
        } else {
            radar::draw(&mut chart, plot, &items, max, unit)
        };
        let (legend_left, legend_width, legend_top) = if beside {
            (left + plot_width + 8, content_width - plot_width - 8, top)
        } else {
            (left, content_width, bottom + 5)
        };
        chart.height = bottom.max(legend(
            &mut chart,
            &items,
            &slices,
            numbered,
            LegendArea {
                left: legend_left,
                width: legend_width,
                top: legend_top,
                // Center short legends vertically beside the disc.
                height: if beside { bottom - top } else { 0 },
            },
        )) + 4;
    }
    Some(chart)
}

fn bars(chart: &mut Chart, items: &[Category], max: f64, top: usize) {
    if items.is_empty() {
        chart.text(
            chart.width as f64 / 2.0,
            (top + 13) as f64,
            "middle",
            "No categories",
        );
        return;
    }
    let min = items.iter().map(|item| item.value).fold(0.0, f64::min);
    let axis = Axis::new(min, if min == 0.0 && max == 0.0 { 1.0 } else { max });
    let layout = HorizontalAxis::new(axis, None, chart.width, 0.0);
    let x = |n| layout.left + (layout.right - layout.left) * axis.fraction(n);
    let zero = x(0.0);
    for (i, item) in items.iter().enumerate() {
        let y = (top + 9 + 25 * i) as f64;
        let value = format_number(item.value);
        let name_width = chart.width.saturating_sub(18 + text_width(&value));
        chart.text(6.0, y, "start", &fit(&item.name, name_width));
        chart.text((chart.width - 6) as f64, y, "end", &value);
        let end = x(item.value);
        write!(
            chart.body,
            r#"<rect x="{:.2}" y="{:.2}" width="{:.2}" height="5" fill="{}"/>"#,
            zero.min(end),
            y + 4.0,
            (end - zero).abs(),
            chart.colors.accent
        )
        .unwrap();
        chart.line(zero, y + 2.0, zero, y + 11.0, chart.colors.secondary);
    }
    chart.height = layout.draw(chart, top + 25 * items.len()) + 4;
}

fn pie(chart: &mut Chart, plot: PolarPlot, slices: &[Slice]) {
    let PolarPlot { cx, cy, radius, .. } = plot;
    let mut start = 0.0;
    for (i, slice) in slices.iter().enumerate() {
        let portion = slice.portion;
        if portion == 0.0 {
            continue;
        }
        let end = start + portion;
        let middle = start + portion / 2.0;
        let (x0, y0) = plot.point(start, radius);
        let (xm, ym) = plot.point(middle, radius);
        let (x1, y1) = plot.point(end, radius);
        // Two arcs also draw a complete circle when one category owns the pie.
        write!(chart.body, r##"<path d="M{cx},{cy} L{x0:.2},{y0:.2} A{radius},{radius} 0 0 1 {xm:.2},{ym:.2} A{radius},{radius} 0 0 1 {x1:.2},{y1:.2} Z" fill="{}" stroke="{}" stroke-width="0.8" stroke-linejoin="round"/>"##, slice.fill, chart.colors.surface).unwrap();
        let index = (i + 1).to_string();
        let label_radius = radius * 0.68;
        // Keep each numeral and its separator inside even a small sector.
        let clearance = label_radius * (portion.min(0.5) * TAU / 2.0).sin();
        if clearance >= (text_width(&index) as f64).hypot(10.0) / 2.0 + 1.0 {
            let (x, y) = plot.point(middle, label_radius);
            chart.colored_text(
                x,
                y + 3.0,
                "middle",
                &index,
                chart.colors.slice_text(slice.fill),
            );
        }
        start = end;
    }
}

struct LegendArea {
    left: usize,
    top: usize,
    width: usize,
    height: usize,
}

fn legend(
    chart: &mut Chart,
    items: &[Category],
    slices: &[Slice],
    numbered: bool,
    area: LegendArea,
) -> usize {
    let share_width = slices
        .iter()
        .map(|s| text_width(&s.share))
        .max()
        .unwrap_or(0);
    let value_width = items
        .iter()
        .map(|item| text_width(&format_number(item.value)))
        .max()
        .unwrap_or(0);
    let end = area.width - 6;
    let value_end = end.saturating_sub(if slices.is_empty() {
        0
    } else {
        share_width + 8
    });
    let name_start = if numbered { 31 } else { 6 };
    let single_line = value_end.saturating_sub(value_width + 6 + name_start);
    let longest_name = items
        .iter()
        .map(|item| text_width(&item.name))
        .max()
        .unwrap_or(0);
    let stacked = single_line < longest_name.min(52);
    let name_width = if stacked {
        end - name_start
    } else {
        single_line
    };
    let row_height = if stacked { 29 } else { 16 };
    let height = row_height * items.len();
    let top = area.top + area.height.saturating_sub(height) / 2;
    let x = |local| (area.left + local) as f64;
    for (i, item) in items.iter().enumerate() {
        let y = (top + 11 + i * row_height) as f64;
        let value_y = if stacked { y + 12.0 } else { y };
        if let Some(slice) = slices.get(i) {
            chart.dot(x(8), y - 3.0, 3.0, slice.fill);
            chart.secondary_text(x(end), value_y, "end", &slice.share);
        }
        if numbered {
            chart.secondary_text(x(26), y, "end", &(i + 1).to_string());
        }
        chart.text(x(name_start), y, "start", &fit(&item.name, name_width));
        chart.text(x(value_end), value_y, "end", &format_number(item.value));
    }
    top + height
}
