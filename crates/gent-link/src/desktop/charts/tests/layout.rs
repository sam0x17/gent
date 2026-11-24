use super::super::text_width;
use super::{coordinate, rendered, rendered_at};
use serde_json::json;

fn cartesian_layout(svg: &str) -> (f64, f64) {
    let width = coordinate(svg, "width");
    let vertical = svg
        .split("<line")
        .skip(1)
        .find(|tag| {
            coordinate(tag, "x1") == coordinate(tag, "x2")
                && coordinate(tag, "y2") - coordinate(tag, "y1") > 10.0
        })
        .unwrap();
    let bottom = coordinate(vertical, "y2");
    let axis = svg
        .split("<line")
        .skip(1)
        .find(|line| coordinate(line, "y1") == bottom && coordinate(line, "y2") == bottom)
        .unwrap();
    let (left, right) = (coordinate(axis, "x1"), coordinate(axis, "x2"));
    let mut last_end = 0.0;
    for tag in svg.split("<text").skip(1) {
        let label = tag
            .split_once('>')
            .unwrap()
            .1
            .split_once("</text>")
            .unwrap()
            .0;
        let label_width = text_width(label) as f64;
        let (x, y) = (coordinate(tag, "x"), coordinate(tag, "y"));
        if y == bottom + 14.0 {
            assert!(
                x - label_width / 2.0 >= last_end + 4.0 && x + label_width / 2.0 <= width - 4.0,
                "{label} at {x}"
            );
            last_end = x + label_width / 2.0;
        } else if tag
            .split_once('>')
            .unwrap()
            .0
            .contains(r#"text-anchor="end""#)
        {
            assert!(x - label_width >= 4.0 && x <= left - 4.0, "{label} at {x}");
        } else if y == 14.0 {
            assert_eq!(x, left, "y caption must align with its axis");
            assert!(x + label_width <= width - 4.0);
        }
    }
    assert!(last_end > 0.0);
    (left, right)
}

#[test]
fn cartesian_width_tracks_tick_strings_and_keeps_edge_labels_visible() {
    let (graph, _) = rendered("graph", json!([-20, 20, 0]));
    let (scatter, _) = rendered("scatter", json!([[1, -20], [2, 20], [3, 0]]));
    for svg in [graph, scatter] {
        let (left, right) = cartesian_layout(&svg);
        assert!(
            right - left >= 208.0,
            "two-digit y ticks should leave 80% of a 260px card for data"
        );
        assert!(left <= 40.0 && right >= 248.0);
        assert!(svg.contains(&format!(r#"<circle cx="{left:.2}""#)));
        assert!(svg.contains(&format!(r#"<circle cx="{right:.2}""#)));
        assert!(
            svg.contains(">2</text>"),
            "keep the middle tick when it fits"
        );
    }
    let (long, _) = rendered(
        "scatter",
        json!([[-9.876e-179, -1.234e-233], [8.876e-179, 1.234e-233]]),
    );
    let (left, right) = cartesian_layout(&long);
    assert!(left > 40.0 && right < 248.0);
    // A wide first x label can set the left inset even with short y ticks.
    let (wide_first, _) = rendered("scatter", json!([[-f64::from_bits(1), 0], [0, 1]]));
    let (left, right) = cartesian_layout(&wide_first);
    assert!(left > 39.0 && right >= 248.0);
    // At minimum width, the nice ticks -3.26e-119 and -3.24e-119 are too close together.
    // Keep two readable labels by placing them at the actual data endpoints.
    let (crowded, _) = rendered_at(
        "scatter",
        json!([[-326.9e-121, -9.876e-310], [-323.4e-121, 9.876e-310]]),
        160,
    );
    cartesian_layout(&crowded);
    assert!(crowded.contains(">-3.269e-119</text>") && crowded.contains(">-3.234e-119</text>"));
    for points in [
        json!([[-1.234e101, -1e-317], [9.876e103, 2e-317]]),
        json!([[1e16, 1e16], [1e16 + 8.0, 1e16 + 8.0]]),
        json!([[0.0000001, -300], [0.0000001, -300]]),
        json!([[0, -1], [f64::from_bits(1), 0]]),
    ] {
        cartesian_layout(&rendered("scatter", points).0);
    }
}

// Check the actual text elements: labels may move to a second baseline, but
// every label must fit the viewport and have its own space on that baseline.
fn check_label_geometry(svg: &str) {
    let width = coordinate(svg, "width");
    let height = coordinate(svg, "height");
    let mut occupied = Vec::new();
    for tag in svg.split("<text").skip(1) {
        let (attrs, content) = tag.split_once('>').unwrap();
        let label = content
            .split_once("</text>")
            .unwrap()
            .0
            .replace("&lt;", "<")
            .replace("&gt;", ">");
        let (x, y) = (coordinate(attrs, "x"), coordinate(attrs, "y"));
        let advance = text_width(&label) as f64;
        let left = if attrs.contains(r#"text-anchor="middle""#) {
            x - advance / 2.0
        } else if attrs.contains(r#"text-anchor="end""#) {
            x - advance
        } else {
            x
        };
        let right = left + advance;
        assert!(
            left >= 0.0 && right <= width && y >= 9.0 && y + 2.0 <= height,
            "{label} outside {width}×{height} at x={left}..{right}, y={y}"
        );
        for (l, r, baseline, other) in &occupied {
            assert!(
                (y - baseline).abs() >= 10.0 || right <= *l || left >= *r,
                "overlapping {label} and {other} at {width} px"
            );
        }
        occupied.push((left, right, y, label));
    }
}

#[test]
fn all_five_charts_relayout_at_the_requested_logical_pixel_width() {
    let categories =
        json!([{"label":"CPU","value":30},{"label":"GPU","value":50},{"label":"RAM","value":20}]);
    for width in [160, 260, 479, 480, 700, 16_384] {
        for (kind, values) in [
            ("graph", json!([1, 8, 3])),
            ("scatter", json!([[1, 1], [2, 8], [3, 3]])),
            ("bar", categories.clone()),
            ("pie", categories.clone()),
            ("radar", categories.clone()),
        ] {
            let (svg, _) = rendered_at(kind, values, width);
            let height = coordinate(&svg, "height") as usize;
            assert!(height < 300, "{kind} {width}×{height}");
            assert!(svg.contains(&format!(r#"viewBox="0 0 {width} {height}""#)));
            assert!(svg.contains(r#"font-size="10""#));
            check_label_geometry(&svg);
            match kind {
                "graph" | "scatter" => {
                    let (left, right) = cartesian_layout(&svg);
                    assert!(right - left > width as f64 * 0.8);
                    let markers: Vec<_> = svg.split("<circle").skip(1).collect();
                    assert_eq!(coordinate(markers[0], "cx"), left);
                    assert_eq!(coordinate(markers[2], "cx"), right);
                    assert!(markers.iter().all(|m| coordinate(m, "r") == 1.8));
                }
                "bar" => {
                    let longest = svg.split("<rect").nth(2).unwrap();
                    assert!(coordinate(longest, "width") > width as f64 * 0.8);
                    assert_eq!(coordinate(longest, "height"), 5.0);
                }
                "pie" | "radar" => {
                    let labels: Vec<_> = svg.split("<text").skip(1).collect();
                    let first_name = labels.iter().rfind(|t| t.contains(">CPU</text>")).unwrap();
                    let x = coordinate(first_name, "x");
                    if width >= 480 {
                        assert!(x > width as f64 / 2.0, "legend beside {kind}");
                    } else {
                        assert!(x < width as f64 / 2.0, "legend below {kind}");
                    }
                }
                _ => unreachable!(),
            }
        }
    }
    for (input, expected) in [(0, 160), (usize::MAX, 16_384)] {
        assert_eq!(
            coordinate(&rendered_at("graph", json!([]), input).0, "width"),
            expected as f64
        );
    }
}

#[test]
fn narrow_cards_keep_full_numeric_values_and_separate_dense_labels() {
    let names: Vec<_> = (0..16)
        .map(|i| format!("Category {i} {}", "Ｗ".repeat(70)))
        .collect();
    let values: Vec<_> = names
        .iter()
        .zip([f64::MAX, 1.354e-314, 2.765e117, 0.0].into_iter().cycle())
        .map(|(name, value)| json!({"label":name,"value":value}))
        .collect();
    for width in [160, 260, 700] {
        for kind in ["pie", "radar", "bar"] {
            let (svg, desc) = rendered_at(kind, json!(values), width);
            check_label_geometry(&svg);
            assert!(names.iter().all(|s| desc.contains(s)));
            assert!(svg.contains(">1.798e308</text>") && svg.contains(">1.354e-314</text>"));
            if kind == "pie" {
                assert!(svg.contains("&lt;0.1%</text>"));
            }
        }
        for points in [
            json!([[-326.9e-121, -9.876e-310], [-323.4e-121, 9.876e-310]]),
            json!([
                [1.234567890123456e-211, -1e237],
                [1.234567890123466e-211, -0.9999999e237]
            ]),
        ] {
            check_label_geometry(&rendered_at("scatter", points, width).0);
        }
    }
}
