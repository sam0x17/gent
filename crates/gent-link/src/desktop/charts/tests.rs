use super::{Palette, decorate, scale::Axis};
use serde_json::{Value, json};

fn rendered(kind: &str, values: Value) -> (String, String) {
    rendered_at(kind, values, 260)
}

fn rendered_at(kind: &str, values: Value, width: usize) -> (String, String) {
    let mut widget =
        json!({"kind":kind, "label":"Latency", "unit":"ms", "x_unit":"Bytes", "value":values});
    decorate(&mut widget, &Palette::default(), width);
    let svg = widget["chart_svg"].as_str().unwrap().to_owned();
    let width = width.clamp(160, 16_384);
    assert!(svg.starts_with(&format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}""#
    )));
    assert!(svg.ends_with("</svg>"));
    assert!(!svg.contains("NaN") && !svg.contains("inf"));
    (
        svg,
        widget["chart_description"].as_str().unwrap().to_owned(),
    )
}

#[test]
fn graphs_cover_empty_single_flat_and_negative_samples() {
    let (empty, _) = rendered("graph", json!([]));
    assert!(empty.contains("No samples") && empty.contains(">Sample<"));
    let (single, _) = rendered("graph", json!([-4]));
    assert_eq!(single.matches("<circle ").count(), 1);
    assert!(!single.contains("<path "));
    let (flat, _) = rendered("graph", json!([-4, -4, -4]));
    assert!(flat.contains(" C") && flat.contains(">-4<") && flat.contains(">ms<"));
    let (rising, description) = rendered("graph", json!([-10, -2, 1, 5, 12]));
    assert!(rising.contains(">-10<") && rising.contains(">10<"));
    assert!(description.contains("5 samples"));
}

#[test]
fn cubic_controls_stay_inside_each_sample_interval_and_flatten_at_extrema() {
    let samples = [-10., -9.99, 8., 8., 5., -3., 2.];
    let (svg, _) = rendered("graph", json!(samples));
    let path = svg
        .split_once("<path d=\"M")
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap();
    let mut segments = path.split(" C");
    let pair = |s: &str| {
        let (x, y) = s.split_once(',').unwrap();
        (x.parse::<f64>().unwrap(), y.parse::<f64>().unwrap())
    };
    let mut start = pair(segments.next().unwrap());
    let mut count = 0;
    for (i, segment) in segments.enumerate() {
        let controls: Vec<_> = segment.split_whitespace().map(pair).collect();
        let [a, b, end] = controls[..] else {
            panic!("expected cubic segment")
        };
        let interval = start.1.min(end.1)..=start.1.max(end.1);
        assert!(interval.contains(&a.1) && interval.contains(&b.1));
        assert!(start.0 < a.0 && a.0 < b.0 && b.0 < end.0);
        if [2, 3, 5].contains(&i) {
            assert_eq!(a.1, start.1);
        }
        if [1, 2, 4].contains(&i) {
            assert_eq!(b.1, end.1);
        }
        start = end;
        count += 1;
    }
    assert_eq!(count, samples.len() - 1);
}

#[test]
fn scatter_plots_numeric_coordinates_without_connecting_points() {
    let (svg, description) = rendered("scatter", json!([[2, -4], [2, 6], [6, 1]]));
    let centers = svg
        .split("<circle ")
        .skip(1)
        .map(|c| c.split_once(" r=").unwrap().0)
        .collect::<Vec<_>>();
    assert_eq!(centers.len(), 3);
    let xs: Vec<_> = centers
        .iter()
        .map(|p| p.split_once(" cy=").unwrap().0)
        .collect();
    assert_eq!(xs[0], xs[1]);
    assert_ne!(xs[1], xs[2]);
    assert!(!svg.contains("<path"));
    assert!(svg.contains(">Bytes<") && svg.contains(">ms<") && description.contains("3 points"));
    assert!(rendered("scatter", json!([])).0.contains("No points"));
}

#[test]
fn bars_share_a_zero_baseline_and_preserve_signed_values() {
    let items = json!([{"label":"Loss","value":-4},{"label":"Gain","value":4}]);
    let (svg, description) = rendered("bar", items);
    let mut bars = svg.split("<rect").skip(1);
    let loss = bars.next().unwrap();
    let gain = bars.next().unwrap();
    let x = coordinate(gain, "x");
    assert_eq!(coordinate(loss, "x") + coordinate(loss, "width"), x);
    assert_eq!(coordinate(loss, "width"), coordinate(gain, "width"));
    assert!(coordinate(loss, "width") > 110.0);
    assert!(svg.contains(">Loss<") && svg.contains(">Gain<") && description.contains("Loss: -4"));
}

#[test]
fn pie_and_radar_show_all_categories_on_one_column_cards() {
    let items: Vec<_> = (0..16)
        .map(|i| json!({"label":format!("Category {i}"),"value":i}))
        .collect();
    for kind in ["pie", "radar"] {
        let (svg, description) = rendered(kind, json!(items));
        for i in 0..16 {
            assert!(svg.contains(&format!(">Category {i}<")));
            assert!(description.contains(&format!("Category {i}: {i}")));
        }
        assert!(svg.contains(">16<") && svg.contains(">ms<"));
    }
    let (pie, _) = rendered("pie", json!([{"label":"Only","value":2}]));
    assert_eq!(pie.matches(" A65,65").count(), 2);
    rendered(
        "radar",
        json!([{"label":"A","value":0},{"label":"B","value":0},{"label":"C","value":0}]),
    );
}

#[test]
fn extreme_scales_stay_finite_and_close_ticks_remain_distinguishable() {
    for (lo, hi) in [
        (0.0, 0.0),
        (-f64::MAX, f64::MAX),
        (f64::MAX, f64::MAX),
        (0., f64::from_bits(1)),
        (1e16, 1e16 + 8.),
    ] {
        let axis = Axis::new(lo, hi);
        let ticks = axis.ticks(4);
        assert!(ticks.len() >= 2);
        assert!(
            ticks
                .windows(2)
                .all(|w| w[0] < w[1] && axis.tick_label(w[0]) != axis.tick_label(w[1]))
        );
        assert!(
            ticks
                .iter()
                .all(|&n| (0.0..=1.0).contains(&axis.fraction(n)))
        );
    }
    let (svg, _) = rendered("scatter", json!([[1e16, 0], [1e16 + 8., 1]]));
    assert!(svg.contains("X Origin"));
}

#[test]
fn chart_text_is_bounded_and_cannot_supply_svg_elements_or_attributes() {
    let malicious = "<image href='file:///tmp'/> & \"\u{ffff}\0";
    let mut widget = json!({"kind":"pie","label":malicious,"unit":malicious,
        "value":[{"label":format!("{malicious}{}","X".repeat(10_000)),"value":1}]});
    decorate(&mut widget, &Palette::default(), 260);
    let svg = widget["chart_svg"].as_str().unwrap();
    assert!(!svg.contains("<image") && !svg.contains('\u{ffff}') && !svg.contains('\0'));
    assert!(svg.contains("&lt;image") && svg.contains("&amp;") && svg.contains("&quot;"));
    assert!(svg.len() < 4000 && widget["chart_description"].as_str().unwrap().len() < 512);
}

#[test]
fn invalid_shapes_and_unrecognized_kinds_discard_stale_decorations() {
    for (kind, value) in [
        ("link", json!("https://example.org")),
        ("graph", json!([null])),
        ("graph", json!(vec![1; 257])),
        ("scatter", json!([[1, 2, 3]])),
        ("scatter", json!(vec![[1, 2]; 257])),
        ("bar", json!([{"label":"", "value":1}])),
        ("bar", json!(vec![json!({"label":"a","value":1}); 17])),
        ("pie", json!([{"label":"a","value":0}])),
        ("pie", json!([{"label":"a","value":-1}])),
        ("radar", json!([{"label":"a","value":1}])),
        (
            "radar",
            json!([{"label":"a","value":1},{"label":"b","value":0},{"label":"c","value":-1}]),
        ),
    ] {
        let mut widget =
            json!({"kind":kind,"value":value,"chart_svg":"stale","chart_description":"stale"});
        decorate(&mut widget, &Palette::default(), 260);
        assert!(
            widget.get("chart_svg").is_none() && widget.get("chart_description").is_none(),
            "{kind}"
        );
    }
}

#[test]
fn pie_legend_includes_raw_values_and_rounded_shares_for_every_slice() {
    let (svg, description) = rendered(
        "pie",
        json!([
            {"label":"Pass", "value":2}, {"label":"Fail", "value":1}, {"label":"Skip","value":0}
        ]),
    );
    for (label, raw, share) in [
        ("Pass", 2, "66.7%"),
        ("Fail", 1, "33.3%"),
        ("Skip", 0, "0%"),
    ] {
        assert!(svg.contains(&format!(">{share}</text>")));
        assert!(description.contains(&format!("{label}: {raw} ({share})")));
    }
    let (tiny, _) = rendered(
        "pie",
        json!([{"label":"Main","value":1},{"label":"Rare","value":1e-20}]),
    );
    assert!(tiny.contains("&lt;0.1%") && tiny.contains("&gt;99.9%"));
    assert!(
        rendered("pie", json!([{"label":"Only","value":2}]))
            .0
            .contains(">100%</text>")
    );
}

#[test]
fn radar_uses_outward_facing_names_when_they_fit_and_indices_otherwise() {
    let labels = |names: &[&str]| {
        json!(
            names
                .iter()
                .map(|name| json!({"label": name,"value": 2}))
                .collect::<Vec<_>>()
        )
    };
    let (radar, _) = rendered("radar", labels(&["CPU", "Memory", "Disk", "Network"]));
    let spokes = radar.split("fill-opacity=").next().unwrap();
    for (name, anchor) in [
        ("CPU", "middle"),
        ("Memory", "start"),
        ("Disk", "middle"),
        ("Network", "end"),
    ] {
        assert!(spokes.contains(&format!("text-anchor=\"{anchor}\">{name}</text>")));
    }
    for names in [
        vec!["CPU", "RAM", "Disk", "Net", "GPU", "I/O"],
        vec!["CPU", "A category name too long for a spoke", "Disk"],
        vec!["A", "B", "C", "D", "E", "F", "G"],
    ] {
        let (radar, _) = rendered("radar", labels(&names));
        let spokes = radar.split("fill-opacity=").next().unwrap();
        if names.len() == 6 {
            assert!(
                names
                    .iter()
                    .all(|name| spokes.contains(&format!(">{name}</text>")))
            );
        } else {
            assert!(
                spokes.contains(">1</text>") && !spokes.contains(&format!(">{}</text>", names[0]))
            );
        }
    }
}

#[test]
fn utilization_radar_keeps_a_hundred_percent_outer_ring_even_when_idle() {
    let render = |delta: f64| {
        let mut w = json!({"kind":"radar","label":"Utilization","unit":"%","value":[
            {"label":"CPU","value":delta},{"label":"GPU","value":0},{"label":"RAM","value":0}]});
        decorate(&mut w, &Palette::default(), 260);
        w["chart_svg"].as_str().unwrap().to_owned()
    };
    let quarter = render(25.0);
    assert!(quarter.contains("Center 0% · Rings 25%, 50%, 75%, 100%"));
    assert_eq!(quarter.matches("<polygon ").count(), 5);
    let first_y = |svg: &str| coordinate(svg.split("<circle").nth(1).unwrap(), "cy");
    let zero = render(0.0);
    let center = first_y(&zero);
    let outer = first_y(&render(100.0));
    assert!(zero.contains("100%") && outer < center);
    assert!((center - first_y(&quarter) - (center - outer) / 4.0).abs() < 0.02);
    let larger = render(150.0);
    assert!(larger.contains("Rings: 75 / 150"));
    assert_eq!(larger.matches("<polygon ").count(), 3);
}

#[test]
fn palette_accepts_only_the_native_rgb_contract() {
    let mut input =
        json!({"surface":[255,254,240],"text":[5,10,0],"secondary":[7,20,18],"accent":[42,0,137]});
    let palette: Palette = serde_json::from_value(input.clone()).unwrap();
    assert_eq!(palette.accent, [42, 0, 137]);
    for invalid in [
        json!([0, 0]),
        json!([0, 0, 0, 0]),
        json!([-1, 0, 1]),
        json!([0, 0, 256]),
        json!("#ff0000"),
    ] {
        input["accent"] = invalid;
        assert!(serde_json::from_value::<Palette>(input.clone()).is_err());
    }
    input["accent"] = json!([1, 2, 3]);
    input["extra"] = json!("ignored?");
    assert!(serde_json::from_value::<Palette>(input).is_err());
}

fn appearances() -> [Palette; 6] {
    [
        Palette::default(),
        Palette {
            surface: [251, 235, 224],
            text: [53, 22, 42],
            secondary: [103, 74, 89],
            accent: [139, 24, 100],
        },
        Palette {
            surface: [41, 27, 60],
            text: [248, 230, 252],
            secondary: [185, 165, 206],
            accent: [110, 219, 178],
        },
        // Intentionally unreadable native colors on a mid-tone chromatic surface.
        Palette {
            surface: [79, 139, 93],
            text: [83, 141, 89],
            secondary: [72, 134, 96],
            accent: [79, 139, 93],
        },
        Palette {
            surface: [0; 3],
            text: [255; 3],
            secondary: [255, 245, 198],
            accent: [255, 220, 0],
        },
        Palette {
            surface: [255; 3],
            text: [0; 3],
            secondary: [15, 10, 0],
            accent: [18, 0, 126],
        },
    ]
}

#[test]
fn roles_preserve_readable_native_colors_and_correct_low_contrast_on_the_actual_surface() {
    use super::colors::{Color, Colors};
    assert!((Color([0; 3]).contrast(Color([255; 3])) - 21.0).abs() < 1e-9);
    assert!(Color([118; 3]).contrast(Color([255; 3])) >= 4.5);
    assert!(Color([119; 3]).contrast(Color([255; 3])) < 4.5);
    for palette in appearances() {
        let colors = Colors::new(&palette);
        assert_eq!(colors.surface.0, palette.surface);
        for (actual, native, target) in [
            (colors.text, palette.text, 4.5),
            (colors.secondary, palette.secondary, 4.5),
            (colors.accent, palette.accent, 3.0),
        ] {
            assert!(
                actual.contrast(colors.surface) >= target,
                "{actual} on {}",
                colors.surface
            );
            if Color(native).contrast(colors.surface) >= target {
                assert_eq!(actual, Color(native));
            }
        }
        let grid_contrast = colors.grid.contrast(colors.surface);
        assert!(
            (1.6..2.2).contains(&grid_contrast),
            "grid contrast {grid_contrast}"
        );
        for ((grid, bg), fg) in colors
            .grid
            .0
            .into_iter()
            .zip(palette.surface)
            .zip(colors.text.0)
        {
            assert!((bg.min(fg)..=bg.max(fg)).contains(&grid));
        }
        let swatches = colors.categories();
        assert_eq!(swatches[0], colors.accent);
        for (i, fill) in swatches.into_iter().enumerate() {
            assert!(!swatches[..i].contains(&fill));
            assert!(fill.contrast(colors.surface) >= 3.0);
            assert!(colors.slice_text(fill).contrast(fill) >= 4.5);
        }
    }
}

#[test]
fn all_five_renderers_use_transparent_canvases_and_semantic_colors() {
    use super::colors::Colors;
    for palette in appearances() {
        let colors = Colors::new(&palette);
        let cats =
            json!([{"label":"CPU","value":3},{"label":"GPU","value":2},{"label":"Disk","value":1}]);
        for (kind, values) in [
            ("graph", json!([1, 3, 2])),
            ("scatter", json!([[0, 1], [1, 3]])),
            ("bar", cats.clone()),
            ("pie", cats.clone()),
            ("radar", cats.clone()),
        ] {
            let mut widget = json!({"kind":kind,"value":values,"unit":"ms","label":"Delay"});
            decorate(&mut widget, &palette, 260);
            let svg = widget["chart_svg"].as_str().unwrap();
            assert_eq!(
                svg.matches("<rect ").count(),
                if kind == "bar" { 3 } else { 0 }
            );
            assert!(svg.contains(&format!(
                r#"fill="{}" text-anchor="start">ms<"#,
                colors.text
            )));
            assert!(svg.contains(&format!(r#"fill="{}" text-anchor="#, colors.secondary)));
            if matches!(kind, "graph" | "scatter" | "radar") {
                assert!(svg.contains(&format!(r#"stroke="{}""#, colors.grid)));
                assert!(svg.contains(&format!(
                    r#"fill="{}" stroke="{}" stroke-width="0.4""#,
                    colors.accent, colors.surface
                )));
            }
            if kind == "bar" {
                assert!(svg.contains(&format!(r#"height="5" fill="{}""#, colors.accent)));
            }
            if kind == "graph" || kind == "radar" {
                assert!(svg.contains(&format!(
                    r#"stroke="{}" stroke-width="1.25""#,
                    colors.accent
                )));
            }
            if kind == "pie" {
                let slices: Vec<_> = svg.split("<path ").skip(1).collect();
                assert_eq!(slices.len(), 3);
                for (i, slice) in slices.iter().enumerate() {
                    let fill = colors.categories()[i];
                    assert!(
                        slice.contains(&format!(r#"fill="{fill}" stroke="{}""#, colors.surface))
                    );
                    assert!(slice.contains(&format!(
                        r#"fill="{}" text-anchor="middle">{}</text>"#,
                        colors.slice_text(fill),
                        i + 1
                    )));
                    assert!(svg.contains(&format!(r#"r="3" fill="{fill}""#)));
                }
                assert!(svg.contains(">50%</text>"));
            }
        }
    }
    let [_, light, dark, ..] = appearances();
    assert_ne!(
        Colors::new(&light).categories(),
        Colors::new(&dark).categories()
    );
}

fn coordinate(tag: &str, key: &str) -> f64 {
    tag.split_once(&format!(" {key}=\""))
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

mod layout;
