"""Exercise projected sections and legacy events through the native GTK dashboard."""


def exercise_lanes(window, pane, row, widgets, settle, requests, clipboard):
    from gi.repository import Gtk, Pango

    tones = ["neutral", "info", "success", "warning", "critical"]
    lanes = [{"id": f"job-{i}", "label": f"Job {i}", "state": "Working",
              "details": [f"Step {i}"], "tone": tone} for i, tone in enumerate(tones)]
    lanes[0]["state"] = "In progress " * 6 + "now"
    lanes[0]["details"].append("unbroken" * 9)
    lane_widgets = [{"kind": "events", "id": lane["id"], "label": lane["label"],
                     "unit": "gent:lane:v1", "value": [lane["tone"] + ": " + lane["state"], *lane["details"]]}
                    for lane in lanes]
    reserve = dict(lane_widgets[0], id="reserve", label="Reserve", value=[])
    feeds = [{"kind": "events", "id": key, "label": key.title(), "unit": "gent:feed-pair:v1",
              "value": [f"{key} · {i}" for i in range(count)]} for key, count in [("finished", 6), ("next", 19)]]
    metric = {"id": "count", "kind": "metric", "label": "Count", "value": 25}
    action = {"id": "details", "kind": "button", "label": "Open details", "value": "Show details"}
    source = row(3, [metric, *lane_widgets, reserve, *feeds, action])
    layout = [0, {"lanes": lanes}, {"feeds": [7, 8]}, 9]
    projected = dict(source, board=dict(source["board"], layout_v1=layout))
    other = row(4, [metric])

    def labels(widget):
        return [w.get_text() for w in widgets(widget, Gtk.Label)]

    pane.receive({"rows": [source]})
    frame, = pane.grid.get_children()
    assert "Reserve" in labels(frame) and any("gent:feed-pair:v1" in text for text in labels(frame))
    pane.receive({"rows": [dict(source, board=dict(source["board"], layout_v1=[]))]})
    frame, = pane.grid.get_children()
    assert len(frame.body.get_children()) == 1

    settings = Gtk.Settings.get_default()
    state_surfaces = []
    viewport, = widgets(pane, Gtk.Viewport)
    for dark in (False, True):
        settings.props.gtk_application_prefer_dark_theme = dark
        for width, rows, lane_columns, feed_columns in [
            (1024, [projected], 5, 2), (420, [projected], 2, 1),
            (1024, [projected, other], 2, 1), (420, [projected, other], 2, 1),
        ]:
            window.resize(width, 760)
            pane.receive({"rows": rows})
            settle()
            assert window.get_size() == (width, 760)
            frames = pane.grid.get_children()
            assert [frame.title.get_text() for frame in frames] == [r["board"]["title"] for r in rows]
            frame = frames[0]
            _, count, lane_grid, feed_grid, button = frame.body.get_children()
            assert labels(count) == ["Count: 25"] and labels(button) == ["Open details"]
            assert "Reserve" not in labels(frame)
            assert not any("gent:" in text for text in labels(frame))
            assert viewport.props.hadjustment.get_page_size() == viewport.props.hadjustment.get_upper()
            for grid, cols in [(lane_grid, lane_columns), (feed_grid, feed_columns)]:
                group = grid.get_children()
                tops = [child.get_allocation().y for child in group]
                assert tops.count(tops[0]) == cols
                assert all(a <= b for a, b in zip(tops, tops[1:]))
                for field in widgets(grid, Gtk.Label):
                    assert field.get_selectable() and field.get_line_wrap()
                    w, h = field.get_layout().get_pixel_size()
                    assert w <= field.get_allocated_width() and h <= field.get_allocated_height()
            for card, lane in zip(lane_grid.get_children(), lanes, strict=True):
                assert labels(card) == [lane["label"], lane["state"], *lane["details"]]
                state = card.get_children()[1]
                assert state.get_style_context().has_class(lane["tone"])
            assert lane_grid.get_children()[0].get_children()[-1].get_layout().get_line_count() > 1
            for card, feed in zip(feed_grid.get_children(), feeds, strict=True):
                title, body = card.get_children()
                assert title.get_text() == feed["label"] and body.get_text().splitlines() == feed["value"]
                body.grab_focus()
                body.select_region(0, -1)
                body.emit("copy-clipboard")
                assert clipboard.wait_for_text() == "\n".join(feed["value"])
            # Center the final feed row in the scroll viewport (or reach the document end).
            last_row = body.get_text().rpartition("\n")[0] + "\n"
            rect = body.get_layout().index_to_pos(len(last_row.encode()))
            y = body.get_layout_offsets().y - body.get_allocation().y + rect.y // Pango.SCALE
            adjustment = viewport.props.vadjustment
            _, target = body.translate_coordinates(pane.grid, 0, y)
            adjustment.set_value(target - adjustment.get_page_size() / 2)
            _, visible_y = body.translate_coordinates(viewport, 0, y)
            assert 0 <= visible_y <= adjustment.get_page_size() - rect.height / Pango.SCALE
            inspect, = widgets(button, Gtk.Button)
            inspect.clicked()
            assert requests.pop() == ("dashboard_click", {"agent": source["agent"],
                                                         "revision": source["revision"], "widget": action["id"]})
        style = lane_grid.get_children()[0].get_style_context()
        state_surfaces.append(style.get_property("background-color", style.get_state()))
    settings.props.gtk_application_prefer_dark_theme = False
    assert state_surfaces[0].red > state_surfaces[1].red
    print("PASS GTK projected lanes, feed rows and clipboard, board-local wrapping, themes, fallback and actions")
