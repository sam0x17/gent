"""Exercise projected sections and legacy events through the native GTK dashboard."""


def exercise_feed_selection(window, section, settle):
    """Exercise native character offsets and both directions of the split breakpoint."""
    def resize(split):
        window.resize(1024 if split else 760, 760)
        settle()
        return [card.get_children()[1] for card in section.get_visible_child().get_children()]

    _, first, continued = resize(True)
    cut = len(first.get_text()) + 1
    for half, offset in [(1, 0), (2, cut)]:
        field = (first, continued)[half - 1]
        field.grab_focus()
        field.select_region(5, 1)
        full = resize(False)[1]
        assert full.is_focus() and (full.props.selection_bound, full.props.cursor_position) == (offset + 5, offset + 1)
        assert full.get_text()[offset + 1:offset + 5] == field.get_text()[1:5]
        assert resize(True)[half] == field
        assert field.is_focus() and (field.props.selection_bound, field.props.cursor_position) == (5, 1)

    # The boundary newline has no representation in either slice.
    full = resize(False)[1]
    for a, b in [(cut - 4, cut + 2), (cut - 1, cut)]:
        full.select_region(a, b)
        _, retained = resize(True)
        assert retained == full
        assert full.get_selection_bounds() == (True, a, b)
        full.select_region(b, b)
        settle()
        assert section.get_visible_child() == section.split
        assert not any(card.get_children()[1].get_selection_bounds()[0] for card in section.split.get_children())
        full = resize(False)[1]
    # A focused cursor on the first character after the break stays a cursor.
    full.grab_focus()
    full.select_region(cut, cut)
    field = resize(True)[2]
    assert field.is_focus() and not field.get_selection_bounds()[0] and field.props.cursor_position == 0
    assert resize(False)[1].get_selection_bounds() == (False, cut, cut)


def exercise_feed_dialog(window, section, widgets, clipboard):
    from gi.repository import Gtk

    split = section.get_visible_child()
    _, first, continued = [card.get_children()[1] for card in split.get_children()]
    text = first.get_text() + "\n" + continued.get_text()
    cut = len(first.get_text())
    for field in (first, continued):
        menu = Gtk.Menu()
        field.emit("populate-popup", menu)
        action, = [item for item in menu.get_children() if item.get_label() == "Select feed text…"]
        action.activate()
        dialog, = [w for w in Gtk.Window.list_toplevels() if w.get_transient_for() == window and w.get_visible()]
        assert dialog.get_modal() and dialog.get_title() == split.get_children()[1].get_children()[0].get_text()
        view, = widgets(dialog, Gtk.TextView)
        assert not view.get_editable() and view.get_accessible().get_text(0, -1) == text
        buffer = view.get_buffer()
        buffer.select_range(buffer.get_iter_at_offset(cut - 4), buffer.get_iter_at_offset(cut + 6))
        view.emit("copy-clipboard")
        assert clipboard.wait_for_text() == text[cut - 4:cut + 6]
        dialog.response(Gtk.ResponseType.CLOSE)
        assert not dialog.get_visible()
        menu.destroy()


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
        for width, height, rows, lane_columns, feed_columns in [
            (1024, 760, [projected], 5, 3), (1024, 760, [projected, other], 3, 1),
            (760, 760, [projected], 4, 2),
            (540, 720, [projected], 3, 1), (540, 720, [projected, other], 3, 1),
            (420, 760, [projected], 2, 1), (420, 760, [projected, other], 2, 1),
        ]:
            window.resize(width, height)
            pane.receive({"rows": rows})
            settle()
            assert window.get_size() == (width, height)
            frames = pane.grid.get_children()
            assert [frame.title.get_text() for frame in frames] == [r["board"]["title"] for r in rows]
            frame = frames[0]
            _, count, lane_grid, section, button = frame.body.get_children()
            feed_grid = section.get_visible_child()
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
                for field in card.get_children():
                    x, y = field.translate_coordinates(card, 0, 0)
                    assert 0 <= x <= card.get_allocated_width() - field.get_allocated_width()
                    assert 0 <= y <= card.get_allocated_height() - field.get_allocated_height()
                state = card.get_children()[1]
                assert state.get_style_context().has_class(lane["tone"])
            assert lane_grid.get_children()[0].get_children()[-1].get_layout().get_line_count() > 1
            expected_feeds = [(feed["label"], feed["value"]) for feed in feeds]
            if feed_columns == 3:
                name, entries = expected_feeds.pop()
                expected_feeds.extend([(name, entries[:10]), (name + " (continued)", entries[10:])])
            for i, (card, (name, entries)) in enumerate(zip(feed_grid.get_children(), expected_feeds, strict=True)):
                title, body = card.get_children()
                assert title.get_text() == name and body.get_text().splitlines() == entries
                assert body.get_accessible().get_text(0, -1) == body.get_text()
                body.grab_focus()
                body.select_region(0, 3)
                body.emit("copy-clipboard")
                assert clipboard.wait_for_text() == body.get_text()[:3]
                if feed_columns == 3 and i > 0:
                    menu = Gtk.Menu()
                    body.emit("populate-popup", menu)
                    copy, = [item for item in menu.get_children() if item.get_label() == "Copy entire feed"]
                    copy.activate()
                    menu.destroy()
                else:
                    body.select_region(0, -1)
                    body.emit("copy-clipboard")
                source_feed = feeds[0] if i == 0 else feeds[1]
                assert clipboard.wait_for_text() == "\n".join(source_feed["value"])
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
    pane.receive({"rows": [projected]})
    _, _, _, section, _ = pane.grid.get_children()[0].body.get_children()
    exercise_feed_selection(window, section, settle)
    window.resize(1024, 760)
    settle()
    exercise_feed_dialog(window, section, widgets, clipboard)

    # Count thresholds apply to the original right feed; the breakpoint uses the section width.
    for left, right, counts in [(0, 3, [0, 3]), (0, 4, [0, 2, 2]), (3, 5, [3, 5]),
                                (3, 6, [3, 3, 3]), (9, 4, [9, 4])]:
        unordered = ["z", "a", "z", "b", "c", "e", "x", "e", "t"]
        items = [dict(feed, value=unordered[:n]) for n, feed in zip((left, right), feeds)]
        sample = row(0, items)
        sample["board"]["layout_v1"] = [{"feeds": [0, 1]}]
        window.resize(1024, 760)
        pane.receive({"rows": [sample]})
        settle()
        _, section = pane.grid.get_children()[0].body.get_children()
        grid = section.get_visible_child() if isinstance(section, Gtk.Stack) else section
        entries = [card.get_children()[1].get_text().splitlines() for card in grid.get_children()]
        assert list(map(len, entries)) == counts
        assert entries[0] == items[0]["value"]
        assert [entry for column in entries[1:] for entry in column] == items[1]["value"]
        if len(counts) == 3:
            for width, n in [(855, 2), (856, 3)]:
                window.resize(width + 56, 760)
                settle()
                assert section.get_allocated_width() == width
                assert len(section.get_visible_child().get_children()) == n
    print("PASS GTK projected lanes, feed rows and clipboard, board-local wrapping, themes, fallback and actions")
