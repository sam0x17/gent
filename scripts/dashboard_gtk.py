"""Exercise the GTK dashboard in a private Xvfb display (no daemon required)."""
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import time
from unittest.mock import patch

import cairo

from desktop_dashboard_samples import chart_widgets, image_uri
from desktop_fixture_browser import install_fixture_browser


def exercise_visibility(pane, Gtk, widgets, requests, boards, example):
    from gi.repository import Pango

    restore, = widgets(pane, Gtk.MenuButton)
    assert restore.get_label() == "Restore hidden dashboards"
    rows = [dict(row, chat="Fixture chat", board=dict(row["board"], title="Same title")) for row in boards[:2]]
    hidden = [{"agent": row["agent"], "chat": row["chat"], "title": row["board"]["title"]} for row in rows]
    pane.receive({"rows": rows, "hidden": []})
    assert not restore.get_visible()
    cards = pane.grid.get_children()
    for card, row in zip(cards, rows, strict=True):
        hide, = widgets(card, Gtk.Button)
        assert hide.get_label() == "×" and hide.get_can_focus()
        assert hide.get_accessible().get_name() == hide.get_tooltip_text() == "Hide dashboard"
        assert max(hide.get_preferred_width()[1], hide.get_preferred_height()[1]) <= 32
        hide.clicked()
        assert requests.pop() == ("dashboard_hide", {"agent": row["agent"]})
    pane.receive({"error": "Hide failed"})
    assert pane.grid.get_children() == cards and not restore.get_visible()

    pane.receive({"rows": rows[:1], "hidden": hidden[1:]})
    remaining, = pane.grid.get_children()
    assert restore.get_visible() and not pane.notice.get_visible()
    assert restore.get_relief() == Gtk.ReliefStyle.NONE and restore.get_can_focus()
    assert restore.get_state_flags() & Gtk.StateFlags.LINK
    caption = restore.get_child()
    link = Gtk.LinkButton.new_with_label("https://example.test", "Fixture link")
    reference = link.get_child()
    assert caption.get_style_context().get_color(caption.get_state_flags()).equal(
        reference.get_style_context().get_color(reference.get_state_flags()))
    assert restore.get_preferred_height()[1] <= caption.get_preferred_height()[1] + 6
    attrs = caption.get_layout().get_attributes().get_attributes()
    assert any(a.klass.type == Pango.AttrType.UNDERLINE and a.as_int().value for a in attrs)
    menu = restore.get_popup()
    choice, = menu.get_children()
    assert choice.get_label() == "Same title — Fixture chat"
    pane.receive({"unchanged": True})
    pane.receive({"layout_only": True, "rows": rows[:1]})
    assert pane.grid.get_children() == [remaining] and restore.get_popup() == menu

    pane.receive({"rows": [], "hidden": hidden, "all_hidden": True, "example": example})
    sample, = pane.grid.get_children()
    assert sample.publisher.get_text() == "Sample test results" and not widgets(sample, Gtk.Button)
    assert restore.get_visible() and pane.notice.get_text() == "All dashboards are hidden."
    choices = restore.get_popup().get_children()
    for choice, row in zip(choices, rows, strict=True):
        assert choice.get_label() == f"Same title — Fixture chat ({row['agent']})"
        choice.activate()
        assert requests.pop() == ("dashboard_restore", {"agent": row["agent"]})
    pane.receive({"error": "Restore failed"})
    pane.receive({"layout_only": True, "unchanged": True})
    assert pane.notice.get_text() == "Restore failed" and restore.get_popup().get_children() == choices
    pane.receive({"unchanged": True, "hidden": hidden[1:]})
    choice, = restore.get_popup().get_children()
    assert choice.get_label() == "Same title — Fixture chat" and pane.notice.get_text() == "All dashboards are hidden."
    pane.receive({"layout_only": True, "rows": [], "hidden": [], "all_hidden": False, "example": example})
    assert not restore.get_visible() and pane.notice.get_text() == "No chats have published a dashboard."
    pane.receive({"layout_only": True, "unchanged": True, "hidden": hidden})
    assert restore.get_visible() and pane.notice.get_text() == "No chats have published a dashboard."
    pane.receive({"rows": rows[1:], "hidden": hidden[:1]})
    real, = pane.grid.get_children()
    assert real.publisher.get_text() == "Fixture chat"
    choice, = restore.get_popup().get_children()
    choice.activate()
    assert requests.pop() == ("dashboard_restore", {"agent": rows[0]["agent"]})
    pane.receive({"rows": rows, "hidden": []})
    assert not restore.get_visible() and len(pane.grid.get_children()) == 2

    pane.receive({"rows": rows[:1], "hidden": hidden[1:]})
    restore.clicked()
    menu = restore.get_popup()
    assert menu.get_visible()
    pane.receive({"rows": [], "pro_required": True})
    assert not pane.grid.get_children() and not restore.get_visible()
    assert not menu.get_visible() and restore.get_popup() is None
    assert "Gent Pro" in pane.notice.get_text() and "https://gent.link/pricing" in pane.notice.get_label()


def exercise(root):
    # GTK_THEME forces a variant even when GtkSettings changes. This subprocess
    # exercises live changes; the daemon smoke inherits the caller's chosen theme.
    os.environ.pop("GTK_THEME", None)
    install_fixture_browser(root)
    desktop = Path(__file__).resolve().parents[1] / "crates/gent-link/src/desktop"
    with patch.object(sys, "argv", ["linux.py", "", "window"]):
        ui = runpy.run_path(str(desktop / "linux.py"), run_name="linux")
    Gtk, GLib = ui["Gtk"], ui["GLib"]
    settings = Gtk.Settings.get_default()
    settings.props.gtk_theme_name = "Adwaita"
    settings.props.gtk_application_prefer_dark_theme = False
    requests = []
    ui["page_request"] = lambda action, **fields: requests.append((action, fields))
    pane = runpy.run_path(str(desktop / "dashboard.py"), init_globals=ui, run_name="dashboard")["DashboardPane"]()
    window = Gtk.Window()
    window.add(pane)
    window.show_all()

    def widgets(container, kind):
        found = []
        for widget in container.get_children():
            if isinstance(widget, kind):
                found.append(widget)
            if isinstance(widget, Gtk.Container):
                found.extend(widgets(widget, kind))
        return found

    def wait(check):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            while GLib.MainContext.default().iteration(False):
                pass
            if check():
                return
            time.sleep(.01)
        assert check(), check.__name__

    def settle():
        deadline = time.monotonic() + .25
        wait(lambda: time.monotonic() >= deadline)

    def row(i, widgets):
        return {"chat": f"Chat {i}", "agent": f"agent-{i}", "revision": i + 1,
                "board": {"title": f"Board {i}", "widgets": widgets}}

    viewport, = widgets(pane, Gtk.Viewport)
    h, v = viewport.props.hadjustment, viewport.props.vadjustment

    def layout(width, height, counts, overflow=False):
        window.resize(width + 24, height + 24)
        frames = widgets(pane, Gtk.Frame)

        def allocated():
            return (window.get_size() == (width + 24, height + 24)
                    and viewport.get_allocated_height() == height
                    and all(frame.get_allocated_width() > 1 for frame in frames))

        wait(allocated)
        actual_width = viewport.get_allocated_width()
        rects = []
        rows = {}
        for frame in frames:
            rect = frame.get_allocation()
            rects.append((rect.x, rect.y, rect.width, rect.height))
            rows.setdefault(rect.y, []).append(rect)
        print(f"{actual_width}x{height} viewport, allocations {rects}")
        assert [len(line) for line in rows.values()] == counts, rects
        next_y = 0
        for y, line in rows.items():
            assert y == next_y and line[0].x == 0
            assert line[-1].x + line[-1].width == actual_width
            assert all(a.x + a.width + 10 == b.x for a, b in zip(line, line[1:]))
            widths = [r.width for r in line]
            assert max(widths) - min(widths) <= 1
            assert all(r.height == line[0].height and r.height >= 160 for r in line)
            next_y = y + line[0].height + 10
        assert h.get_upper() == h.get_page_size() == actual_width
        assert v.get_upper() == next_y - 10 and v.get_page_size() == height
        assert (v.get_upper() > height) == overflow
        return rects

    text = {"id": "state", "kind": "text", "label": "State", "value": "Ready"}
    boards = [row(i, [text]) for i in range(5)]
    assert pane.grid.chart_widths(None, 32) == [260]
    assert pane.grid.chart_widths(100, 32) == [160]
    assert pane.grid.chart_widths(100000, 32) == [16384] * 4
    pane.receive({"rows": boards[:1]})
    layout(826, 500, [1])
    wait(lambda: requests and requests[-1][1]["chart_widths"] == [792, 376])
    assert [op for op, _ in requests].count("dashboard") == 1
    assert requests[0][0] == "dashboard"
    requests.clear()
    # Coalesce several actual allocations. The final single board still reports
    # every occupancy the viewport could support after the next publication.
    rect = pane.grid.get_allocation()
    for width in (827, 837, 848):
        rect.width = width
        pane.grid.size_allocate(rect)
    layout(852, 500, [1])
    settle()
    assert [(op, f["chart_widths"]) for op, f in requests] == [("dashboard_layout", [824, 392, 248])], requests
    layout(853, 505, [1])
    settle()
    assert len(requests) == 1  # Sub-bucket width and height changes.
    pane.load()
    pane.load()
    settle()
    assert [op for op, _ in requests] == ["dashboard_layout", "dashboard"]
    assert requests[1][1] == requests[0][1]
    pane.receive({"rows": boards[:2]})
    two = layout(260, 450, [1, 1])
    assert two[0][3] == two[1][3] == 220
    pane.receive({"rows": boards[:4]})
    four = layout(700, 500, [2, 2])
    assert all(ht == 245 for _, _, _, ht in four)
    pane.receive({"rows": boards[:3]})
    three = layout(800, 670, [2, 1])
    areas = [w * ht for _, _, w, ht in three]
    assert max(areas) < 1.02 * min(areas), areas
    pane.receive({"rows": boards})
    five = layout(840, 500, [3, 2])
    assert max(w * ht for _, _, w, ht in five) < 1.02 * min(w * ht for _, _, w, ht in five)
    clamped = layout(839, 501, [2, 2, 1])
    assert clamped[-1][-1] == 160 and abs(clamped[0][-1] - clamped[2][-1]) <= 1
    layout(1120, 500, [4, 1])
    wait(lambda: requests[-1][1]["chart_widths"] == [1088, 520, 336, 240])
    stacked = layout(260, 500, [1] * 5, overflow=True)
    assert all(ht == 160 for _, _, _, ht in stacked)
    v.set_value(v.get_upper() - v.get_page_size())
    assert v.get_value() + v.get_page_size() == v.get_upper()
    layout(560, 501, [2, 2, 1])

    # A tall final card takes its natural height even when its proportional
    # share would be smaller. The shorter cards still share the remaining space.
    events = {"id": "log", "kind": "events", "label": "Log", "value": ["entry"] * 16}
    pane.receive({"rows": boards[:2] + [row(2, [events])]})
    mixed = layout(800, 670, [2, 1])
    assert mixed[-1][3] > three[-1][3] and mixed[0][3] < three[0][3]
    log, = [w for w in widgets(pane, Gtk.Label) if w.get_text().startswith("entry")]
    assert log.get_allocated_height() >= log.get_layout().get_pixel_size()[1]
    layout(800, 300, [2, 1], overflow=True)

    long_text = dict(text, value="verylongword" * 120)
    pane.receive({"rows": [row(0, [long_text])]})
    layout(260, 260, [1], overflow=True)
    value, = [w for w in widgets(pane, Gtk.Label) if w.get_text() == long_text["value"]]
    assert value.get_allocated_height() >= value.get_layout().get_pixel_size()[1] > 260

    # An unchanged snapshot clears the transient notice while retaining the
    # decoded content, focusable widgets and the user's place in a long board.
    v.set_value(85)
    pane.receive({"error": "Daemon temporarily unavailable"})
    wait(lambda: pane.notice.get_visible())
    pane.receive({"unchanged": True})
    wait(lambda: not pane.notice.get_visible())
    assert v.get_value() == 85 and value in widgets(pane, Gtk.Label)

    def rendered(widget):
        surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, widget.get_allocated_width(), widget.get_allocated_height())
        widget.draw(cairo.Context(surface))
        return ui["Gdk"].pixbuf_get_from_surface(surface, 0, 0, surface.get_width(), surface.get_height())

    def rgb(pixbuf, x, y):
        offset = y * pixbuf.get_rowstride() + x * pixbuf.get_n_channels()
        return tuple(pixbuf.get_pixels()[offset:offset + 3])

    from gi.repository import Atk, Pango
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="100" height="40" viewBox="0 0 100 40">'
           '<rect width="100" height="40" fill="white"/><rect x="50" width=".4" height="40" fill="red"/></svg>')
    charts = [dict(w, chart_svg=svg, chart_description=w["kind"] + " details") for w in chart_widgets()]
    # Compare reported logical widths with GTK chart allocations in both rows.
    # Apply a width-specific SVG as the cached supervisor would after a resize.
    pane.receive({"rows": [row(i, charts[:1]) for i in range(3)]})
    layout(800, 830, [2, 1])
    wait(lambda: requests[-1][1]["chart_widths"] == [768, 360])
    for plot, count in zip(widgets(pane, Gtk.DrawingArea), (2, 2, 1)):
        assert abs(requests[-1][1]["chart_widths"][count - 1] - plot.get_allocated_width()) <= 4
    def resized_chart(widget, width):
        graphic = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="96" '
                   f'viewBox="0 0 {width} 96"><circle cx="20" cy="20" r="6"/></svg>')
        return dict(widget, chart_svg=graphic)

    cached = [row(i, [resized_chart(charts[0], width)]) for i, width in enumerate((360, 360, 768))]
    before = list(requests)
    pane.receive({"error": "Daemon temporarily unavailable"})
    pane.receive({"layout_only": True, "rows": cached})
    settle()
    assert requests == before
    assert pane.notice.get_text() == "Daemon temporarily unavailable"
    pane.receive({"layout_only": True, "unchanged": True})
    assert pane.notice.get_text() == "Daemon temporarily unavailable"
    pane.receive({"unchanged": True})
    assert not pane.notice.get_visible()
    for plot in widgets(pane, Gtk.DrawingArea):
        assert abs(plot.get_allocated_height() - 96) <= 2
    metric = {"id": "rate", "kind": "metric", "label": "Δ <rate>:  ", "value": 12.5, "unit": "jobs & runs"}
    pane.receive({"rows": [row(0, charts + [metric])]})
    for width in (800, 260):
        layout(width, 280, [1], overflow=True)
        plots = widgets(pane, Gtk.DrawingArea)
        assert len(plots) == len(charts)
        for plot, w in zip(plots, charts):
            a = plot.get_accessible()
            assert a.get_role() == Atk.Role.IMAGE and a.get_name() == w["label"]
            assert a.get_description() == w["chart_description"]
            pixels = rendered(plot)
            pw, ph = pixels.get_width(), pixels.get_height()
            assert pw >= width - 50 and abs(ph - .4 * pw) < 1
            assert rgb(pixels, pw // 4, ph // 2) == (255, 255, 255)
            if width == 800:
                # A subpixel-wide SVG stripe resolves to solid red when enlarged.
                assert rgb(pixels, pw // 2 + 1, ph // 2) == (255, 0, 0)
    fields = [w for w in widgets(pane, Gtk.Label) if w.get_text() == "Δ <rate>: 12.5 jobs & runs"]
    field, = fields
    attrs = field.get_layout().get_attributes().get_attributes()
    weight, = [a for a in attrs if a.klass.type == Pango.AttrType.WEIGHT]
    assert weight.as_int().value == Pango.Weight.BOLD
    assert (weight.start_index, weight.end_index) == (0, len("Δ <rate>:".encode()))
    assert "3 ms" in [w.get_text() for w in widgets(pane, Gtk.Label)]

    v.set_value(85)
    pane.receive({"error": "Transient dashboard error"})
    pane.receive({"page": "dashboard", "unchanged": True})
    assert widgets(pane, Gtk.DrawingArea) == plots and v.get_value() == 85 and not pane.notice.get_visible()

    layout(600, 280, [1], overflow=True)
    wait(lambda: requests[-1][1]["chart_widths"] == [568, 264])
    assert requests[-1][0] == "dashboard_layout" and v.get_value() == 85
    resized = [resized_chart(w, 568) for w in charts]
    before = list(requests)
    pane.receive({"layout_only": True, "rows": [row(0, resized + [metric])]})
    settle()
    assert requests == before and v.get_value() == 85

    with patch.object(ui["gi"], "require_version", side_effect=ValueError("Rsvg not installed")):
        pane.receive({"rows": [row(0, [charts[0], dict(metric, label="Δ <rate>")])]})
    labels = [w.get_text() for w in widgets(pane, Gtk.Label)]
    assert not widgets(pane, Gtk.DrawingArea)
    assert "graph details" in labels and "3 ms" in labels and "Δ <rate>: 12.5 jobs & runs" in labels

    pane.receive({"rows": [row(0, [dict(charts[0], chart_svg="<broken>")])]})
    assert "graph details" in [w.get_text() for w in widgets(pane, Gtk.Label)]

    for fmt in ("PNG", "JPEG"):
        item = {"id": "sample", "kind": "image", "label": "Fixture preview", "value": image_uri(fmt)}
        pane.receive({"rows": [row(0, [item])]})
        layout(260, 300, [1])
        preview, = widgets(pane, Gtk.DrawingArea)
        assert preview.get_accessible().get_name() == item["label"]
        assert fmt in preview.get_accessible().get_description()
        pixels = rendered(preview)
        pw, ph = pixels.get_width(), pixels.get_height()
        assert pw < 320 and abs(ph - pw / 4) < 1
        red = rgb(pixels, pw // 4, ph // 2)
        blue = rgb(pixels, 3 * pw // 4, ph // 2)
        assert red[0] > 180 > red[2] and blue[2] > 170 > blue[0]

    pane.receive({"rows": [row(0, [dict(item, value=image_uri("PNG", (80, 960)))])]})
    layout(260, 200, [1], overflow=True)
    portrait, = widgets(pane, Gtk.DrawingArea)
    pixels = rendered(portrait)
    assert pixels.get_height() == 360
    mid = pixels.get_width() // 2
    assert rgb(pixels, mid - 10, 180)[0] > 180 and rgb(pixels, mid + 10, 180)[2] > 170
    assert rgb(pixels, mid + 18, 180) != rgb(pixels, mid + 10, 180)

    for bad in ("https://example.invalid/preview.png", "file:///tmp/preview.png",
                "data:image/svg+xml;base64,PHN2Zy8+", "data:image/png;base64,!!!",
                "data:image/png;base64,aW52YWxpZA==", image_uri("JPEG").replace("jpeg;", "png;"),
                image_uri("PNG", (2049, 1)), image_uri("PNG", (1025, 1025))):
        pane.receive({"rows": [row(0, [dict(item, value=bad)])]})
        assert not widgets(pane, Gtk.DrawingArea)
        assert "Image unavailable" in [w.get_text() for w in widgets(pane, Gtk.Label)]

    themed = [dict(charts[0], value=[15.0]),
              {"id": "pct", "label": "Complete", "kind": "progress", "value": 72.0, "unit": "%"},
              {"id": "count", "label": "Workers", "kind": "gauge", "value": 3.125, "max": 8},
              dict(metric, value=0.0), dict(item, value=image_uri("PNG"))]

    def apply_palette(expected_op):
        action, fields = requests[-1]
        assert action == expected_op and set(fields) == {"palette", "chart_widths"}
        assert fields["chart_widths"] == [232]
        palette = fields["palette"]
        assert set(palette) == {"surface", "text", "secondary", "accent"}
        assert all(len(rgb) == 3 and all(type(v) is int and 0 <= v <= 255 for v in rgb) for rgb in palette.values())
        accent = "#%02x%02x%02x" % tuple(palette["accent"])
        themed[0] = dict(themed[0], chart_svg=
            f'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="40" viewBox="0 0 100 40">'
            f'<circle cx="50" cy="20" r="8" fill="{accent}"/></svg>')
        pane.receive({"rows": [row(0, list(themed))], "layout_only": expected_op == "dashboard_layout"})
        layout(260, 240, [1], overflow=True)
        frame, = widgets(pane, Gtk.Frame)
        card = rendered(frame)
        assert rgb(card, card.get_width() - 5, 40) == tuple(palette["surface"])
        for label, key in [(frame.title, "text"), (frame.publisher, "secondary")]:
            x, y = label.translate_coordinates(frame, 0, 0)
            assert x >= 14 and y >= 14
            content = card.new_subpixbuf(x, y, label.get_allocated_width(), label.get_allocated_height())
            pixels = content.get_pixels()
            stride, channels = content.get_rowstride(), content.get_n_channels()
            assert any(max(abs(a - b) for a, b in zip(pixels[k:k+3], palette[key])) <= 5
                       for y in range(content.get_height())
                       for k in range(y * stride, y * stride + content.get_width() * channels, channels))
        style = frame.title.get_style_context()
        assert style.get_property("font-size", style.get_state()) >= 17
        for cls in (Gtk.ProgressBar, Gtk.LevelBar):
            bar, = widgets(frame, cls)
            pixels = rendered(bar)
            assert rgb(pixels, pixels.get_width() // 8, pixels.get_height() // 2) == tuple(palette["accent"])
            assert pixels.get_height() <= 8
        chart, image = widgets(frame, Gtk.DrawingArea)
        pixels = rendered(chart)
        assert rgb(pixels, pixels.get_width() // 2, pixels.get_height() // 2) == tuple(palette["accent"])
        labels = {w.get_text(): w for w in widgets(frame, Gtk.Label)}
        assert "Δ <rate>: 0 jobs & runs" in labels
        for title, value in [("Sample history", "15 ms"), ("Complete", "72%"), ("Workers", "3.125")]:
            a, b = labels[title].get_allocation(), labels[value].get_allocation()
            assert a.y == b.y and a.x + a.width <= b.x
        return palette, rendered(image).get_pixels()

    settle()
    requests.clear()
    pane.queue_refresh()
    pane.load()  # A poll takes precedence over a pending style/layout refresh.
    wait(lambda: requests)
    light, original_image = apply_palette("dashboard")
    v.set_value(80)
    settings.props.gtk_application_prefer_dark_theme = True
    wait(lambda: len(requests) > 1)
    dark, dark_image = apply_palette("dashboard_layout")
    settle()
    assert len(requests) == 2 and sum(dark["surface"]) < sum(light["surface"])
    assert dark_image == original_image and v.get_value() == 80

    custom = Gtk.CssProvider()
    custom.load_from_data(b"@define-color theme_selected_bg_color #bd4d87;")
    Gtk.StyleContext.add_provider_for_screen(window.get_screen(), custom, Gtk.STYLE_PROVIDER_PRIORITY_USER)
    wait(lambda: len(requests) > 2)
    accented, accent_image = apply_palette("dashboard_layout")
    settle()
    assert len(requests) == 3 and accented["accent"] == [189, 77, 135]
    assert dark["accent"] != accented["accent"] and accent_image == original_image and v.get_value() == 80
    window.hide()
    Gtk.StyleContext.remove_provider_for_screen(window.get_screen(), custom)
    settings.props.gtk_application_prefer_dark_theme = False
    settle()
    assert len(requests) == 3
    window.show()
    wait(lambda: len(requests) == 4)
    settle()
    assert requests[-1] == ("dashboard", requests[0][1]) and len(requests) == 4
    requests.clear()

    # A traditional scrollbar and user CSS both reduce the available plot width.
    scroll, = widgets(pane, Gtk.ScrolledWindow)
    scroll.set_overlay_scrolling(False)
    inset = Gtk.CssProvider()
    inset.load_from_data(b".gent-dashboard-card { padding-left: 5px; padding-right: 7px; }")
    Gtk.StyleContext.add_provider_for_screen(window.get_screen(), inset, Gtk.STYLE_PROVIDER_PRIORITY_USER)
    settle()
    chart, _ = widgets(pane, Gtk.DrawingArea)
    assert viewport.get_allocated_width() < 260
    assert chart.get_allocated_width() == viewport.get_allocated_width() - 44
    assert [op for op, _ in requests] == ["dashboard_layout"]
    negotiated, = requests[0][1]["chart_widths"]
    assert abs(chart.get_allocated_width() - negotiated) <= 4
    Gtk.StyleContext.remove_provider_for_screen(window.get_screen(), inset)
    scroll.set_overlay_scrolling(True)
    settle()
    requests.clear()

    urls = ["http://localhost:8123/job?q=one%20two#chart", "HTTPS://192.168.1.2:444/report",
            "http://[::1]/status"]
    link_fields = [{"id": str(i), "kind": "link", "label": f"Report {i}", "value": url}
                   for i, url in enumerate(urls)]
    invalid = [None, "file:///tmp/a", "javascript:alert(1)", "data:text/plain,test", "gent://chat",
               "/relative", "//host", "https:host", "https://", "https:///path", "https://?x",
               "http://[::1", "https://host:65536", "https://host/a b", "http://host/\n",
               "https://host/\x7f", "https://host/\u0080", "https://host\\other"]
    invalid_fields = [{"id": f"bad{i}", "kind": "link", "label": f"Bad {i}", "value": url}
                      for i, url in enumerate(invalid)]
    action = {"id": "inspect", "kind": "button", "label": "Inspect", "value": "Report status"}
    pane.receive({"rows": [row(0, link_fields + invalid_fields + [action])]})
    links = widgets(pane, Gtk.LinkButton)
    buttons = widgets(pane.grid, Gtk.Button)
    assert len(buttons) == len(links) + 2 and len(links) == len(urls)
    for i, (link, url) in enumerate(zip(links, urls)):
        assert link.get_label() == f"Report {i}" and link.get_tooltip_text() == link.get_uri() == url
        link.clicked()
        opened = root / "opened"
        wait(lambda: opened.exists() and opened.read_text().splitlines() == urls[:i + 1])
    assert requests == []
    inspect, = [b for b in buttons if b.get_label() == "Inspect"]
    inspect.clicked()
    assert requests == [("dashboard_click", {"agent": "agent-0", "revision": 1, "widget": "inspect"})]
    example = json.loads((desktop / "dashboard-example.json").read_text())
    graph, = [w for w in example["board"]["widgets"] if w["kind"] == "graph"]
    graph.update(chart_svg=svg, chart_description="Tests passed per batch. 4 samples.")
    empty = {"rows": [], "hidden": [], "example": example}
    free = dict(empty, pro_required=True)
    window.resize(850, 605)
    pane.receive(free)
    settle()
    sample, = pane.grid.get_children()
    plot, = widgets(sample, Gtk.DrawingArea)
    assert plot.get_accessible().get_name() == "Tests passed per batch"
    intro = next(label for label in widgets(sample, Gtk.Label) if label.get_text().startswith("Ask a registered chat to build a dashboard like this one."))
    for widget in [intro, plot]:
        _, top = widget.translate_coordinates(viewport, 0, 0)
        assert 0 <= top < viewport.get_allocated_height()
    window.resize(284, 424)
    settle()
    card, = pane.grid.get_children()
    assert card.get_accessible().get_name() == "Example dashboard" and card.publisher.get_text() == "Sample test results"
    assert not widgets(card, Gtk.Button) and "https://gent.link/pricing" in pane.notice.get_label()
    bar, = widgets(card, Gtk.ProgressBar)
    assert bar.get_fraction() == .75 and bar.get_accessible().get_name() == "Tests passed"
    assert h.get_page_size() == h.get_upper() and viewport.get_allocated_width() <= 260
    labels = {label.get_text(): label for label in widgets(card, Gtk.Label)}
    assert "Ask a registered chat to build a dashboard like this one. On Pro, each chat can publish one and update it across your cluster." in labels
    assert "18 of 24" in labels
    clipboard = Gtk.Clipboard.get(ui["Gdk"].SELECTION_CLIPBOARD)
    for prompt in ("Make a Gent dashboard for this test run. Show how many tests have passed and list any failures.",
                   "Update my dashboard after each test batch."):
        field = labels[prompt]
        assert field.get_selectable() and field.get_layout().get_pixel_size()[1] <= field.get_allocated_height()
        field.grab_focus()
        field.select_region(0, -1)
        pane.receive(free)
        assert pane.grid.get_children() == [card] and field.get_selection_bounds() == (True, 0, len(prompt))
        field.emit("copy-clipboard")
        assert clipboard.wait_for_text() == prompt
    pane.receive(empty)
    assert pane.grid.get_children() == [card] and pane.notice.get_text() == "No chats have published a dashboard."
    pane.receive({"error": "Daemon offline", "hidden": []})
    pane.receive({"layout_only": True, "unchanged": True})
    assert not pane.grid.get_children() and pane.notice.get_text() == "Daemon offline"
    pane.receive(empty)
    assert len(pane.grid.get_children()) == 1
    exercise_visibility(pane, Gtk, widgets, requests, boards, example)
    pane.receive({"rows": []})
    assert not widgets(pane, Gtk.Frame) and pane.notice.get_visible()
    pane.receive({"error": "Disconnected"})
    pane.receive({"unchanged": True})
    assert pane.notice.get_text() == "No chats have published a dashboard."
    window.destroy()
    print("PASS dashboard allocations, logical chart widths, cached resize and theme redraw, scroll and notices, compact readings, SVG and image pixels, accessibility, links, actions, hide and selective restore")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="gent-gtk-dashboard-") as folder:
        exercise(Path(folder))
