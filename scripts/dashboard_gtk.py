"""Exercise the GTK dashboard in a private Xvfb display (no daemon required)."""
from pathlib import Path
import runpy
import sys
import tempfile
import time
from unittest.mock import patch

from desktop_fixture_browser import install_fixture_browser


def exercise(root):
    install_fixture_browser(root)
    desktop = Path(__file__).resolve().parents[1] / "crates/gent-link/src/desktop"
    with patch.object(sys, "argv", ["linux.py", "", "window"]):
        ui = runpy.run_path(str(desktop / "linux.py"), run_name="linux")
    Gtk, GLib = ui["Gtk"], ui["GLib"]
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
    pane.receive({"rows": boards[:1]})
    layout(826, 500, [1])
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
    buttons = widgets(pane, Gtk.Button)
    assert len(buttons) == len(links) + 1 and len(links) == len(urls)
    for i, (link, url) in enumerate(zip(links, urls)):
        assert link.get_label() == f"Report {i}" and link.get_tooltip_text() == link.get_uri() == url
        link.clicked()
        opened = root / "opened"
        wait(lambda: opened.exists() and opened.read_text().splitlines() == urls[:i + 1])
    assert requests == []
    buttons[-1].clicked()
    assert requests == [("dashboard_click", {"agent": "agent-0", "revision": 1, "widget": "inspect"})]
    pane.receive({"rows": []})
    assert not widgets(pane, Gtk.Frame) and pane.notice.get_visible()
    window.destroy()
    print("PASS dashboard allocations, scrolling, link tooltips, default URI handlers and action routing")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="gent-gtk-dashboard-") as folder:
        exercise(Path(folder))
