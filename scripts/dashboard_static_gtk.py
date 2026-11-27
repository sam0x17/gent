"""Direct GTK integration check in a disposable X11 display. Optional WebKitGTK 4.1."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch


def wait(GLib, predicate, timeout=9):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        while GLib.MainContext.default().iteration(False):
            pass
        if predicate():
            return
        time.sleep(.01)
    assert predicate(), predicate.__name__


def exercise(private_document=None, evidence=None, require_browser=False):
    desktop = Path(__file__).resolve().parents[1] / "crates/gent-link/src/desktop"
    with patch.object(sys, "argv", ["linux.py", "", "window"]):
        ui = runpy.run_path(str(desktop / "linux.py"), run_name="linux")
    Gtk, Gdk, GLib = (ui[k] for k in ("Gtk", "Gdk", "GLib"))
    ui["page_request"] = lambda *args, **kw: None
    ui = runpy.run_path(str(desktop / "dashboard_static.py"), init_globals=ui, run_name="dashboard_static")
    ui = runpy.run_path(str(desktop / "dashboard.py"), init_globals=ui, run_name="dashboard")
    pane = ui["DashboardPane"]()
    win = Gtk.Window(title="Dashboard")
    win.set_default_size(1060, 720)
    win.add(pane)
    win.show_all()
    settings = Gtk.Settings.get_default()
    settings.props.gtk_theme_name = "Adwaita"
    settings.props.gtk_application_prefer_dark_theme = False

    def settle():
        end = time.monotonic() + .28
        wait(GLib, lambda: time.monotonic() >= end)

    def row(html=None, revision=1):
        board = {"title": "Fixture board", "widgets": [{"id": "count", "kind": "metric", "label": "Count", "value": 3}]}
        if html is not None:
            board["static_html"] = html
        return {"agent": "fixture", "chat": "Fixture publisher", "revision": revision, "board": board}

    def publish(r, **fields):
        pane.receive(dict(rows=[r], **fields))
        return pane.grid.get_children()[0]

    def loaded(frame):
        a = frame.attachment
        wait(GLib, lambda: a.view is not None and a.get_visible_child() == a.view)
        settle()
        return a, a.view

    def click(view, x, y, button=1):
        wx, wy = view.translate_coordinates(win, x, y)
        _, rx, ry = win.get_window().get_origin()
        scale = view.get_scale_factor()
        subprocess.run(["xdotool", "mousemove", str((rx + wx) * scale), str((ry + wy) * scale),
                        "click", str(button)], check=True)
        settle()

    def selected_text(view):
        cb = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        cb.set_text("fixture clipboard", -1)
        view.grab_focus()
        view.execute_editing_command("SelectAll")
        view.execute_editing_command("Copy")
        wait(GLib, lambda: cb.wait_for_text() not in (None, "fixture clipboard"))
        return cb.wait_for_text()

    def color(view, x, y):
        wx, wy = view.translate_coordinates(win, x, y)
        pix = Gdk.pixbuf_get_from_window(win.get_window(), wx, wy, 1, 1)
        return tuple(pix.get_pixels()[:3])

    assert publish(row()).attachment is None
    if ui["dashboard_browser"]() is None:
        assert publish(row("<p>Optional view</p>")).attachment is None
        assert not require_browser, "Sandboxed WebKitGTK unavailable"
        print("PASS static HTML unavailable; native widget fallback")
        win.destroy()
        return

    # Loopback accepts count even speculative connections with no HTTP payload.
    with closing(socket.socket()) as listener, tempfile.TemporaryDirectory() as scratch:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(.2)
        waiting = threading.Event()
        waiting.set()
        connections = []
        def listen():
            while waiting.is_set():
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                with conn:
                    connections.append(True)
        thread = threading.Thread(target=listen, daemon=True)
        thread.start()
        with socket.create_connection(listener.getsockname(), timeout=1):
            pass
        wait(GLib, lambda: len(connections) == 1)
        address = "http://127.0.0.1:" + str(listener.getsockname()[1])
        file = Path(scratch) / "fixture.txt"
        file.write_text("Local file canary")
        html = f"""<!doctype html><meta name="color-scheme" content="light dark">
        <style>@import url('{address}/style'); *{{box-sizing:border-box}}
        body{{margin:0;font:16px sans-serif}} summary,p,a{{display:block;margin:0;height:32px}}
        .marker{{height:40px;background:#123456}} @media(max-width:500px){{.marker{{background:#ab3456}}}}
        @media(prefers-color-scheme:dark){{.marker{{background:#342abc}}}}</style>
        <link rel="preconnect" href="{address}"><link rel="dns-prefetch" href="{address}">
        <link rel="prefetch" href="{address}/later"><div class="marker"></div>
        <details><summary>Show rows</summary><p>Expanded fixture row</p></details>
        <a href="{address}/away">Navigation fixture</a><a href="{file.as_uri()}">Local fixture</a>
        <svg width="40" height="40"><rect width="40" height="40" fill="#ed1958"/></svg>
        <p>Selectable fixture text</p><img src="{address}/image"><iframe src="{file.as_uri()}"></iframe>
        <script>document.body.append('Script ran')</script>"""
        r = row(html)
        frame = publish(r)
        a, view = loaded(frame)
        assert view.get_context().is_ephemeral() and view.get_context().get_sandbox_enabled()
        assert not view.get_settings().get_enable_javascript()
        assert not view.get_website_data_manager().get_persistent_credential_storage_enabled()
        assert color(view, 5, 8) == (0x12, 0x34, 0x56)
        assert color(view, 5, 150) == (0xed, 0x19, 0x58)
        text = selected_text(view)
        assert "Selectable fixture text" in text and "Script ran" not in text and "Local file canary" not in text
        assert "Expanded fixture row" not in text
        click(view, 30, 54)
        assert "Expanded fixture row" in selected_text(view)
        # A new fallback allocation need not replace the attachment or its open details.
        updated = dict(r, board=dict(r["board"], widgets=[dict(r["board"]["widgets"][0], value=4)]))
        assert publish(updated, layout_only=True) == frame and frame.attachment.view == view
        assert "Expanded fixture row" in selected_text(view)
        click(view, 35, 117)
        click(view, 35, 150)
        assert view.get_uri() == ui["STATIC_BOARD_URI"]
        win.resize(420, 720)
        wait(GLib, lambda: view.get_allocated_width() < 500)
        settle()
        assert color(view, 5, 8) == (0xab, 0x34, 0x56)
        settings.props.gtk_application_prefer_dark_theme = True
        settle()
        assert color(view, 5, 8) == (0x34, 0x2a, 0xbc)
        other = dict(row("<p>Independent board</p>"), agent="other")
        pane.receive({"rows": [updated, other]})
        first, second = pane.grid.get_children()
        _, other_view = loaded(second)
        assert first.attachment.view == view
        assert view.get_context() != other_view.get_context()
        assert view.get_website_data_manager() != other_view.get_website_data_manager()
        pane.receive({"rows": [updated]})
        view.terminate_web_process()
        wait(GLib, lambda: a.get_visible_child() == a.native)
        assert a.native.get_children()[0].get_children()[0].get_text() == "Count: 4"
        waiting.clear()
        thread.join(2)
        assert len(connections) == 1, "a document attempted a network connection"

    assert publish(row(None, revision=2)).attachment is None
    print("PASS ephemeral sandbox, CSS widths/themes, inline SVG, details, clipboard, no network/file/navigation/script, retained layout and failure fallback")
    if private_document:
        # Only the caller-supplied scratch directory receives private captures.
        r = row(private_document.read_text(), revision=3)
        a, view = loaded(publish(r))
        for dark in (False, True):
            settings.props.gtk_application_prefer_dark_theme = dark
            for width in (1060, 420):
                win.resize(width, 720)
                wait(GLib, lambda: win.get_size() == (width, 720))
                settle()
                win.set_focus(None)
                pix = Gdk.pixbuf_get_from_window(win.get_window(), 0, 0, width, 720)
                scale = view.get_scale_factor()
                assert pix.get_width() == width * scale and pix.get_height() == 720 * scale
                name = f"gtk-{width}-{'dark' if dark else 'light'}-{scale}x.png"
                pix.savev(str(evidence / name), "png", [], [])
                print(json.dumps({"image": name, "scale": scale, "document_width": view.get_allocated_width(),
                                  "document_height": view.get_allocated_height(), "sandbox": True}))
    win.destroy()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-document", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--require-browser", action="store_true")
    options = parser.parse_args()
    if options.private_document and not options.evidence:
        parser.error("--private-document needs --evidence")
    exercise(options.private_document, options.evidence, options.require_browser)
