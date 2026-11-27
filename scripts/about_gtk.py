"""Native About layout, link activation, selection and refreshes in a disposable GTK window."""
from pathlib import Path
import runpy
import sys
import time
from unittest.mock import patch


def exercise():
    repo = Path(__file__).resolve().parents[1]
    desktop = repo / "crates/gent-link/src/desktop"
    icon = str(repo / "assets/branding/inkling-512.png")
    with patch.object(sys, "argv", ["linux.py", icon, "window"]):
        ui = runpy.run_path(str(desktop / "linux.py"), run_name="linux")
    ui = runpy.run_path(str(desktop / "tabs.py"), init_globals=ui, run_name="tabs")
    ui = runpy.run_path(str(desktop / "management.py"), init_globals=ui, run_name="management")
    Gtk, Gdk = ui["Gtk"], ui["Gdk"]

    def settle():
        end = time.monotonic() + .12
        while time.monotonic() < end:
            while Gtk.events_pending():
                Gtk.main_iteration()
            time.sleep(.002)

    root = "https://github.com/sam0x17/gent"
    sha = "abcdef0123456789" * 2 + "12345678"
    commit = root + "/commit/" + sha
    tag = root + "/releases/tag/v0.1.7"
    notes = ("Changes to Gent Desktop.\n\n- Select text in the release notes.\n"
             "- Retain <literal> text & punctuation.\n\n" + "Long paragraph with wrapping words. " * 38
             + "\n\nFinal line.")
    base = dict(title="Gent", version="0.1.7", revision=sha,
                detail=f"Version 0.1.7 · {sha[:12]}\nCopyright © 2026 DuroSoft LLC",
                actions=[{"title": "Check for updates", "kind": "check_update"}])
    release = dict(version="0.1.7", url=tag, notes=notes)
    pane = ui["ManagementPane"]("about")
    window = Gtk.Window(title="Gent About fixture")
    window.add(pane)
    window.set_default_size(850, 605)
    window.show_all()
    text = pane.detail
    accessible = text.get_accessible()

    def links():
        return [accessible.get_link(i) for i in range(accessible.get_n_links())]

    def urls():
        return [link.get_uri(0) for link in links()]

    pane.receive(dict(base, latest_release=release, revision_url=commit))
    for width, height in [(850, 605), (410, 380)]:
        window.resize(width, height)
        settle()
        assert window.get_size() == (width, height), window.get_size()
        assert text.get_selectable() and text.get_text().endswith(notes)
        assert urls() == [tag, commit, tag], urls()
        logo = pane.get_children()[0]
        assert logo.get_mapped() and logo.logo is not None
        assert min(logo.get_allocated_width(), logo.get_allocated_height()) >= 32
        adjustment = pane.about_scroll.get_vadjustment()
        assert adjustment.get_upper() > adjustment.get_page_size() >= 95
        assert pane.about_scroll.get_hadjustment().get_upper() <= pane.about_scroll.get_allocated_width() + 1
        check = pane.actions.buttons[0][0]
        x, y = check.translate_coordinates(window, 0, 0)
        assert x >= 0 and y >= 0 and y + check.get_allocated_height() <= height
        assert text.get_layout().get_line_count() > text.get_text().count("\n") + 1
        start = text.get_text().index("<literal>")
        text.select_region(start, start + len("<literal>"))
        assert text.get_selection_bounds()[-2:] == (start, start + len("<literal>")), text.get_selection_bounds()
        adjustment.set_value(adjustment.get_upper() - adjustment.get_page_size())
        settle()
        assert adjustment.get_value() > 0
        text.select_region(0, 0)
        adjustment.set_value(0)
        settle()
        if len(sys.argv) == 2 and width == 410:
            image = Gdk.pixbuf_get_from_window(window.get_window(), 0, 0, width, height)
            image.savev(sys.argv[1], "png", [], [])
    opened = []
    with patch.object(Gtk, "show_uri_on_window", lambda _w, uri, _t: opened.append(uri)):
        for link in links():
            assert link.do_action(0)
        text.emit("activate-link", "https://example.org/")
        assert opened == [tag, commit, tag], opened
    pane.receive(dict(base, latest_release=release, revision_url=tag))
    assert urls() == [tag, tag, tag]
    pane.receive(dict(base, version="0.1.6", detail=base["detail"].replace("0.1.7", "0.1.6"),
                      latest_release=release, revision_url=commit))
    assert urls() == [commit, tag]
    for invalid in [tag + "?x=1", tag + "/../other", tag.replace("github.com", "github.com.evil"),
                    tag.replace("sam0x17", "another-owner"), "file:///tmp/test"]:
        pane.receive(dict(base, latest_release=dict(release, url=invalid), revision_url=invalid))
        assert not urls() and text.get_text().endswith(notes)
    pane.receive(dict(base, latest_release={"notes": "Notes without a version."}))
    assert not urls() and text.get_text().endswith("Notes without a version.")
    pane.receive(dict(base, latest_release=dict(release, notes=None)))
    assert urls() == [tag, tag] and "Latest release" in text.get_text() and "Final line." not in text.get_text()
    pane.receive(dict(base, revision_url=commit))
    assert urls() == [commit] and text.get_text() == base["detail"]
    pane.receive(dict(base, latest_release=None))
    assert text.get_text() == base["detail"] and not urls()
    window.resize(850, 605)
    settle()
    assert pane.get_children()[0].size == 512
    calls = []
    with patch.dict(pane.load.__globals__, page_request=lambda op, **fields: calls.append((op, fields))):
        pane.actions.buttons[0][0].clicked()
        assert not pane.actions.buttons[0][0].get_sensitive()
        pane.receive({"operation": True, "notice": "Current"})
        assert pane.notice.get_visible() and pane.notice.get_text() == "Current"
        assert calls == [("manage", {"action": {"kind": "check_update"}}), ("about", {})]
    window.destroy()


if __name__ == "__main__":
    exercise()
    print("PASS: native GTK About at 850×605 and 410×380, scrolling, selection, release and revision links, missing fields")
