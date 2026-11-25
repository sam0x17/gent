"""Exercise the GTK Settings controls against synthetic supervisor replies."""
from pathlib import Path
import runpy
from unittest.mock import patch
import sys


def exercise():
    desktop = Path(__file__).resolve().parents[1] / "crates/gent-link/src/desktop"
    with patch.object(sys, "argv", ["linux.py", "", "window"]):
        ui = runpy.run_path(str(desktop / "linux.py"), run_name="linux")
    ui = runpy.run_path(str(desktop / "tabs.py"), init_globals=ui, run_name="tabs")
    calls = []
    pane = ui["SettingsPane"]()
    requests = pane.request.__globals__
    with patch.dict(requests, page_request=lambda op, **fields: calls.append((op, fields))):
        window = ui["Gtk"].Window()
        window.add(pane)
        window.show_all()
        pane.load()
        assert calls == [("settings", {}), ("release_channel", {})]
        pane.receive({"values": {"updates": False, "discovery": True}})
        row = pane.channel
        assert any(isinstance(widget, ui["Gtk"].Label) and "one update per node" in widget.get_text()
                   and widget.get_visible() for widget in row.get_children())
        assert not row.choice.get_sensitive() and row.choice.get_active_id() is None
        row.receive({"current": "stable", "can_set": True})
        assert row.choice.get_active_id() == "stable" and len(calls) == 2
        row.choice.set_active_id("beta")
        assert calls.pop() == ("set_release_channel", {"channel": "beta"})
        assert row.choice.get_active_id() == "stable" and not row.choice.get_sensitive()
        assert "Beta" in row.detail.get_text()
        row.receive({"current": "stable", "pending": True, "notice": "Beta queued"})
        pane.poll_channel()
        assert calls.pop() == ("release_channel", {})
        assert row.choice.get_active_id() == "stable"
        row.receive({"current": "stable", "retry": True, "pending": True, "notice": "Outcome unconfirmed"})
        assert row.retry.get_visible() and row.retry.get_sensitive()
        row.retry.clicked()
        assert calls.pop() == ("retry_release_channel", {})
        pane.request("edit")
        assert calls.pop() == ("edit", {})
        pane.receive({"document": "draft"})
        row.receive({"current": "beta", "can_set": True, "notice": "Cluster accepted beta"})
        pane.load()
        assert pane.stack.get_visible_child_name() == "document"
        buf = pane.text.get_buffer()
        assert buf.get_text(*buf.get_bounds(), True) == "draft"
        assert row.choice.get_active_id() == "beta" and not row.retry.get_visible()
        assert not pane.checks["updates"].get_active() and pane.checks["discovery"].get_active()
        row.receive({"current": "beta", "notice": "Read only"})
        assert not row.choice.get_sensitive()
        row.receive({"notice": "Unavailable"})
        assert row.choice.get_active_id() is None and not row.choice.get_sensitive()
        assert len(calls) == 2
        window.destroy()


if __name__ == "__main__":
    exercise()
    print("PASS: GTK cluster release channel and independent node settings")
