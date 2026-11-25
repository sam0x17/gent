"""Check cached, partial and unsupported Stats snapshots in a private GTK window."""
from pathlib import Path
import runpy
import sys
from unittest.mock import patch


def exercise():
    desktop = Path(__file__).resolve().parents[1] / "crates/gent-link/src/desktop"
    with patch.object(sys, "argv", ["linux.py", "", "window"]):
        ui = runpy.run_path(str(desktop / "linux.py"), run_name="linux")
    ui = runpy.run_path(str(desktop / "tabs.py"), init_globals=ui, run_name="tabs")
    pane = ui["StatsPane"]()
    window = ui["Gtk"].Window()
    window.add(pane)
    window.show_all()
    calls = []
    with patch.dict(pane.load.__globals__, page_request=calls.append):
        pane.load()
        pane.load()
        assert calls == ["stats"] and pane.notice.get_text() == "Loading stats…"
        sender = dict(chat_id="fixture-id", name="Fixture Ω", messages="1,234", bytes="56,789")
        stale = dict.fromkeys(pane.nodes.keys, "—")
        stale.update(name="Studio", status="stale", messages="1,234", bytes="56,789", started="2026-11-24 15:00:00")
        missing = dict.fromkeys(pane.nodes.keys, "—")
        missing.update(name="Offline", status="unavailable")
        reply = dict(coverage="1 of 2 cluster nodes reporting · 0 fresh.", outbound="Accepted sends: 1,234",
                     babysitter="Goal resumes: 25", rows=[sender], nodes=[stale, missing])
        for error in ("Stats unavailable. Start the local Gent daemon, then refresh.",
                      "This daemon does not support Stats. Update the daemon, then refresh."):
            pane.receive(reply)
            assert pane.body.get_visible() and not pane.empty.get_visible()
            assert list(pane.senders.store[0]) == ["Fixture Ω", "1,234", "56,789", "fixture-id"]
            assert [list(row)[:3] for row in pane.nodes.store] == [["Studio", "stale", "1,234"], ["Offline", "unavailable", "—"]]
            assert pane.fields["coverage"].get_text() == reply["coverage"]
            pane.load()
            pane.receive({"error": error})
            assert not pane.body.get_visible() and pane.notice.get_text() == error
            assert not len(pane.senders.store) and not len(pane.nodes.store)
        pane.receive(dict(reply, rows=[]))
        assert pane.body.get_visible() and pane.empty.get_visible() and not pane.senders.get_visible()
        assert not pane.notice.get_visible()
    window.destroy()


if __name__ == "__main__":
    exercise()
    print("PASS: GTK Stats covers ranked chats, missing and stale node reports, empty and unavailable states")
