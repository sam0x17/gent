"""Check cached, partial and unsupported Stats snapshots in a private GTK window."""
from pathlib import Path
import sys
from unittest.mock import patch


def exercise():
    root = Path(__file__).resolve().parents[1]
    desktop = root / "crates/gent-link/src/desktop"
    ui = {"__name__": "stats_fixture"}
    with patch.object(sys, "argv", ["linux.py", str(root / "assets/branding/inkling-512.png"), "tray"]):
        for name in ["linux.py", "tabs.py", "management.py", "dashboard.py"]:
            source = desktop / name
            exec(compile(source.read_text(), str(source), "exec"), ui)
    calls = []
    with patch.dict(ui, page_request=lambda op, **fields: calls.append(op)), \
            patch.object(ui["Desktop"], "install_tray"), patch.object(ui["Desktop"], "send"):
        app = ui["Desktop"]()
        pane = app.replies["stats"]
        app.window.show()
        app.tabs.set_current_page(app.tabs.page_num(pane))
        app.refresh.clicked()
        app.refresh.clicked()
        assert calls == ["stats"] and pane.notice.get_text() == "Loading stats…"
        sender = dict(chat_id="fixture-id", name="Fixture Ω", messages="1,234", bytes="56,789")
        stale = dict.fromkeys(pane.nodes.keys, "—")
        stale.update(name="Studio", status="stale", messages="1,234", bytes="56,789", started="2026-11-24 15:00:00")
        missing = dict.fromkeys(pane.nodes.keys, "—")
        missing.update(name="Offline", status="unavailable")
        reply = dict(coverage="1 of 2 cluster nodes reporting · 0 fresh.", outbound="Accepted sends: 1,234",
                     babysitter="Goal resumes: 25", rows=[sender], nodes=[stale, missing])
        pane.receive(reply)
        assert calls == ["stats", "refresh_stats"] and pane.body.get_visible()
        assert pane.notice.get_text() == "Requesting current reports from cluster nodes…"
        app.refresh.clicked()
        assert calls == ["stats", "refresh_stats"]
        for notice in ("Node reports confirmed on refresh: 2 of 2.",
                       "Node reports confirmed on refresh: 1 of 2. Other nodes may be offline or still responding.",
                       "Showing cached figures. Update the local daemon to refresh peers."):
            pane.receive(dict(reply, notice=notice, outbound="Accepted sends: 1,235"))
            assert pane.notice.get_text() == notice and pane.body.get_visible()
            assert pane.fields["outbound"].get_text() == "Accepted sends: 1,235"
            calls.clear()
            app.show()
            assert calls == ["stats"], "raising the window must read the cache"
            pane.receive(reply)
            assert not pane.notice.get_visible()
            app.refresh.clicked()
            assert calls == ["stats", "refresh_stats"] and pane.body.get_visible()
        for error in ("Stats unavailable. Start the local Gent daemon, then refresh.",
                      "This daemon does not support Stats. Update the daemon, then refresh."):
            pane.receive(reply)
            assert pane.body.get_visible() and not pane.empty.get_visible()
            assert list(pane.senders.store[0]) == ["Fixture Ω", "1,234", "56,789", "fixture-id"]
            assert [list(row)[:3] for row in pane.nodes.store] == [["Studio", "stale", "1,234"], ["Offline", "unavailable", "—"]]
            assert pane.fields["coverage"].get_text() == reply["coverage"]
            app.refresh.clicked()
            pane.receive({"error": error})
            assert not pane.body.get_visible() and pane.notice.get_text() == error
            assert not len(pane.senders.store) and not len(pane.nodes.store)
        pane.receive(dict(reply, rows=[]))
        assert pane.body.get_visible() and pane.empty.get_visible() and not pane.senders.get_visible()
        assert not pane.notice.get_visible()
        app.window.destroy()


if __name__ == "__main__":
    exercise()
    print("PASS: GTK Stats covers ranked chats, missing and stale node reports, empty and unavailable states")
