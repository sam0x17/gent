#!/usr/bin/env python3
"""Exercise the built daemon and MCP server using independent JSON-RPC clients.

Uses a temporary state directory and synthetic messages only. No model calls.
Run: python3 scripts/smoke_mcp.py target/debug/gent
"""
import base64
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mcp_client import Client
from mcp_fixtures import PNG
from relay_checks import exercise_turns


def main():
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/gent").resolve())
    # Short /tmp paths work within macOS's Unix-domain socket path limit.
    with tempfile.TemporaryDirectory(prefix="gent-", dir="/tmp") as directory:
        home = Path(directory) / "state"
        base = [binary, "--home", str(home)]

        def cli(*args):
            return subprocess.run(base + ["--json", *args], capture_output=True, text=True, check=True).stdout

        cli("cluster", "new", "proof", "--local")
        daemon = None
        clients = []

        def start_daemon():
            process = subprocess.Popen(base + ["daemon", "run"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read())
                if (home / "daemon.sock").exists():
                    probe = subprocess.run(base + ["daemon", "status"], check=False, capture_output=True, text=True)
                    if probe.returncode == 0:
                        return process
                time.sleep(0.02)
            process.kill()
            process.wait()
            raise AssertionError("daemon did not start")

        def connect(binding):
            client = Client(base + ["mcp", "serve", "--binding", str(home / "bindings" / binding)])
            clients.append(client)
            return client

        try:
            daemon = start_daemon()
            a, b, outsider = connect("a.key"), connect("b.key"), connect("outsider.key")
            aid = a.call("gent_register", {"name": "a", "provider": "agents"})[0]["agent"]["id"]
            bid = b.call("gent_register", {"name": "b", "provider": "arbitrary-b"})[0]["agent"]["id"]
            hid = outsider.call("gent_register", {"name": "hidden", "provider": "hidden-provider"})[0]["agent"]["id"]
            assert {agent["id"] for agent in a.call("gent_agents")[0]} == {aid, bid, hid}
            chats = a.call("gent_chats")[0]
            assert {chat["chat_id"] for chat in chats} == {aid, bid, hid}
            identity = a.call("gent_identity")[0]
            assert identity["chat"]["chat_id"] == identity["agent"]["id"] == aid
            for command in ("chats", "agents", "ls", "list"):
                assert {chat["chat_id"] for chat in json.loads(cli(command))} == {aid, bid, hid}
            for command in ("chat", "agent"):
                assert json.loads(cli(command, "show", aid))["chat_id"] == aid
            resolved = a.call("gent_resolve", {"name": "b"})[0]
            assert resolved["selected"]["chat_id"] == bid
            assert set(json.loads(cli("providers"))) == {"agents", "arbitrary-b", "hidden-provider"}
            # Explicit restrictions hide the third agent and keep B reply-only.
            cli("permission", "deny", "*", hid, "--permission", "enumerate")
            cli("permission", "deny", hid, "*", "--permission", "enumerate")
            cli("permission", "deny", bid, aid, "--permission", "send")
            attempt = {"recipient": bid, "request_id": a.request_id(), "text": "review", "files": [{"name": "pixel.png", "media_type": "image/png", "data_base64": PNG}]}
            a.call("gent_send_non_blocking", dict(attempt, recipient=hid), error=True)
            assert {agent["id"] for agent in a.call("gent_agents")[0]} == {aid, bid}
            assert {chat["chat_id"] for chat in a.call("gent_chats")[0]} == {aid, bid}
            a.call("gent_chats", {"credential": "forged"}, error=True)
            attachment_request = {"target": bid, "request_id": a.request_id()}
            attached = a.call("gent_relay_attach", attachment_request)[0]
            attachment_id = attached["attachment"]["id"]
            assert attached["state"] == "attached" and attached["supports_turns"] is True
            assert "grant_id" not in attached["attachment"]
            assert "expires_at" not in attached["attachment"]
            assert a.call("gent_relay_attach", attachment_request)[0] == attached
            outsider.call("gent_relay_status", {"attachment_id": attachment_id}, error=True)
            assert json.loads(cli("relay", "attachments"))[0]["id"] == attachment_id

            def wait_for(check):
                deadline = time.monotonic() + 15
                while not check():
                    assert time.monotonic() < deadline, "relay turn timed out"
                    time.sleep(.05)

            def restart_relay_daemon():
                nonlocal daemon
                daemon.send_signal(signal.SIGINT)
                assert daemon.wait(timeout=5) == 0
                daemon.stderr.close()
                daemon = start_daemon()

            exercise_turns(a, b, attachment_id, attempt["files"], wait_for, restart_relay_daemon)
            a.call("gent_send_non_blocking", dict(attempt, sender=bid), error=True)
            a.call("gent_register", {"name": "a", "provider": "a", "node_id": "forged"}, error=True)
            sent = a.call("gent_send_non_blocking", attempt)[0]
            assert a.call("gent_send_non_blocking", attempt)[0]["duplicate"] is True
            a.call("gent_send_non_blocking", dict(attempt, text="different"), error=True)
            outsider.call("gent_ack", {"message_id": sent["message_id"]}, error=True)
            inbox, raw = b.call("gent_inbox")
            assert len(inbox) == 1 and inbox[0]["id"] == sent["message_id"]
            assert base64.b64decode(inbox[0]["files"][0]["data_base64"]) == base64.b64decode(PNG)
            assert any(part["type"] == "image" and part["data"] == PNG for part in raw["content"])
            b.call("gent_ack", {"message_id": sent["message_id"]})
            assert b.call("gent_inbox")[0] == []
            reply = b.call("gent_reply", {"message_id": sent["message_id"], "request_id": b.request_id(), "text": "make it blue"})[0]
            assert a.call("gent_inbox")[0][0]["id"] == reply["message_id"]
            b.call("gent_send_non_blocking", {"recipient": aid, "request_id": b.request_id(), "text": "unsolicited"}, error=True)

            for client in clients:
                client.close()
            clients.clear()
            daemon.send_signal(signal.SIGINT)
            assert daemon.wait(timeout=5) == 0
            daemon.stderr.close()
            daemon = start_daemon()
            a = connect("a.key")
            assert a.call("gent_identity")[0]["agent"]["id"] == aid
            assert a.call("gent_relay_status")[0]["attachment"]["id"] == attachment_id
            cli("permission", "deny", aid, bid, "--permission", "send")
            assert a.call("gent_relay_status")[0]["state"] == "blocked"
            a.call("gent_relay_detach", {"attachment_id": attachment_id})
            assert a.call("gent_relay_status")[0] is None
            assert a.call("gent_relay_attach", attachment_request)[0]["state"] == "detached"
            assert a.call("gent_inbox")[0][0]["id"] == reply["message_id"]
            # Denial after enqueue takes effect before retrieval.
            cli("permission", "deny", aid, bid, "--permission", "receive")
            assert a.call("gent_inbox")[0] == []
            cli("agent", "revoke", bid)
            b = connect("b.key")
            b.call("gent_register", {"name": "b", "provider": "arbitrary-b"}, error=True)
            assert "hidden-provider" in json.loads(cli("providers", "list"))  # owner view
            # Private credentials never appear in protocol output.
            credential = (home / "bindings" / "a.key").read_text()
            assert credential not in json.dumps(a.call("gent_identity"))
            assert os.stat(home / "bindings" / "a.key").st_mode & 0o077 == 0
            print("PASS: MCP registration, isolation, permissions, replies, image bytes, deduplication, restart recovery, ordered relay turns/cancellation without grants, and restrictions")
        finally:
            for client in clients:
                client.close()
            if daemon is not None and daemon.poll() is None:
                daemon.send_signal(signal.SIGINT)
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()
            if daemon is not None:
                daemon.stderr.close()


if __name__ == "__main__":
    main()
