#!/usr/bin/env python3
"""Exercise the built daemon and MCP server using independent JSON-RPC clients.

Uses a temporary state directory and synthetic messages only. No model calls.
Run: python3 scripts/smoke_mcp.py target/debug/gent
"""
import base64
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import uuid


PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a7q8AAAAASUVORK5CYII="


class Client:
    def __init__(self, command):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.counter = 0
        self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "gent-generic-proof", "version": "1"}})
        self.write({"jsonrpc": "2.0", "method": "notifications/initialized"})
        declared = self.rpc("tools/list", {})["result"]["tools"]
        assert "gent_register" in {tool["name"] for tool in declared}

    def write(self, payload):
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()

    def rpc(self, method, params):
        self.counter += 1
        self.write({"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params})
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if not selector.select(max(0, deadline - time.monotonic())):
                    raise AssertionError("MCP response timed out")
                line = self.process.stdout.readline()
                assert line, "MCP process closed stdout"
                response = json.loads(line)
                if response.get("id") == self.counter:
                    return response
        raise AssertionError("no matching response")

    def call(self, name, arguments=None, error=False):
        response = self.rpc("tools/call", {"name": name, "arguments": arguments or {}})
        if error:
            assert "error" in response or response.get("result", {}).get("isError"), response
            return response
        assert "error" not in response, response
        result = response["result"]
        assert not result.get("isError"), result
        return json.loads(result["content"][0]["text"]), result

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process.stdout.close()
        self.process.stderr.close()


def main():
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/gent").resolve())
    # Short /tmp paths work within macOS's Unix-domain socket path limit.
    with tempfile.TemporaryDirectory(prefix="gent-", dir="/tmp") as directory:
        home = Path(directory) / "state"
        base = [binary, "--home", str(home)]

        def cli(*args):
            return subprocess.run(base + list(args), capture_output=True, text=True, check=True).stdout

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
                    probe = subprocess.run(base + ["daemon", "status"], capture_output=True, text=True)
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
            aid = a.call("gent_register", {"name": "a", "provider": "arbitrary-a"})[0]["agent"]["id"]
            bid = b.call("gent_register", {"name": "b", "provider": "arbitrary-b"})[0]["agent"]["id"]
            outsider.call("gent_register", {"name": "hidden", "provider": "hidden-provider"})
            assert a.call("gent_agents")[0] == []
            attempt = {"recipient": bid, "request_id": str(uuid.uuid4()), "text": "review", "files": [{"name": "pixel.png", "media_type": "image/png", "data_base64": PNG}]}
            a.call("gent_send", attempt, error=True)
            cli("permission", "allow", aid, bid, "--permission", "enumerate", "send")
            cli("permission", "allow", bid, aid, "--permission", "enumerate", "receive")
            assert [agent["id"] for agent in a.call("gent_agents")[0]] == [bid]
            a.call("gent_send", dict(attempt, sender=bid), error=True)
            a.call("gent_register", {"name": "a", "provider": "a", "node_id": "forged"}, error=True)
            sent = a.call("gent_send", attempt)[0]
            assert a.call("gent_send", attempt)[0]["duplicate"] is True
            a.call("gent_send", dict(attempt, text="different"), error=True)
            outsider.call("gent_ack", {"message_id": sent["message_id"]}, error=True)
            inbox, raw = b.call("gent_inbox")
            assert len(inbox) == 1 and inbox[0]["id"] == sent["message_id"]
            assert base64.b64decode(inbox[0]["files"][0]["data_base64"]) == base64.b64decode(PNG)
            assert any(part["type"] == "image" and part["data"] == PNG for part in raw["content"])
            b.call("gent_ack", {"message_id": sent["message_id"]})
            assert b.call("gent_inbox")[0] == []
            reply = b.call("gent_reply", {"message_id": sent["message_id"], "request_id": str(uuid.uuid4()), "text": "make it blue"})[0]
            assert a.call("gent_inbox")[0][0]["id"] == reply["message_id"]
            b.call("gent_send", {"recipient": aid, "request_id": str(uuid.uuid4()), "text": "unsolicited"}, error=True)

            for client in clients:
                client.close()
            clients.clear()
            daemon.send_signal(signal.SIGINT)
            assert daemon.wait(timeout=5) == 0
            daemon.stderr.close()
            daemon = start_daemon()
            a = connect("a.key")
            assert a.call("gent_identity")[0]["agent"]["id"] == aid
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
            print("PASS: MCP registration, isolation, permissions, replies, image bytes, deduplication, restart recovery, and revocation")
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
