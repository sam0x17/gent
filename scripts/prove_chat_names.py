#!/usr/bin/env python3
"""Check default chat names through real MCP processes; optional native Codex.

Native Codex needs the websockets Python package. No model turns are submitted.
All daemon, host and conversation state is disposable.
"""

import argparse
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from mcp_client import Client


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_socket(path, process):
    deadline = time.monotonic() + 15
    while not path.exists():
        assert process.poll() is None and time.monotonic() < deadline
        time.sleep(0.05)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gent", type=Path, required=True)
    parser.add_argument("--codex", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="gent-names-", dir="/tmp") as folder:
        root = Path(folder).resolve()
        home = root / "node"
        base = [str(args.gent.resolve()), "--home", str(home)]
        clients = []
        daemon = native = None
        checks = []

        def cli(*argv, **kwargs):
            return subprocess.run(
                base + list(argv),
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
                **kwargs,
            )

        def connect(*argv, host="gent-generic-proof"):
            connection = Client(base + ["mcp", "serve", *argv], client_name=host)
            clients.append(connection)
            return connection

        def start_daemon():
            process = subprocess.Popen(
                base + ["daemon", "run"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wait_socket(home / "daemon.sock", process)
            return process

        with (root / "native.log").open("w") as log:
            try:
                cli("cluster", "new", "names-proof", "--local")
                daemon = start_daemon()
                binding = str(root / "generic.key")
                generic = connect("--binding", binding)
                initial = generic.call("gent_register", {"provider": "generic"})[0]
                assert initial["agent"]["name"].startswith("agent-")
                generic.close()
                stop(daemon)
                daemon = start_daemon()
                generic = connect("--binding", binding)
                resumed = generic.call("gent_register", {"provider": "generic"})[0]
                assert resumed["agent"]["id"] == initial["agent"]["id"]
                assert resumed["agent"]["name"] == initial["agent"]["name"]
                generic.call(
                    "gent_rename", {"name": "chosen alias", "expected_generation": 1}
                )
                assert (
                    generic.call("gent_register", {"provider": "generic"})[0]["agent"][
                        "name"
                    ]
                    == "chosen alias"
                )
                generic.call(
                    "gent_register", {"provider": "generic", "name": ""}, error=True
                )
                checks.append(
                    "stable fallback and explicit rename survive reconnect and restart"
                )

                claude = connect("--host", "claude-code", host="claude-code")
                session = str(uuid.uuid4())
                transcript = root / f"{session}.jsonl"
                transcript.write_text(
                    json.dumps(
                        {
                            "type": "custom-title",
                            "sessionId": session,
                            "customTitle": "cit-claude",
                        }
                    )
                    + "\n"
                )

                def claude_register(arguments, child=None):
                    tool_use = str(uuid.uuid4())
                    event = {
                        "hook_event_name": "PreToolUse",
                        "session_id": session,
                        "transcript_path": str(transcript),
                        "tool_use_id": tool_use,
                        "tool_name": "mcp__gent__gent_register",
                        "tool_input": arguments,
                    }
                    if child:
                        event["agent_id"] = child
                    cli("integration", "hook", "claude-code", input=json.dumps(event))
                    return claude.call(
                        "gent_register",
                        arguments,
                        meta={"claudecode/toolUseId": tool_use},
                    )[0]

                first = claude_register({"provider": "claude-code"})
                assert first["agent"]["name"] == "cit-claude"
                child = claude_register({"provider": "claude-code"}, "child")
                assert child["agent"]["id"] != first["agent"]["id"]
                assert child["agent"]["name"].startswith("claude-code-")
                alias = claude_register(
                    {"provider": "claude-code", "name": "explicit child"},
                    "second-child",
                )
                assert alias["agent"]["name"] == "explicit child"
                transcript.write_text(
                    json.dumps(
                        {
                            "type": "custom-title",
                            "sessionId": session,
                            "customTitle": "changed host title",
                        }
                    )
                    + "\n"
                )
                assert (
                    claude_register({"provider": "claude-code"})["agent"]["name"]
                    == "cit-claude"
                )
                checks.append(
                    "Claude hook title, subagent isolation and explicit aliases"
                )

                if args.codex:
                    from websockets.sync.client import unix_connect

                    codex_home = root / "codex"
                    codex_home.mkdir()
                    socket = root / "native.sock"
                    native = subprocess.Popen(
                        [
                            str(args.codex.resolve()),
                            "app-server",
                            "--listen",
                            f"unix://{socket}",
                        ],
                        env=dict(os.environ, CODEX_HOME=str(codex_home)),
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=log,
                    )
                    wait_socket(socket, native)
                    with unix_connect(str(socket), max_size=1024 * 1024) as ws:
                        counter = 0

                        def rpc(method, params):
                            nonlocal counter
                            counter += 1
                            ws.send(
                                json.dumps(
                                    {"id": counter, "method": method, "params": params}
                                )
                            )
                            while True:
                                response = json.loads(ws.recv(timeout=15))
                                if response.get("id") == counter:
                                    assert "error" not in response, response
                                    return response["result"]

                        rpc(
                            "initialize",
                            {
                                "clientInfo": {
                                    "name": "gent-names-proof",
                                    "version": "1",
                                },
                                "capabilities": {"experimentalApi": True},
                            },
                        )
                        ws.send(json.dumps({"method": "initialized"}))
                        thread = rpc(
                            "thread/start", {"cwd": str(root), "ephemeral": False}
                        )["thread"]["id"]
                        rpc("thread/name/set", {"threadId": thread, "name": "cit"})
                        assert (
                            rpc(
                                "thread/read",
                                {"threadId": thread, "includeTurns": False},
                            )["thread"]["name"]
                            == "cit"
                        )
                        codex = connect(
                            "--host",
                            "codex",
                            "--wake-socket",
                            str(socket),
                            host="codex-mcp-client",
                        )
                        registered = codex.call(
                            "gent_register",
                            {"provider": "codex"},
                            meta={"threadId": thread},
                        )[0]
                        assert registered["agent"]["name"] == "cit", registered
                        visible = generic.call("gent_agents")[0]
                        assert any(
                            a["id"] == registered["agent"]["id"] and a["name"] == "cit"
                            for a in visible
                        )
                        codex.call(
                            "gent_rename",
                            {"name": "cit alias", "expected_generation": 1},
                            meta={"threadId": thread},
                        )
                        rpc(
                            "thread/name/set",
                            {"threadId": thread, "name": "changed title"},
                        )
                        codex.close()
                        codex = connect(
                            "--host",
                            "codex",
                            "--wake-socket",
                            str(socket),
                            host="codex-mcp-client",
                        )
                        restored = codex.call(
                            "gent_register",
                            {"provider": "codex"},
                            meta={"threadId": thread},
                        )[0]
                        assert restored["agent"]["id"] == registered["agent"]["id"]
                        assert restored["agent"]["name"] == "cit alias"
                    checks.append(
                        "native Codex title becomes discoverable; alias survives host rename and reconnect"
                    )
                print(
                    json.dumps(
                        {
                            "passed": True,
                            "platform": os.uname().sysname,
                            "checks": checks,
                        }
                    )
                )
            finally:
                for connection in clients:
                    connection.close()
                stop(native)
                stop(daemon)


if __name__ == "__main__":
    main()
