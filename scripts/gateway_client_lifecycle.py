"""Opt-in native OAuth model lifecycle, used by prove_gateway_clients.py.

Expires only the synthetic grant's server-side access token while the gateway is
stopped. This exercises the client's HTTP 401 recovery with a still-live refresh
grant; it does not simulate the client's proactive expiry timer or edit its store.
The concurrent option launches two chats together with one shared OAuth entry;
it checks overlapping client runs, without forcing an HTTP-level race.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import tomllib


def exercise(host, executable, name, root, work, gent_dir, resource, registration,
             callback, env, restart_gateway, cli, conversations=1):
    assert conversations in (1, 2)
    directories = [work / f"{host}-{index}" for index in range(conversations)]
    for directory in directories:
        directory.mkdir()

    def grants():
        state = json.loads((gent_dir / "gateway/state.json").read_text())
        return {key: value for key, value in state["oauth"]["grants"].items()
                if value["client"] == registration["client"]}

    original = grants()
    assert len(original) == 1
    family_id, initial = next(iter(original.items()))

    def turn(label, index, session, barrier):
        directory = directories[index]
        if host == "codex":
            command = [executable, "--profile", name, "exec", "--json", "--skip-git-repo-check",
                       "--sandbox", "read-only", "-C", str(directory), "--disable", "shell_tool",
                       "--disable", "multi_agent", "--disable", "apps", "-c", 'approval_policy="never"',
                       "-c", 'web_search="disabled"', "-c", 'model_reasoning_effort="low"']
            config_dir = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
            config = tomllib.loads((config_dir / "config.toml").read_text())
            for table in ("mcp_servers", "plugins"):
                for other in config.get(table, {}):
                    command += ["-c", f"{table}.{json.dumps(other)}.enabled=false"]
            command += ["-c", f"mcp_servers.{name}.enabled=true", "-c", f"mcp_servers.{name}.required=true",
                        "-c", f'mcp_servers.{name}.default_tools_approval_mode="approve"']
            if session:
                command += ["resume", session]
            command += ["-"]
        else:
            path = root / f"claude-lifecycle-{index}.json"
            path.write_text(json.dumps({"mcpServers": {name: {"type": "http", "url": resource,
                "oauth": {"clientId": registration["client"], "callbackPort": callback}}}}))
            command = [executable, "-p", "--output-format", "stream-json", "--verbose", "--setting-sources", "",
                       "--strict-mcp-config", "--tools", "", "--disable-slash-commands", "--no-chrome",
                       "--permission-mode", "dontAsk", "--allowedTools", f"mcp__{name}__*", "--max-budget-usd", "1",
                       "--settings", '{"disableAllHooks":true}', "--mcp-config", str(path)]
            if session:
                command += ["--resume", session]
        prompt = (f"This is an isolated Gent OAuth compatibility test. Call gent_register with name oauth-proof "
                  f"and provider {host}, then call gent_identity. Call both even if either returns an error. "
                  "Do not use other tools or repair anything. Report completion briefly.")
        output, errors = root / f"{host}-{label}-{index}.jsonl", root / f"{host}-{label}-{index}.stderr"
        with output.open("w") as out, errors.open("w") as err:
            barrier.wait(timeout=30)
            started = time.monotonic()
            completed = subprocess.run(command, input=prompt, text=True, cwd=directory, env=env,
                                       stdout=out, stderr=err, timeout=180)
            ended = time.monotonic()
        assert completed.returncode == 0, f"{host} {label} failed; private model output omitted"
        events = [json.loads(line) for line in output.read_text().splitlines() if line.strip()]
        reported = None
        responses = []
        tools = {}
        for event in events:
            if host == "codex":
                if event.get("type") == "thread.started":
                    reported = event["thread_id"]
                item = event.get("item", {})
                if event.get("type") == "item.completed" and item.get("type") == "mcp_tool_call":
                    assert item.get("status") == "completed" and not item.get("error"), "OAuth MCP call failed"
                    assert item["server"] == name
                    responses.append((item["tool"], item["result"]))
            else:
                if event.get("type") == "system" and event.get("subtype") == "init":
                    reported = event["session_id"]
                for block in event.get("message", {}).get("content", []):
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_use":
                        tools[block["id"]] = block["name"].removeprefix(f"mcp__{name}__")
                    if block.get("type") == "tool_result" and block["tool_use_id"] in tools:
                        content = block["content"]
                        if isinstance(content, str):
                            content = [{"type": "text", "text": content}]
                        responses.append((tools[block["tool_use_id"]], {"isError": block.get("is_error", False), "content": content}))
        assert reported and (not session or reported == session), "unexpected conversation identity"
        assert {tool for tool, _ in responses} == {"gent_register", "gent_identity"}, "missing actual tool results"
        if host == "codex":
            identities = set()
            for _, result in responses:
                assert not result.get("isError"), "OAuth model tool was rejected"
                identities.add(json.loads(result["content"][0]["text"])["agent"]["id"])
            assert len(identities) == 1
            return reported, identities.pop(), started, ended
        for _, result in responses:
            assert result.get("isError") and "conversation binding unavailable" in result["content"][0]["text"], "Claude missing identity did not fail closed"
        return reported, None, started, ended

    def turns(label, sessions=None):
        sessions = sessions or [None] * conversations
        barrier = threading.Barrier(conversations)
        with ThreadPoolExecutor(max_workers=conversations) as pool:
            jobs = [pool.submit(turn, label, index, session, barrier)
                    for index, session in enumerate(sessions)]
            results = [job.result() for job in jobs]
        assert max(row[2] for row in results) < min(row[3] for row in results), "client runs did not overlap"
        identities = {row[0]: row[1] for row in results}
        assert len(identities) == conversations, "separate chats shared a conversation"
        if host == "codex":
            assert len(set(identities.values())) == conversations, "separate chats shared a Gent agent"
        return identities

    identities = turns("initial")
    initial = grants()[family_id]

    def expire():
        path = gent_dir / "gateway/state.json"
        state = json.loads(path.read_text())
        grant = state["oauth"]["grants"][family_id]
        assert not grant["revoked"] and grant["expires_at"] > int(time.time()) + 60
        grant["access_expires_at"] = int(time.time()) - 1
        temporary = path.with_name("lifecycle.tmp")
        with temporary.open("x") as file:
            json.dump(state, file)
        os.replace(temporary, path)

    restart_gateway(expire)
    restored = turns("renewed", list(identities))
    current = grants()
    assert set(current) == {family_id}, "client reauthorized instead of refreshing its grant"
    current = current[family_id]
    assert current["refresh_generation"] > initial["refresh_generation"] and not current["revoked"], "client did not refresh"
    assert current["access_hash"] != initial["access_hash"] and current["access_expires_at"] > int(time.time())
    assert current["expires_at"] == initial["expires_at"], "refresh extended the authorization lifetime"
    assert restored == identities
    restart_gateway(lambda: None)
    assert turns("reconnected", list(identities)) == identities
    clients = cli("gateway", "clients", "list")["clients"]
    client = next(c for c in clients if c["id"] == registration["client"])
    assert client["conversations"] == (conversations if host == "codex" else 0)
    return {"checks": ["OAuth-authenticated tools", "server access expiry", "client-driven refresh",
                       "unchanged grant lifetime", "restart and resume"],
            "agent_binding": "stable" if host == "codex" else "missing conversation rejected",
            "concurrent_chats": conversations,
            "refresh_rotations": current["refresh_generation"] - initial["refresh_generation"],
            "model_turns": 3 * conversations}
