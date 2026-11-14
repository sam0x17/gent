#!/usr/bin/env python3
"""Opt-in real-model proof of HTTP conversation metadata with installed hosts.

Codex registers, resumes after daemon/gateway restart, and forks without sharing
an agent. Claude Code's missing conversation ID must fail without creating an
agent. Uses normal model access with other tools disabled. Provider-owned test
sessions remain; private Gent state/configs/transcripts are removed on exit.
The loopback observer forwards unchanged JSON and never logs bearer headers.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gent", type=Path, required=True)
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--claude", default="claude")
    args = parser.parse_args()
    binary = str(args.gent.resolve())
    codex, claude = shutil.which(args.codex), shutil.which(args.claude)
    assert codex and claude, "both installed clients are required"
    os.umask(0o077)
    processes = []
    calls = []
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    with tempfile.TemporaryDirectory(prefix="gent-http-hosts-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        node, work = root / "node", root / "work"
        work.mkdir()
        backend = free_port()
        tokens = {}

        def cli(*arguments):
            result = subprocess.run([binary, "--home", str(node), "--json", *arguments],
                                    capture_output=True, text=True, timeout=20)
            assert result.returncode == 0, result.stderr
            return json.loads(result.stdout)

        class Observer(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_arguments):
                pass

            def do_GET(self):
                self.send_error(405)

            def do_DELETE(self):
                self.send_error(405)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                assert length <= 1024 * 1024
                body = self.rfile.read(length)
                rpc = json.loads(body)
                headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in ("host", "content-length", "connection")}
                request = urllib.request.Request(f"http://127.0.0.1:{backend}/mcp", body, headers)
                try:
                    response = opener.open(request, timeout=30)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    data = response.read()
                    if rpc.get("method") == "tools/call":
                        calls.append({"params": rpc["params"], "response": json.loads(data)})
                    self.send_response(response.status)
                    for key, value in response.headers.items():
                        if key.lower() not in ("content-length", "transfer-encoding", "connection"):
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

        observer = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Observer)
        thread = threading.Thread(target=observer.serve_forever, daemon=True)
        thread.start()
        endpoint = f"http://127.0.0.1:{observer.server_port}/mcp"

        def start(*arguments):
            with (root / f"gent-{len(processes)}.log").open("wb") as log:
                process = subprocess.Popen([binary, "--home", str(node), *arguments],
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            processes.append(process)
            return process

        def ready():
            for _ in range(200):
                assert all(p.poll() is None for p in (daemon, gateway))
                try:
                    with opener.open(f"http://127.0.0.1:{backend}/.well-known/oauth-authorization-server", timeout=2):
                        if (node / "daemon.sock").exists():
                            return
                except urllib.error.URLError:
                    pass
                time.sleep(0.05)
            raise AssertionError("Gent startup timed out")

        def stop(process):
            process.terminate()
            assert process.wait(timeout=15) == 0

        def turn(host, label, session=None, fork=False):
            if host == "codex":
                command = [codex, "exec", "--json", "--skip-git-repo-check", "--sandbox", "read-only",
                           "-C", str(work), "--disable", "shell_tool", "--disable", "multi_agent",
                           "--disable", "apps", "-c", 'approval_policy="never"',
                           "-c", 'web_search="disabled"', "-c", 'model_reasoning_effort="low"']
                config_dir = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
                config = tomllib.loads((config_dir / "config.toml").read_text())
                assert "gent_http_proof" not in config.get("mcp_servers", {}), "reserved proof server name is already configured"
                for table in ("mcp_servers", "plugins"):
                    for name in config.get(table, {}):
                        command += ["-c", f"{table}.{json.dumps(name)}.enabled=false"]
                command += ["-c", f"mcp_servers.gent_http_proof.url={json.dumps(endpoint)}",
                            "-c", 'mcp_servers.gent_http_proof.bearer_token_env_var="GENT_HTTP_PROOF_TOKEN"',
                            "-c", "mcp_servers.gent_http_proof.enabled=true",
                            "-c", "mcp_servers.gent_http_proof.required=true",
                            "-c", 'mcp_servers.gent_http_proof.default_tools_approval_mode="approve"']
                if session:
                    command += ["fork" if fork else "resume", session]
                command += ["-"]
                env = dict(os.environ, GENT_HTTP_PROOF_TOKEN=tokens[host])
            else:
                config_file = root / "claude-mcp.json"
                config_file.write_text(json.dumps({"mcpServers": {"gent": {
                    "type": "http", "url": endpoint, "headers": {"Authorization": "Bearer " + tokens[host]}}}}))
                command = [claude, "-p", "--output-format", "stream-json", "--verbose", "--setting-sources", "",
                           "--strict-mcp-config", "--tools", "", "--disable-slash-commands", "--no-chrome",
                           "--permission-mode", "dontAsk", "--allowedTools", "mcp__gent__*", "--max-budget-usd", "1",
                           "--settings", '{"disableAllHooks":true}', "--mcp-config", str(config_file)]
                env = os.environ
            prompt = (f"This is an isolated Gent compatibility test. Call gent_register with name http-proof and provider {host}. "
                      "Then call gent_identity twice, even if the server returns an error. "
                      "Do not call other tools or repair anything. Report completion briefly.")
            before = len(calls)
            with (root / (label + ".jsonl")).open("w") as out, (root / (label + ".stderr")).open("w") as err:
                result = subprocess.run(command, input=prompt, text=True, cwd=work, env=env,
                                        stdout=out, stderr=err, timeout=180)
            assert result.returncode == 0, f"{label}: host failed"
            events = [json.loads(line) for line in (root / (label + ".jsonl")).read_text().splitlines() if line.strip()]
            reported = next((e["thread_id"] for e in events if e.get("type") == "thread.started"), None) if host == "codex" else next(
                (e["session_id"] for e in events if e.get("type") == "system" and e.get("subtype") == "init"), None)
            assert reported, "host did not report a conversation ID"
            observed = calls[before:]
            assert {c["params"]["name"] for c in observed} == {"gent_register", "gent_identity"}
            assert sum(c["params"]["name"] == "gent_identity" for c in observed) >= 2
            return reported, observed

        def identities(observed, conversation):
            ids = set()
            for call in observed:
                assert call["params"]["_meta"]["threadId"] == conversation
                result = call["response"]["result"]
                assert not result.get("isError"), "Codex call was rejected"
                value = json.loads(result["content"][0]["text"])
                ids.add(value["agent"]["id"])
            assert len(ids) == 1, "one conversation created multiple agents"
            return ids.pop()

        try:
            cli("cluster", "new", "http-hosts", "--local")
            for host, key in (("codex", "threadId"), ("claude", "test/missing-conversation")):
                export = root / (host + ".json")
                cli("gateway", "clients", "add", host, "--conversation-key", key, "--out", str(export))
                tokens[host] = json.loads(export.read_text())["token"]
            daemon = start("daemon", "run")
            gateway = start("gateway", "run", "--listen", f"127.0.0.1:{backend}")
            ready()
            conversation, initial = turn("codex", "initial")
            first = identities(initial, conversation)
            stop(gateway)
            stop(daemon)
            daemon = start("daemon", "run")
            gateway = start("gateway", "run", "--listen", f"127.0.0.1:{backend}")
            ready()
            resumed, observed = turn("codex", "resume", conversation)
            assert resumed == conversation and identities(observed, resumed) == first
            fork, forked = turn("codex", "fork", conversation, fork=True)
            assert fork != conversation and identities(forked, fork) != first
            shared_session = initial[0]["params"]["_meta"].get("sessionId") == forked[0]["params"]["_meta"].get("sessionId")
            _, observed = turn("claude", "claude")
            call_ids = set()
            for call in observed:
                meta = call["params"]["_meta"]
                assert "threadId" not in meta
                call_ids.add(meta["claudecode/toolUseId"])
                result = call["response"]["result"]
                assert result.get("isError") and "conversation binding unavailable" in result["content"][0]["text"]
            assert len(call_ids) == len(observed), "Claude tool-use ID unexpectedly stable"
            listing = {c["name"]: c for c in cli("gateway", "clients", "list")["clients"]}
            assert listing["codex"]["conversations"] == 2 and listing["claude"]["conversations"] == 0
            print(json.dumps({"status": "passed", "proof": "installed-host-http-metadata", "clients": {
                "codex": {"version": subprocess.check_output([codex, "--version"], text=True).strip(),
                          "checks": ["per-call thread identity", "restart and resume", "fork isolation"],
                          "fork_shares_session_id": shared_session},
                "claude": {"version": subprocess.check_output([claude, "--version"], text=True).strip(),
                           "checks": ["tool-use ID changes per call", "missing conversation rejected", "no agents created"]}},
                "model_turns": 4}))
        finally:
            observer.shutdown()
            observer.server_close()
            thread.join(timeout=5)
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    main()
