#!/usr/bin/env python3
"""Opt-in OAuth proof with installed Codex and Claude Code.

Uses a temporary Codex profile and a unique entry in its file OAuth store,
removed through `mcp logout` on exit. Claude uses an isolated configuration
directory and file storage (Keychain access is disabled for this subprocess).
No existing provider settings are edited. Secrets never enter command arguments.
--exercise-models uses normal model access for token-renewal and reconnect tests.
"""
import argparse
import json
import os
from pathlib import Path
import pty
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gent", type=Path, required=True)
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--claude", default="claude")
    parser.add_argument("--exercise-models", action="store_true")
    args = parser.parse_args()
    binary = str(args.gent.resolve())
    codex = shutil.which(args.codex)
    claude = shutil.which(args.claude)
    assert codex and claude, "both installed clients are required"
    os.umask(0o077)
    processes = []
    terminals = []
    profile = None
    logout = None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    with tempfile.TemporaryDirectory(prefix="gent-clients-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        gent_dir = root / "node"
        work = root / "work"
        work.mkdir()
        private = []
        daemon_logs = []

        def cli(*arguments):
            result = subprocess.run([binary, "--home", str(gent_dir), "--json", *arguments],
                                    capture_output=True, text=True, timeout=20)
            assert result.returncode == 0, "Gent CLI failed: " + result.stderr
            return json.loads(result.stdout)

        def start(arguments, label, env=None, terminal=False):
            path = root / (label + ".log")
            if terminal:
                master, slave = pty.openpty()
                process = subprocess.Popen(arguments, stdin=slave, stdout=slave, stderr=slave,
                                           cwd=work, env=env, start_new_session=True)
                os.close(slave)

                def pump():
                    with path.open("wb") as log:
                        while True:
                            try:
                                chunk = os.read(master, 65536)
                            except OSError:
                                break
                            if not chunk:
                                break
                            log.write(chunk)
                            log.flush()
                            if b"\x1b[6n" in chunk:
                                os.write(master, b"\x1b[1;1R")

                thread = threading.Thread(target=pump, daemon=True)
                thread.start()
                terminals.append((master, thread))
                processes.append(process)
                return process, path
            with path.open("wb") as log:
                process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=log, stderr=log,
                                           cwd=work, env=env)
            processes.append(process)
            return process, path

        def http(url, status=200):
            try:
                response = opener.open(url, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                assert response.status == status, f"unexpected HTTP status {response.status}"
                return response.headers, response.read().decode()

        def wait_for(check, timeout=30):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                value = check()
                if value:
                    return value
                time.sleep(0.05)
            raise AssertionError("client proof timed out")

        def login(command, label, client, callback, env=None):
            process, path = start(command, label, env, terminal=env is not None)

            def authorization_url():
                assert process.poll() is None, f"{label} exited before authorization"
                match = re.search(re.escape(origin) + r"/oauth/authorize\?[^\x00-\x20\x7f\[\]<>()]+", path.read_text() if path.exists() else "")
                return match.group() if match else None

            url = wait_for(authorization_url)
            fields = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            assert fields["client_id"] == [client]
            assert fields["redirect_uri"] == [callback]
            assert fields["resource"] == [resource], (fields["resource"], resource)
            assert fields["code_challenge_method"] == ["S256"]
            assert fields["scope"] == ["gent:agents"]
            assert fields.get("state") and fields.get("code_challenge")
            private.extend(fields["state"])
            http(url)
            pending = [r for r in cli("gateway", "oauth", "requests")["requests"]
                       if r["client"] == client and r["decision"] is None]
            assert len(pending) == 1
            request_id = pending[0]["request"]
            assert pending[0]["redirect_uri"] == callback
            http(origin + "/oauth/continue?request=" + request_id)
            cli("gateway", "oauth", "approve", request_id)
            headers, _ = http(origin + "/oauth/continue?request=" + request_id, 303)
            location = headers["Location"]
            values = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
            assert values["state"] == fields["state"] and values["iss"] == [origin]
            private.extend(values["code"])
            if env is not None:
                os.write(terminals[-1][0], (location + "\r").encode())
            else:
                process.stdin.write((location + "\n").encode())
                process.stdin.flush()
            result = process.wait(timeout=30)
            assert result == 0, f"{label} failed with exit code {result}; private client output omitted"
            state = json.loads((gent_dir / "gateway/state.json").read_text())
            grants = [g for g in state["oauth"]["grants"].values() if g["client"] == client]
            assert len(grants) == 1, "client did not exchange its code"
            return {"authorization": "S256 with exact resource, callback, scope and state",
                    "consent": "local owner approval", "token_exchange": "accepted"}

        try:
            cli("cluster", "new", "native-clients", "--local")
            port = free_port()
            origin = f"http://127.0.0.1:{port}"
            resource = origin + "/mcp"
            clients = {}
            for host in ("codex", "claude"):
                callback = f"http://{'127.0.0.1' if host == 'codex' else 'localhost'}:{free_port()}/callback"
                export = root / (host + ".json")
                cli("gateway", "clients", "add", host, "--conversation-key", "threadId" if host == "codex" else "test/conversation",
                    "--out", str(export), "--oauth-resource", resource, "--redirect-uri", callback)
                registration = json.loads(export.read_text())
                private.append(registration["token"])
                clients[host] = (registration, callback)
            daemon, path = start([binary, "--home", str(gent_dir), "daemon", "run"], "daemon")
            daemon_logs.append(path)
            wait_for(lambda: (gent_dir / "daemon.sock").exists())
            gateway, path = start([binary, "--home", str(gent_dir), "gateway", "run",
                                   "--listen", f"127.0.0.1:{port}"], "gateway")
            daemon_logs.append(path)

            def ready():
                assert gateway.poll() is None
                try:
                    http(origin + "/.well-known/oauth-authorization-server")
                    return True
                except urllib.error.URLError:
                    return False

            wait_for(ready)

            def restart_gateway(edit):
                nonlocal gateway
                gateway.terminate()
                assert gateway.wait(timeout=15) == 0
                edit()
                gateway, path = start([binary, "--home", str(gent_dir), "gateway", "run",
                                       "--listen", f"127.0.0.1:{port}"], f"gateway-{len(processes)}")
                daemon_logs.append(path)
                wait_for(ready)
            config_dir = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
            assert config_dir.is_dir(), "use an installed Codex configuration directory"
            name = "gent-proof-" + uuid.uuid4().hex
            profile = config_dir / (name + ".config.toml")
            registration, callback = clients["codex"]
            with profile.open("x") as file:
                file.write(f'mcp_oauth_credentials_store = "file"\n[mcp_servers.{name}]\n'
                           f'url = {json.dumps(resource)}\n'
                           f'[mcp_servers.{name}.oauth]\nclient_id = {json.dumps(registration["client"])}\n'
                           f'client_secret = {json.dumps(registration["token"])}\n'
                           f'callback_url = {json.dumps(callback)}\n')
            logout = [codex, "--profile", name, "mcp", "logout", name]
            results = {}
            results["codex"] = login([codex, "--profile", name, "mcp", "login", name, "--no-browser"],
                                     "codex-login", registration["client"], callback)
            if args.exercise_models:
                from gateway_client_lifecycle import exercise
                results["codex"]["lifecycle"] = exercise("codex", codex, name, root, work, gent_dir, resource,
                    registration, urllib.parse.urlsplit(callback).port, os.environ, restart_gateway, cli)
            claude_dir = root / "claude"
            claude_dir.mkdir()
            shim_dir = root / "bin"
            shim_dir.mkdir()
            # Simulate a missing item (44), not a failed/locked Keychain read.
            # Writes fail, selecting file fallback without touching the real Keychain.
            security = shim_dir / "security"
            security.write_text("#!/bin/sh\ncase \"$1\" in\nfind-generic-password) exit 44 ;;\n*) exit 1 ;;\nesac\n")
            security.chmod(0o700)
            env = dict(os.environ, CLAUDE_CONFIG_DIR=str(claude_dir),
                       CLAUDE_SECURESTORAGE_CONFIG_DIR=str(claude_dir),
                       PATH=str(shim_dir) + os.pathsep + os.environ["PATH"])
            registration, callback = clients["claude"]
            add = subprocess.run([claude, "mcp", "add", "--transport", "http", "--scope", "user",
                                  "--client-id", registration["client"], "--client-secret",
                                  "--callback-port", str(urllib.parse.urlsplit(callback).port), name, resource],
                                 env=dict(env, MCP_CLIENT_SECRET=registration["token"]), cwd=work,
                                 capture_output=True, text=True, timeout=30)
            assert add.returncode == 0, "Claude client setup failed"
            stored = claude_dir / ".credentials.json"
            assert stored.exists() and registration["token"] in stored.read_text(), "Claude did not persist the client secret in the isolated file store"
            results["claude"] = login([claude, "mcp", "login", name, "--no-browser"],
                                      "claude-login", registration["client"], callback, env)
            if args.exercise_models:
                results["claude"]["lifecycle"] = exercise("claude", claude, name, root, work, gent_dir, resource,
                    registration, urllib.parse.urlsplit(callback).port, env, restart_gateway, cli)
            for host, (registration, _) in clients.items():
                cli("gateway", "clients", "revoke", registration["client"])
                results[host]["version"] = subprocess.check_output(
                    [codex if host == "codex" else claude, "--version"], text=True).strip()
            for path in daemon_logs:
                assert not any(value in path.read_text() for value in private)
            removed = subprocess.run(logout, capture_output=True, timeout=20)
            assert removed.returncode == 0, "Codex proof credential cleanup failed"
            logout = None
            credentials = config_dir / ".credentials.json"
            if credentials.exists():
                assert name not in credentials.read_text(), "Codex proof credential remains"
            print(json.dumps({"status": "passed", "proof": "installed-client-oauth", "clients": results,
                              "credential_cleanup": "passed", "model_turns": 6 if args.exercise_models else 0}))
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                if process.stdin:
                    process.stdin.close()
            for descriptor, thread in terminals:
                thread.join(timeout=2)
                os.close(descriptor)
            if logout:
                cleanup = subprocess.run(logout, capture_output=True, timeout=20)
                assert cleanup.returncode == 0, "Codex proof credential cleanup failed"
            if profile:
                profile.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
