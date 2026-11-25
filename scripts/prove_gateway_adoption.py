#!/usr/bin/env python3
"""Exercise a disposable native gateway service using three separately built binaries.

Requires a user service manager and Python websockets >= 14. Uses a loopback
bridge, synthetic credentials and its own cluster, installation and service label.
"""
import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid

from websockets.exceptions import ConnectionClosed
from websockets.sync.server import serve


def wait(description, check, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if result := check():
            return result
        time.sleep(.2)
    raise RuntimeError(f"timed out waiting for {description}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("legacy", "candidate", "baseline"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    issuers = []
    bridge_online = threading.Event()

    def bridge(ws):
        if issuers and not bridge_online.is_set():
            return
        request_id = str(uuid.uuid4())
        try:
            ws.send(json.dumps(dict(kind="ready", version=1)))
            ws.send(json.dumps(dict(kind="request", id=request_id, method="GET",
                                    path="/.well-known/oauth-authorization-server",
                                    headers=[], body_base64="")))
            for frame in ws:
                if frame == "gent-mcp-ping-v1":
                    ws.send("gent-mcp-pong-v1")
                else:
                    msg = json.loads(frame)
                    if msg["kind"] == "response" and msg["id"] == request_id:
                        assert msg["status"] == 200
                        issuers.append(json.loads(base64.b64decode(msg["body_base64"]))["issuer"])
                        if not bridge_online.is_set():
                            return
        except ConnectionClosed:
            pass

    with (tempfile.TemporaryDirectory(prefix="gent-adopt-", dir="/tmp") as scratch,
          serve(bridge, "127.0.0.1", 0) as server, socket.socket() as relay):
        relay.bind(("127.0.0.1", 0))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.socket.getsockname()[1]}"
        root = Path(scratch)
        home = root / "node"
        cargo = root / "cargo"
        binary = cargo / "bin/gent"
        binary.parent.mkdir(parents=True)
        env = dict(os.environ, CARGO_HOME=str(cargo), GIT_TERMINAL_PROMPT="0")
        # The synthetic cluster does not perform release discovery.
        def publish(source):
            stage = binary.with_suffix(".new")
            shutil.copy2(source, stage)
            stage.replace(binary)

        def call(*words, reader=None, allowed=(0,)):
            result = subprocess.run([reader or binary, "--home", home, "--json", *words],
                                    capture_output=True, timeout=60, env=env)
            if result.returncode not in allowed:
                raise RuntimeError(f"{words[:3]} exited {result.returncode}")
            return json.loads(result.stdout) if result.stdout else {}

        def status():
            return call("gateway", "service", "status", reader=args.candidate, allowed=(0, 3))

        processes = []
        def spawn(*words):
            proc = subprocess.Popen([binary, "--home", home, *words], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(proc)
            return proc

        def activate():
            proc = spawn("daemon", "run")
            wait("authenticated daemon readiness", lambda: call(
                "daemon", "status", reader=args.candidate, allowed=(0, 3))["daemon"]["pid"] == proc.pid)
            return proc

        def stop(proc):
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=45)

        installed = False
        try:
            publish(args.legacy)
            call("cluster", "new", "adoption", "--local")
            call("update", "disable")
            export = root / "fixture.json"
            call("gateway", "clients", "add", "synthetic-host", "--conversation-key", "fixture/chat", "--out", str(export))
            original_export = export.read_bytes()
            (home / "relay.key").write_text(f"gent_t1.{int(time.time())}.{secrets.token_hex(32)}")
            with (home / "config.toml").open("a") as cfg:
                cfg.write(f'\n[relay]\nendpoint="http://127.0.0.1:{relay.getsockname()[1]}"\ncredential_file="relay.key"\n')
            installed = True
            first = call("gateway", "service", "install", "--hosted", origin)
            pid = first["gateway"]["pid"]
            unit_file = Path(first["service"]["file"])
            definition = unit_file.read_bytes()
            wait("legacy issuer", lambda: len(issuers) == 1)
            wait("legacy bridge disconnect", lambda: status().get("connected") is False)
            publish(args.candidate)
            daemon = activate()
            commit = call("version")["commit"]
            upgraded = wait("new gateway", lambda: (s if (s := status()).get("build", {}).get("commit") == commit else None))
            assert upgraded["gateway"]["managed"] and upgraded["gateway"]["pid"] != pid
            assert upgraded.get("destination_host") is None  # custom bridge address stays private
            assert upgraded["connected"] is False
            bridge_online.set()
            wait("candidate reconnect", lambda: status().get("connected"))
            wait("candidate issuer", lambda: len(issuers) == 2)
            assert unit_file.read_bytes() == definition and export.read_bytes() == original_export
            print("PASS disconnected legacy gateway adopts candidate, then reconnects with the same issuer and arguments", flush=True)

            stop(daemon)
            publish(args.baseline)
            time.sleep(6)
            assert status().get("build", {}).get("commit") == commit
            daemon = activate()
            floor = wait("baseline gateway", lambda: (s if not (s := status()).get("build") and s.get("connected") else None))
            assert floor["gateway"]["managed"] and floor["gateway"]["pid"] == upgraded["gateway"]["pid"]
            if Path("/proc/self/exe").exists():
                assert os.path.samefile(f'/proc/{floor["gateway"]["pid"]}/exe', binary)
            wait("baseline issuer", lambda: len(issuers) == 3)
            assert len(set(issuers)) == 1 and unit_file.read_bytes() == definition
            print("PASS gateway drains and execs baseline after daemon readiness", flush=True)

            stop(daemon)
            call("gateway", "service", "stop")
            publish(args.candidate)
            daemon = activate()
            time.sleep(6)
            assert not status()["gateway"]["running"]
            stop(daemon)
            foreground = spawn("gateway", "run", "--hosted", origin)
            wait("foreground readiness", lambda: status()["gateway"]["pid"] == foreground.pid)
            publish(args.baseline)
            daemon = activate()
            time.sleep(7)
            external = status()
            assert external["gateway"]["pid"] == foreground.pid and not external["gateway"]["managed"]
            assert external["build"]["commit"] == commit
            print("PASS intentional stop and foreground gateway preserved", flush=True)
            stop(foreground)
            stop(daemon)
            publish(args.candidate)
            with socket.socket() as available:
                available.bind(("127.0.0.1", 0))
                port = available.getsockname()[1]
            direct = call("gateway", "service", "install", "--listen", f"127.0.0.1:{port}")
            target_pid = direct["gateway"]["pid"]
            with socket.create_connection(("127.0.0.1", port), timeout=20) as connection:
                body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
                token = json.loads(original_export)["token"]
                headers = (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                           f"Authorization: Bearer {token}\r\nContent-Length: {len(body)}\r\n"
                           "Expect: 100-continue\r\nContent-Type: application/json\r\n"
                           "Accept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2025-11-25\r\n\r\n")
                connection.sendall(headers.encode())
                # The server only sends 100 once its authenticated handler reads the body.
                response = connection.makefile("rb")
                assert b" 100 " in response.readline()
                assert response.readline() == b"\r\n"
                connection.sendall(body[:-1])
                publish(args.baseline)
                daemon = activate()
                def listener_closed():
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            return False
                    except ConnectionRefusedError:
                        return True
                wait("direct listener to drain", listener_closed, 15)
                connection.sendall(body[-1:])
                reply = http.client.HTTPResponse(connection)
                reply.begin()
                assert reply.status == 200 and "result" in json.loads(reply.read())
                response.close()
            wait("direct baseline readiness", lambda: (s := status())["gateway"]["pid"] == target_pid
                 and not s.get("build"))
            print("PASS direct gateway finishes an admitted HTTP request before baseline exec", flush=True)
        finally:
            for proc in reversed(processes):
                stop(proc)
            if installed:
                call("gateway", "service", "uninstall", reader=args.candidate)
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    main()
