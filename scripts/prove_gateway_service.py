#!/usr/bin/env python3
"""Opt-in native gateway/daemon lifecycle proof using disposable user services.

Uses a synthetic authenticated HTTP host and a temporary TLS certificate. No
provider calls, real account credentials, or cloud deployment. Requires OpenSSL.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from http_mcp_client import rpc as http_rpc
from mcp_fixtures import PNG


def wait(check):
    until = time.monotonic() + 30
    while time.monotonic() < until:
        if check():
            return
        time.sleep(0.15)
    raise AssertionError("gateway did not reach expected state")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gent", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="gent-gs-", dir="/tmp")).resolve()
    home = root / "node '$%&"
    command = [str(args.gent.resolve()), "--home", str(home), "--json"]
    foreground = None
    completed = False
    result = None

    def cli(*arguments, expected=0):
        response = subprocess.run(
            command + list(arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert response.returncode == expected, (
            f"{arguments}: exit {response.returncode}: {response.stderr}"
        )
        return json.loads(response.stdout) if response.stdout else None

    def service(*arguments, expected=0):
        return cli("gateway", "service", *arguments, expected=expected)

    def status():
        response = subprocess.run(
            command + ["gateway", "service", "status"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert response.returncode in (0, 3), response.stderr
        return json.loads(response.stdout)

    def rpc(method, params, bearer=None, expected=200):
        return http_rpc(
            opener,
            origin + "/mcp",
            method,
            params,
            token if bearer is None else bearer,
            expected,
        )

    def call(name, arguments=None, conversation="one"):
        response = rpc(
            "tools/call",
            {
                "name": name,
                "arguments": arguments or {},
                "_meta": {"test/conversation": conversation},
            },
        )
        assert "error" not in response and not response["result"].get("isError"), (
            "MCP call failed"
        )
        raw = response["result"]
        return json.loads(raw["content"][0]["text"]), raw

    def same_daemon():
        current = cli("daemon", "status")
        assert current["daemon"]["managed"] and current["daemon"]["pid"] == daemon_pid
        assert daemon_file.read_bytes() == daemon_bytes

    try:
        assert not service("status", expected=3)["service"]["installed"]
        assert not home.exists()
        service("install", expected=1)
        assert not home.exists()
        daemon = cli("daemon", "install", "--local", "gateway-service-proof")
        daemon_pid = daemon["daemon"]["pid"]
        daemon_file = Path(daemon["service"]["file"])
        daemon_bytes = daemon_file.read_bytes()
        config = cli("config")
        identity = (home / "identity.key").read_bytes()
        owner = (home / "owner.key").read_bytes()
        exported = root / "host.json"
        added = cli(
            "gateway",
            "clients",
            "add",
            "synthetic-host",
            "--conversation-key",
            "test/conversation",
            "--out",
            str(exported),
        )
        credential = exported.read_bytes()
        token = json.loads(credential)["token"]

        cert, key = root / "cert ' $%&.pem", root / 'key " $%<xml>.pem'
        conf = root / "server.cnf"
        conf.write_text(
            "[req]\ndistinguished_name=dn\nx509_extensions=server\nprompt=no\n"
            "[dn]\nCN=localhost\n[server]\nbasicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
        )
        generated = subprocess.run(
            [
                args.openssl,
                "req",
                "-new",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-config",
                str(conf),
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=False,
            capture_output=True,
            timeout=30,
        )
        assert generated.returncode == 0, "TLS fixture generation failed"
        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        address, origin = f"127.0.0.1:{port}", f"https://localhost:{port}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(
                context=ssl.create_default_context(cafile=str(cert))
            ),
        )
        options = [
            "--listen",
            address,
            "--origin",
            origin,
            "--tls-cert",
            str(cert),
            "--tls-key",
            str(key),
            "--file-origin",
            added["client"] + "=https://files.example",
            "--file-downloads",
            added["client"],
        ]
        installed = service("install", *options)
        assert installed["gateway"]["managed"] and installed["service"]["enabled"]
        assert installed["listen"] == address and installed["origin"] == origin
        service_file = Path(installed["service"]["file"])
        service_bytes = service_file.read_bytes()
        assert service_file != daemon_file and service_file.stat().st_mode & 0o077 == 0
        assert (
            token.encode() not in service_bytes
            and key.read_bytes() not in service_bytes
        )
        pid = installed["gateway"]["pid"]
        assert service("install", *options)["gateway"]["pid"] == pid
        assert service("start")["gateway"]["pid"] == pid
        same_daemon()
        rpc("tools/list", {}, bearer="invalid-host-token", expected=401)
        first = call("gent_register", {"name": "one", "provider": "synthetic"})[0]
        second = call("gent_register", {"name": "two", "provider": "synthetic"}, "two")[
            0
        ]
        aid, bid = first["agent"]["id"], second["agent"]["id"]
        assert aid != bid
        cli("permission", "allow", aid, bid, "--permission", "enumerate", "send")
        cli("permission", "allow", bid, aid, "--permission", "enumerate", "receive")
        sent = call(
            "gent_send_non_blocking",
            {
                "recipient": bid,
                "request_id": call("gent_request_ids")[0]["request_ids"][0],
                "text": "survive independent services",
                "files": [
                    {"name": "image.png", "media_type": "image/png", "data_base64": PNG}
                ],
            },
        )[0]

        # Invalid replacement arguments must leave the working listener intact.
        for flag, value in [
            ("--tls-key", str(root / "missing.key")),
            ("--file-origin", "invalid-host=https://files.example"),
            ("--file-downloads", "invalid-host"),
            ("--listen", "127.0.0.1:0"),
        ]:
            invalid = options.copy()
            invalid[invalid.index(flag) + 1] = value
            service("install", *invalid, expected=1)
            assert (
                status()["gateway"]["pid"] == pid
                and service_file.read_bytes() == service_bytes
            )
        service("install", *options, "--client-metadata", added["client"], expected=1)
        assert (
            status()["gateway"]["pid"] == pid
            and service_file.read_bytes() == service_bytes
        )
        assert call("gent_identity")[0]["agent"]["id"] == aid

        assert not service("stop")["gateway"]["running"]
        assert not (home / "gateway/control.sock").exists()
        assert not service("stop")["gateway"]["running"]
        same_daemon()
        started = service("start")
        assert started["gateway"]["managed"] and started["gateway"]["pid"] != pid
        restarted = service("restart")
        assert restarted["gateway"]["pid"] != started["gateway"]["pid"]
        os.kill(restarted["gateway"]["pid"], signal.SIGKILL)
        wait(
            lambda: (
                (s := status())["gateway"]["managed"]
                and s["gateway"]["pid"] != restarted["gateway"]["pid"]
            )
        )
        same_daemon()
        cli("daemon", "restart")
        inbox, raw = call("gent_inbox", conversation="two")
        assert len(inbox) == 1 and inbox[0]["id"] == sent["message_id"]
        assert inbox[0]["files"][0]["data_base64"] == PNG
        assert any(
            part["type"] == "image" and part["data"] == PNG for part in raw["content"]
        )
        assert call("gent_identity")[0]["agent"]["id"] == aid
        daemon_pid = cli("daemon", "status")["daemon"]["pid"]

        # Preserve edits, links and shared files without taking control of them.
        try:
            service_file.write_bytes(service_bytes + b"\n")
            service("install", *options, expected=1)
            service("uninstall", expected=1)
            assert service_file.read_bytes() == service_bytes + b"\n"
        finally:
            service_file.write_bytes(service_bytes)
        try:
            service_file.chmod(0o644)
            service("stop", expected=1)
            assert service_file.stat().st_mode & 0o777 == 0o644
        finally:
            service_file.chmod(0o600)
        backup = service_file.with_name(service_file.name + ".proof-backup")
        service_file.rename(backup)
        try:
            service_file.symlink_to(backup)
            service("uninstall", expected=1)
            assert service_file.is_symlink() and backup.read_bytes() == service_bytes
        finally:
            service_file.unlink()
            backup.rename(service_file)

        service("stop")
        with (root / "foreground.log").open("w") as log:
            foreground = subprocess.Popen(
                command + ["gateway", "run", *options],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
            )
        wait(lambda: status()["gateway"]["running"])
        assert not status()["gateway"]["managed"]
        for operation in [
            ("install", *options),
            ("start",),
            ("restart",),
            ("stop",),
            ("uninstall",),
        ]:
            service(*operation, expected=1)
            assert (
                foreground.poll() is None and service_file.read_bytes() == service_bytes
            )
        same_daemon()
        foreground.terminate()
        assert foreground.wait(timeout=15) == 0
        foreground = None
        service("start")

        # Removal must work even if the TLS material has become unavailable.
        saved_key = key.read_bytes()
        key.unlink()
        service("restart", expected=1)
        assert status()["gateway"]["managed"]
        removed = service("uninstall")
        assert not removed["gateway"]["running"] and not removed["service"]["installed"]
        assert not service_file.exists()
        same_daemon()
        key.write_bytes(saved_key)
        service("install", *options)
        assert exported.read_bytes() == credential
        assert call("gent_identity")[0]["agent"]["id"] == aid
        assert call("gent_inbox", conversation="two")[0][0]["id"] == sent["message_id"]
        assert (home / "identity.key").read_bytes() == identity and (
            home / "owner.key"
        ).read_bytes() == owner
        current = cli("config")
        assert (
            current["node"]["id"] == config["node"]["id"]
            and current["cluster"]["id"] == config["cluster"]["id"]
        )
        logs = service("logs", "--lines", "100")["lines"]
        assert any("Gent gateway:" in line for line in logs)
        captured = "\n".join(logs) + (root / "foreground.log").read_text()
        assert all(
            value not in captured
            for value in [
                token,
                "test/conversation",
                "survive independent services",
                PNG,
            ]
        )
        service("uninstall")
        service("uninstall")
        same_daemon()
        result = {
            "status": "passed",
            "proof": "gateway-service",
            "platform": os.uname().sysname,
            "backend": installed["service"]["backend"],
            "checks": [
                "install/reinstall/start/stop/restart/uninstall",
                "SIGKILL recovery",
                "independent daemon lifecycle",
                "literal TLS and node paths",
                "preflight preserves service",
                "edited/shared/symlink file protection",
                "foreground ownership",
                "cleanup without TLS key",
                "authenticated TLS MCP",
                "separate conversation identities",
                "durable pending PNG",
                "identity and credentials survive reinstall",
                "logs exclude tested private values",
            ],
        }
        completed = True
    finally:
        if foreground and foreground.poll() is None:
            foreground.terminate()
            foreground.wait(timeout=15)
        failures = []
        for operation in [["gateway", "service", "uninstall"], ["daemon", "uninstall"]]:
            cleanup = subprocess.run(
                command + operation,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if cleanup.returncode:
                failures.append(" ".join(operation))
        if failures:
            raise RuntimeError(f"cleanup failed for {failures}; retained {root}")
        if completed:
            shutil.rmtree(root)
        else:
            print(
                f"Proof failed; service registrations removed, evidence retained at {root}",
                flush=True,
            )
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
