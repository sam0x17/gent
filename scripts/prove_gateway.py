#!/usr/bin/env python3
"""Exercise the real CLI and foreground gateway in private disposable state.

Synthetic trusted host only; this does not test a provider connector or OAuth.
"""
import argparse
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from http_mcp_client import rpc as http_rpc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gent", type=Path, required=True)
    parser.add_argument("--files", action="store_true", help="also prove 32 MiB chunk reads and image views")
    parser.add_argument("--host-files", action="store_true", help="prove host file inputs using a public PNG and local binary framing")
    parser.add_argument("--downloads", action="store_true", help="also prove bearer file links, full integrity and restart (includes --files)")
    args = parser.parse_args()
    binary = args.gent.resolve()
    with tempfile.TemporaryDirectory(prefix="gent-gw-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        home = root / "node"
        processes = []
        logs = []

        def cli(*arguments, success=True):
            result = subprocess.run(
                [str(binary), "--home", str(home), "--json", *arguments],
                check=False, capture_output=True, text=True, timeout=20,
            )
            if success:
                assert result.returncode == 0, result.stderr
                return json.loads(result.stdout)
            assert result.returncode != 0
            return result

        def start(*arguments):
            path = root / f"process-{len(logs)}.log"
            with path.open("wb") as log:
                process = subprocess.Popen(
                    [str(binary), "--home", str(home), *arguments],
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                )
            processes.append(process)
            logs.append(path)
            return process

        def stop(process):
            process.terminate()
            try:
                assert process.wait(timeout=20) == 0
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def rpc(method, params, token, expected=200):
            return http_rpc(opener, url, method, params, token, expected)

        def call(name, arguments, conversation="one"):
            result = rpc("tools/call", {
                "name": name, "arguments": arguments,
                "_meta": {"test/conversation": conversation},
            }, token)
            assert "error" not in result, result
            assert not result["result"].get("isError"), result
            return json.loads(result["result"]["content"][0]["text"])

        def ready(process):
            for _ in range(200):
                assert process.poll() is None, "gateway exited during startup"
                try:
                    return rpc("tools/list", {}, token)
                except (urllib.error.URLError, TimeoutError):
                    time.sleep(0.025)
            raise AssertionError("gateway did not start")

        try:
            cli("cluster", "new", "original", "--local")
            assert cli("gateway", "status")["configured"] is False
            assert not (home / "gateway").exists()
            exported = home / "synthetic-host.json"
            added = cli("gateway", "clients", "add", "synthetic-host",
                        "--conversation-key", "test/conversation", "--out", str(exported))
            token = json.loads(exported.read_text())["token"]
            assert exported.stat().st_mode & 0o077 == 0
            assert token not in json.dumps(added)
            repeat = cli("gateway", "clients", "add", "synthetic-host",
                         "--conversation-key", "test/conversation", "--out", str(exported))
            assert repeat == added
            daemon = start("daemon", "run")
            for _ in range(200):
                assert daemon.poll() is None
                if (home / "daemon.sock").exists():
                    break
                time.sleep(0.025)
            with socket.socket() as free:
                free.bind(("127.0.0.1", 0))
                port = free.getsockname()[1]
            address = f"127.0.0.1:{port}"
            url = f"http://{address}/mcp"
            file_options = []
            if args.host_files:
                from gateway_input_checks import ORIGIN, InputChecks
                file_options = ["--file-origin", added["client"] + "=" + ORIGIN]
            if args.downloads:
                file_options.extend(["--file-downloads", added["client"]])
            gateway = start("gateway", "run", "--listen", address, *file_options)
            ready(gateway)
            first = call("gent_register", {"name": "one", "provider": "synthetic"})
            second = call("gent_register", {"name": "two", "provider": "synthetic"}, "two")
            assert first["agent"]["id"] != second["agent"]["id"]
            assert first["access_route"]["mode"] == "user_controlled_gateway"
            original = first["cluster_id"]
            files = None
            if args.files or args.downloads:
                from gateway_file_checks import FileChecks
                files = FileChecks(binary, home, cli, rpc, token, first, second)
            downloads = None
            if args.downloads:
                from gateway_download_checks import DownloadChecks
                downloads = DownloadChecks(home, files)
            inputs = InputChecks(binary, home, cli, rpc, token) if args.host_files else None
            # The primary CLI now selects another managed profile. Both running
            # and restarted --home runtimes must remain on the physical node.
            cli("cluster", "new", "selected-elsewhere", "--local")
            assert cli("gateway", "status")["configured"] is False
            assert call("gent_identity", {})["agent"]["id"] == first["agent"]["id"]
            stop(gateway)
            stop(daemon)
            daemon = start("daemon", "run")
            for _ in range(200):
                if (home / "daemon.sock").exists():
                    break
                time.sleep(0.025)
            gateway = start("gateway", "run", "--listen", address, *file_options)
            ready(gateway)
            assert call("gent_identity", {})["agent"]["id"] == first["agent"]["id"]
            if downloads:
                downloads.after_restart()
            if files:
                files.after_restart()
            if downloads:
                downloads.after_permission_change()
            if inputs:
                inputs.after_restart()
            cli("--cluster", original, "gateway", "clients", "revoke", added["client"])
            rpc("tools/list", {}, token, expected=401)
            cli("--cluster", original, "gateway", "clients", "add", "synthetic-host",
                "--conversation-key", "test/conversation", "--out", str(exported), success=False)
            stop(gateway)
            stop(daemon)
            for path in logs:
                text = path.read_text()
                assert token not in text
                assert "test/conversation" not in text
            if downloads:
                downloads.check_logs(logs)
            print(json.dumps({"status": "passed", "proof": "foreground-gateway",
                              "file_reads": bool(files),
                              "host_file_inputs": bool(inputs),
                              "file_downloads": bool(downloads),
                              "platform": os.uname().sysname,
                              "checks": ["private host export", "separate conversations", "profile switch isolation",
                                         "daemon and gateway restart", "live host revocation", "clean shutdown",
                                         "no bearer or conversation metadata in process logs"]}))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    main()
