#!/usr/bin/env python3
"""Native-process proof of per-grant client TLS certificates.

Uses OpenSSL to create a temporary CA, server and client identities. It exercises
the Gent CLI, direct TLS, ordinary browser discovery, persistent agent binding,
leaf rotation, listener restart and revocation. No provider calls or deployment.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gent", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    binary = str(args.gent.resolve())
    os.umask(0o077)
    processes = []
    with tempfile.TemporaryDirectory(prefix="gent-mtls-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        node = root / "node"
        logs = []

        def cli(*arguments, success=True):
            result = subprocess.run([binary, "--home", str(node), "--json", *arguments],
                                    capture_output=True, text=True, timeout=20)
            assert (result.returncode == 0) == success, "unexpected CLI result"
            return json.loads(result.stdout) if success else None

        def openssl(*arguments):
            result = subprocess.run([args.openssl, *arguments], cwd=root,
                                    capture_output=True, timeout=20)
            assert result.returncode == 0, "OpenSSL fixture setup failed"

        def certificate(name, dns, usage):
            openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + dns,
                    "-keyout", name + ".key", "-out", name + ".csr")
            (root / (name + ".ext")).write_text("basicConstraints=critical,CA:FALSE\n"
                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=" + usage +
                "\nsubjectAltName=DNS:" + dns + "\n")
            openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                    "-CAcreateserial", "-days", "2", "-sha256", "-extfile", name + ".ext", "-out", name + ".pem")

        def start(*arguments):
            path = root / f"process-{len(processes)}.log"
            with path.open("wb") as log:
                process = subprocess.Popen([binary, "--home", str(node), *arguments],
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            logs.append(path)
            processes.append(process)
            return process

        def stop(process):
            process.terminate()
            assert process.wait(timeout=15) == 0

        def context(name=None):
            result = ssl.create_default_context(cafile=str(root / "ca.pem"))
            if name:
                result.load_cert_chain(root / (name + ".pem"), root / (name + ".key"))
            return result

        def request(ctx, path, rpc=None, bearer=None, expected=200, headers=None):
            headers = dict(headers or {})
            data = None
            if rpc is not None:
                headers.update({"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                                "MCP-Protocol-Version": "2025-11-25"})
                data = json.dumps(rpc).encode()
            if bearer:
                headers["Authorization"] = "Bearer " + bearer
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
            try:
                response = opener.open(urllib.request.Request(origin + path, data, headers), timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                assert response.status == expected, f"unexpected HTTP status {response.status}"
                body = response.read()
                return json.loads(body) if body else None

        def call(ctx, name, arguments):
            response = request(ctx, "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": name, "arguments": arguments, "_meta": {"test/conversation": "stable-chat"}}}, token)
            assert not response.get("error") and not response["result"].get("isError"), "agent call failed"
            return json.loads(response["result"]["content"][0]["text"])

        try:
            (root / "ca.cnf").write_text("[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n"
                "[dn]\nCN=Gent proof CA\n[ca]\nbasicConstraints=critical,CA:TRUE\n"
                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
                "keyUsage=critical,keyCertSign,cRLSign\n")
            openssl("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-config", "ca.cnf", "-keyout", "ca.key", "-out", "ca.pem")
            certificate("server", "localhost", "serverAuth")
            certificate("client", "client.example", "clientAuth")
            certificate("rotated", "client.example", "clientAuth")
            certificate("wrong", "other.example", "clientAuth")
            browser, host, rotated, wrong = context(), context("client"), context("rotated"), context("wrong")
            cli("cluster", "new", "mtls", "--local")
            export = root / "client.json"
            added = cli("gateway", "clients", "add", "pinned", "--conversation-key", "test/conversation",
                        "--out", str(export), "--tls-client-ca", str(root / "ca.pem"), "--tls-client-name", "client.example")
            token = json.loads(export.read_text())["token"]
            assert added["mtls"]["dns_name"] == "client.example" and len(added["mtls"]["ca_sha256"]) == 64
            cli("gateway", "clients", "add", "pinned", "--conversation-key", "test/conversation",
                "--out", str(export), success=False)
            # The CA is copied into the registry; changing/removing the source cannot change trust.
            (root / "ca.pem").unlink()
            daemon = start("daemon", "run")
            for _ in range(200):
                assert daemon.poll() is None
                if (node / "daemon.sock").exists():
                    break
                time.sleep(0.05)
            with socket.socket() as free:
                free.bind(("127.0.0.1", 0))
                port = free.getsockname()[1]
            origin = f"https://localhost:{port}"
            options = ["gateway", "run", "--listen", f"127.0.0.1:{port}", "--origin", origin,
                       "--tls-cert", str(root / "server.pem"), "--tls-key", str(root / "server.key")]

            def launch():
                process = start(*options)
                failure = None
                for _ in range(200):
                    assert process.poll() is None
                    try:
                        metadata = request(browser, "/.well-known/oauth-protected-resource/mcp")
                        assert metadata["resource"] == origin + "/mcp"
                        return process
                    except urllib.error.URLError as error:
                        failure = error.reason
                        time.sleep(0.05)
                raise AssertionError(f"TLS gateway startup timed out: {failure}")

            gateway = launch()
            rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            request(browser, "/mcp", rpc, token, expected=401,
                    headers={"X-TLS-Client-Name": "client.example", "X-Client-Cert": "forged"})
            request(wrong, "/mcp", rpc, token, expected=401)
            request(host, "/mcp", rpc, "invalid", expected=401)
            first = call(host, "gent_register", {"name": "pinned", "provider": "synthetic"})
            stop(gateway)
            gateway = launch()
            assert call(rotated, "gent_identity", {})["agent"]["id"] == first["agent"]["id"]
            cli("gateway", "clients", "revoke", added["client"])
            request(rotated, "/mcp", rpc, token, expected=401)
            stop(gateway)
            stop(daemon)
            for path in logs:
                assert token not in path.read_text()
            print(json.dumps({"status": "passed", "proof": "gateway-mtls-cli", "checks": [
                "pinned CA and DNS identity", "private registration retry", "anonymous discovery",
                "missing/wrong peer rejection", "certificate still requires bearer", "no HTTP-header impersonation",
                "persisted CA after source deletion", "leaf rotation", "gateway restart identity", "revocation", "private logs"]}))
        finally:
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
