#!/usr/bin/env python3
"""Synthetic OAuth client against real Gent CLI, gateway and daemon processes."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gent", type=Path, required=True)
    args = parser.parse_args()
    binary = args.gent.resolve()
    with tempfile.TemporaryDirectory(prefix="gent-go-", dir="/tmp") as temporary:
        home = Path(temporary).resolve() / "node"
        processes = []
        log_paths = []
        private_values = []
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

        def cli(*arguments):
            completed = subprocess.run([str(binary), "--home", str(home), "--json", *arguments],
                                       capture_output=True, text=True, timeout=20)
            assert completed.returncode == 0, completed.stderr
            return json.loads(completed.stdout)

        def start(*arguments):
            path = home / f"process-{len(log_paths)}.log"
            with path.open("wb") as log:
                process = subprocess.Popen([str(binary), "--home", str(home), *arguments],
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            log_paths.append(path)
            processes.append(process)
            return process

        def stop(process):
            process.terminate()
            assert process.wait(timeout=20) == 0

        def http(path, *, form=None, rpc=None, bearer=None, status=200):
            headers = {}
            data = None
            if form is not None:
                data = urllib.parse.urlencode(form).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            if rpc is not None:
                data = json.dumps(rpc).encode()
                headers.update({"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                                "MCP-Protocol-Version": "2025-11-25"})
            if bearer is not None:
                headers["Authorization"] = "Bearer " + bearer
            request = urllib.request.Request(origin + path, data=data, headers=headers)
            try:
                response = opener.open(request, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                assert response.code == status, f"unexpected HTTP status {response.code}"
                return response.headers, response.read().decode()

        def call(token, name, arguments):
            _, body = http("/mcp", bearer=token, rpc={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": name, "arguments": arguments, "_meta": {"test/conversation": "same-chat"}}})
            result = json.loads(body)
            assert "error" not in result and not result["result"].get("isError"), result
            return json.loads(result["result"]["content"][0]["text"])

        def authorize():
            verifier = secrets.token_urlsafe(48)
            state = secrets.token_urlsafe(32)
            private_values.extend([verifier, state])
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            query = urllib.parse.urlencode({"response_type": "code", "client_id": client_id, "redirect_uri": callback,
                                           "resource": resource, "scope": "gent:agents", "state": state,
                                           "code_challenge_method": "S256", "code_challenge": challenge})
            _, page = http("/oauth/authorize?" + query)
            pending = [r for r in cli("gateway", "oauth", "requests")["requests"] if r["decision"] is None]
            assert len(pending) == 1
            request_id = pending[0]["request"]
            assert request_id in page and pending[0]["redirect_uri"] == callback
            http("/oauth/continue?request=" + request_id)
            cli("gateway", "oauth", "approve", request_id)
            headers, _ = http("/oauth/continue?request=" + request_id, status=303)
            redirect = urllib.parse.urlsplit(headers["Location"])
            assert redirect.scheme + "://" + redirect.netloc + redirect.path == callback
            values = urllib.parse.parse_qs(redirect.query)
            assert values["state"] == [state] and values["iss"] == [origin]
            code = values["code"][0]
            private_values.append(code)
            _, body = http("/oauth/token", form={"grant_type": "authorization_code", "client_id": client_id,
                                               "client_secret": client_secret, "resource": resource,
                                               "redirect_uri": callback, "code": code, "code_verifier": verifier})
            token = json.loads(body)
            private_values.extend([token["access_token"], token["refresh_token"]])
            return token

        try:
            cli("cluster", "new", "oauth", "--local")
            with socket.socket() as free:
                free.bind(("127.0.0.1", 0))
                address = "127.0.0.1:" + str(free.getsockname()[1])
            origin = "http://" + address
            resource = origin + "/mcp"
            callback = "https://synthetic.invalid/callback"
            export = home / "oauth.json"
            added = cli("gateway", "clients", "add", "synthetic-oauth", "--conversation-key", "test/conversation",
                        "--out", str(export), "--oauth-resource", resource, "--redirect-uri", callback)
            exported = json.loads(export.read_text())
            client_id, client_secret = exported["client"], exported["token"]
            private_values.append(client_secret)
            assert client_secret not in json.dumps(added)
            daemon = start("daemon", "run")
            for _ in range(200):
                assert daemon.poll() is None
                if (home / "daemon.sock").exists():
                    break
                time.sleep(0.025)
            gateway = start("gateway", "run", "--listen", address)
            for _ in range(200):
                assert gateway.poll() is None
                try:
                    _, body = http("/.well-known/oauth-protected-resource/mcp")
                    break
                except urllib.error.URLError:
                    time.sleep(0.025)
            assert json.loads(body)["resource"] == resource
            headers, _ = http("/mcp", status=401)
            assert "resource_metadata" in headers["WWW-Authenticate"]
            token = authorize()
            first = call(token["access_token"], "gent_register", {"name": "hosted", "provider": "synthetic"})
            stop(gateway)
            gateway = start("gateway", "run", "--listen", address)
            for _ in range(200):
                assert gateway.poll() is None
                try:
                    http("/.well-known/oauth-authorization-server")
                    break
                except urllib.error.URLError:
                    time.sleep(0.025)
            refresh = {"grant_type": "refresh_token", "client_id": client_id, "client_secret": client_secret,
                       "resource": resource, "refresh_token": token["refresh_token"]}
            _, body = http("/oauth/token", form=refresh)
            rotated = json.loads(body)
            private_values.extend([rotated["access_token"], rotated["refresh_token"]])
            assert call(rotated["access_token"], "gent_identity", {})["agent"]["id"] == first["agent"]["id"]
            http("/mcp", bearer=token["access_token"], status=401)
            http("/oauth/token", form=refresh, status=400)
            http("/mcp", bearer=rotated["access_token"], status=401)
            fresh = authorize()
            assert call(fresh["access_token"], "gent_identity", {})["agent"]["id"] == first["agent"]["id"]
            cli("gateway", "clients", "revoke", client_id)
            http("/mcp", bearer=fresh["access_token"], status=401)
            stop(gateway)
            stop(daemon)
            for log in log_paths:
                assert not any(value in log.read_text() for value in private_values)
            print(json.dumps({"status": "passed", "proof": "gateway-oauth-cli", "checks": [
                "discovery", "local owner consent", "PKCE", "issuer and state callback", "restart",
                "refresh", "replay revocation", "reconnect identity", "host revocation", "private logs"]}))
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
