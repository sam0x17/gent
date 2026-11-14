#!/usr/bin/env python3
"""Opt-in public metadata import and optional loopback CIMD; no model calls."""
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


def exercise_gateway(binary, node, registration, resource, cli):
    origin = resource.removesuffix("/mcp")
    listen = urllib.parse.urlsplit(origin).netloc
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def get(path, status=200):
        try:
            response = opener.open(origin + path, timeout=25)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.status == status, f"unexpected HTTP status {response.status}"
            return response.headers, response.read().decode()

    for _ in range(2):
        process = subprocess.Popen(
            [str(binary), "--home", str(node), "gateway", "run", "--listen", listen,
             "--client-metadata", registration["client"]],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                assert process.poll() is None, "gateway exited before discovery"
                try:
                    _, body = get("/.well-known/oauth-authorization-server")
                    break
                except urllib.error.URLError:
                    assert time.monotonic() < deadline, "gateway discovery timed out"
                    time.sleep(0.05)
            discovery = json.loads(body)
            assert discovery["client_id_metadata_document_supported"] is True
            assert "registration_endpoint" not in discovery
            verifier = secrets.token_urlsafe(48)
            fields = {
                "response_type": "code", "client_id": registration["oauth"]["assertion"]["client_id"],
                "redirect_uri": registration["oauth"]["redirect_uris"][0], "resource": resource,
                "scope": "gent:agents", "state": secrets.token_hex(16), "code_challenge_method": "S256",
                "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("="),
            }
            get("/oauth/authorize?" + urllib.parse.urlencode(dict(fields, client_id="https://unapproved.invalid/client.json")), 400)
            _, page = get("/oauth/authorize?" + urllib.parse.urlencode(fields))
            pending = [v for v in cli("gateway", "oauth", "requests")["requests"] if v["decision"] is None]
            assert len(pending) == 1 and pending[0]["oauth_client_id"] == fields["client_id"]
            request = pending[0]["request"]
            assert request in page and fields["client_id"] in page
            cli("gateway", "oauth", "deny", request)
            headers, _ = get("/oauth/continue?request=" + request, 303)
            redirect = urllib.parse.urlsplit(headers["Location"])
            query = urllib.parse.parse_qs(redirect.query)
            assert query["error"] == ["access_denied"] and query["iss"] == [origin]
            assert query["state"] == [fields["state"]]
            # The callback is inspected, never followed to the provider.
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            assert process.returncode == 0, "gateway shutdown failed"
    return {"discovery": "passed", "public_metadata_authorization": "passed",
            "unknown_client_rejection": "passed", "denial": "passed", "restart": "passed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gent", type=Path, required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--redirect-uri", required=True)
    parser.add_argument("--exercise-gateway", action="store_true", help="Also start a temporary loopback gateway and exercise CIMD authorization/restart")
    args = parser.parse_args()
    binary = args.gent.resolve()
    with tempfile.TemporaryDirectory(prefix="gent-metadata-", dir="/tmp") as temporary:
        node = Path(temporary).resolve() / "node"

        def cli(*arguments, success=True):
            result = subprocess.run(
                [str(binary), "--home", str(node), "--json", *arguments],
                capture_output=True, text=True, timeout=30,
            )
            assert (result.returncode == 0) == success, result.stderr
            return json.loads(result.stdout) if success else None

        cli("cluster", "new", "metadata-proof", "--local")
        resource = "https://node.invalid/mcp"
        if args.exercise_gateway:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                resource = f"http://127.0.0.1:{listener.getsockname()[1]}/mcp"
        export = node / "host.json"
        setup = (
            "gateway", "clients", "add", "metadata-host",
            "--conversation-key", "test/conversation",
            "--oauth-resource", resource,
            "--redirect-uri", args.redirect_uri,
            "--oauth-metadata", args.metadata,
            "--out", str(export),
        )
        cli(*setup)
        original = export.read_bytes()
        registered = json.loads(original)
        client = registered["client"]
        assert registered.get("token") is None
        assert registered["oauth"]["assertion"]["client_id"] == args.metadata
        assert registered["oauth"]["redirect_uris"] == [args.redirect_uri]
        keys = cli("gateway", "clients", "keys", "show", client)
        assert keys["key_revision"] == 0 and not keys["export_pending"]
        assert keys["key_ids"]

        cli(*setup)
        assert export.read_bytes() == original, "repeated setup changed the registration"
        refreshed = cli("gateway", "clients", "keys", "refresh", client, "--expect-revision", "0")
        assert refreshed == keys, "published keys changed during this proof"
        assert export.read_bytes() == original
        state = node / "gateway" / "state.json"
        before = state.read_bytes()
        cli("gateway", "clients", "keys", "refresh", client, "--expect-revision", "1", success=False)
        assert state.read_bytes() == before and export.read_bytes() == original
        gateway = exercise_gateway(binary, node, registered, resource, cli) if args.exercise_gateway else None
        print(json.dumps({
            "status": "passed", "proof": "public-client-metadata-import",
            "metadata": args.metadata, "selected_callback": args.redirect_uri,
            "key_ids": keys["key_ids"], "key_revision": keys["key_revision"],
            "repeated_setup": "passed", "unchanged_refresh": "passed",
            "wrong_revision_nonmutation": "passed", "shared_secret": False,
            "gateway_started": args.exercise_gateway, "gateway": gateway,
        }))


if __name__ == "__main__":
    main()
