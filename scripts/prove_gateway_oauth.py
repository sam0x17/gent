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
    parser.add_argument("--private-key-jwt", action="store_true")
    parser.add_argument("--subject-binding", action="store_true")
    args = parser.parse_args()
    binary = args.gent.resolve()
    with tempfile.TemporaryDirectory(prefix="gent-go-", dir="/tmp") as temporary:
        home = Path(temporary).resolve() / "node"
        processes = []
        log_paths = []
        private_values = []
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

        def authentication(key=None, kid=None):
            if not args.private_key_jwt:
                return {"client_secret": client_secret}
            now = int(time.time())
            header = {"alg": "RS256", "kid": kid or signing_kid, "typ": "JWT"}
            claims = {"iss": client_id, "sub": client_id, "aud": origin + "/oauth/token",
                      "iat": now, "exp": now + 120, "jti": secrets.token_hex(16)}
            encoded = [base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip("=") for v in (header, claims)]
            signing = ".".join(encoded).encode()
            signature = subprocess.check_output(["openssl", "dgst", "-sha256", "-sign", str(key or signing_key)], input=signing)
            assertion = signing.decode() + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")
            private_values.append(assertion)
            return {"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": assertion}

        def signing_fixture(kid):
            key = home / (kid + ".pem")
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                            "-out", str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            modulus = subprocess.check_output(["openssl", "rsa", "-in", str(key), "-noout", "-modulus"],
                                              stderr=subprocess.DEVNULL).decode().strip().split("=", 1)[1]
            return key, {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
                         "n": base64.urlsafe_b64encode(bytes.fromhex(modulus)).decode().rstrip("="), "e": "AQAB"}

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

        def call(token, name, arguments, *, subject="synthetic-user-a", error=False, metadata=None):
            if metadata is None:
                metadata = {"test/conversation": "same-chat"}
                if args.subject_binding and subject is not None:
                    metadata["test/subject"] = subject
            _, body = http("/mcp", bearer=token, rpc={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": name, "arguments": arguments, "_meta": metadata}})
            result = json.loads(body)
            if error:
                assert "error" in result or result["result"].get("isError"), result
                return result
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
                                               **authentication(), "resource": resource,
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
            extra = []
            if args.private_key_jwt:
                signing_kid = "synthetic"
                signing_key, original_jwk = signing_fixture(signing_kid)
                jwks = home / "jwks.json"
                jwks.write_text(json.dumps({"keys": [original_jwk]}))
                extra = ["--oauth-client-id", "https://synthetic.invalid/client.json", "--oauth-jwks", str(jwks)]
            if args.subject_binding:
                extra.extend(["--subject-key", "test/subject"])
                private_values.extend(["synthetic-user-a", "synthetic-user-b"])
            added = cli("gateway", "clients", "add", "synthetic-oauth", "--conversation-key", "test/conversation",
                        "--out", str(export), "--oauth-resource", resource, "--redirect-uri", callback, *extra)
            exported = json.loads(export.read_text())
            local_client_id = exported["client"]
            if args.private_key_jwt:
                client_id = exported["oauth"]["assertion"]["client_id"]
                assert "token" not in exported and exported["version"] == (5 if args.subject_binding else 3)
                # Prove that setup pins the key material and exact retries keep it.
                assert cli("gateway", "clients", "add", "synthetic-oauth", "--conversation-key", "test/conversation",
                           "--out", str(export), "--oauth-resource", resource, "--redirect-uri", callback, *extra) == added
                jwks.unlink()
            else:
                client_id, client_secret = local_client_id, exported["token"]
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
            _, metadata = http("/.well-known/oauth-authorization-server")
            assert "private_key_jwt" in json.loads(metadata)["token_endpoint_auth_methods_supported"]
            assert json.loads(metadata).get("client_id_metadata_document_supported") is not True
            headers, _ = http("/mcp", status=401)
            assert "resource_metadata" in headers["WWW-Authenticate"]
            if args.private_key_jwt:
                http("/mcp", bearer=authentication()["client_assertion"], status=401)
            token = authorize()
            if args.subject_binding:
                call(token["access_token"], "gent_register", {"name": "hosted", "provider": "synthetic"}, subject=None, error=True)
                # Arguments never supply the host identity metadata.
                call(token["access_token"], "gent_register", {"name": "hosted", "provider": "synthetic", "test/subject": "synthetic-user-a"}, subject=None, error=True)
                saved = json.loads((home / "gateway/state.json").read_text())
                assert saved["clients"][local_client_id]["bindings"] == {}
                assert all(g["subject"] == "unbound" for g in saved["oauth"]["grants"].values())
            first = call(token["access_token"], "gent_register", {"name": "hosted", "provider": "synthetic"})
            if args.subject_binding:
                second_token = authorize()
                second = call(second_token["access_token"], "gent_register", {"name": "other-user", "provider": "synthetic"}, subject="synthetic-user-b")
                assert second["agent"]["id"] != first["agent"]["id"]
                call(token["access_token"], "gent_identity", {}, subject="synthetic-user-b", error=True)
                call(second_token["access_token"], "gent_identity", {}, error=True)
            stop(gateway)
            gateway = start("gateway", "run", "--listen", address)
            for _ in range(200):
                assert gateway.poll() is None
                try:
                    http("/.well-known/oauth-authorization-server")
                    break
                except urllib.error.URLError:
                    time.sleep(0.025)
            refresh = {"grant_type": "refresh_token", "client_id": client_id, **authentication(),
                       "resource": resource, "refresh_token": token["refresh_token"]}
            _, body = http("/oauth/token", form=refresh)
            rotated = json.loads(body)
            private_values.extend([rotated["access_token"], rotated["refresh_token"]])
            assert call(rotated["access_token"], "gent_identity", {})["agent"]["id"] == first["agent"]["id"]
            if args.subject_binding:
                call(rotated["access_token"], "gent_identity", {}, subject="synthetic-user-b", error=True)
                assert call(second_token["access_token"], "gent_identity", {}, subject="synthetic-user-b")["agent"]["id"] == second["agent"]["id"]
            http("/mcp", bearer=token["access_token"], status=401)
            http("/oauth/token", form=refresh, status=400)
            if args.private_key_jwt:
                # Replaying client authentication alone must not revoke the grant.
                assert call(rotated["access_token"], "gent_identity", {})["agent"]["id"] == first["agent"]["id"]
                stop(gateway)
                gateway = start("gateway", "run", "--listen", address)
                for _ in range(200):
                    assert gateway.poll() is None
                    try:
                        http("/.well-known/oauth-authorization-server")
                        break
                    except urllib.error.URLError:
                        time.sleep(0.025)
                http("/oauth/token", form=refresh, status=400)
                assert call(rotated["access_token"], "gent_identity", {})["agent"]["id"] == first["agent"]["id"]
                # A new assertion authenticates a spent refresh-token replay.
                http("/oauth/token", form={**refresh, **authentication()}, status=400)
            http("/mcp", bearer=rotated["access_token"], status=401)
            fresh = authorize()
            assert call(fresh["access_token"], "gent_identity", {})["agent"]["id"] == first["agent"]["id"]
            if args.private_key_jwt:
                def renew(current, auth):
                    _, body = http("/oauth/token", form={"grant_type": "refresh_token", "client_id": client_id,
                        **auth, "resource": resource, "refresh_token": current["refresh_token"]})
                    renewed = json.loads(body)
                    assert renewed["refresh_token"].split(".")[1] == current["refresh_token"].split(".")[1]
                    private_values.extend([renewed["access_token"], renewed["refresh_token"]])
                    assert call(renewed["access_token"], "gent_identity", {})["agent"]["id"] == first["agent"]["id"]
                    return renewed

                next_key, next_jwk = signing_fixture("rotated")
                assert cli("gateway", "clients", "keys", "show", local_client_id)["key_revision"] == 0
                overlap = home / "overlap.json"
                overlap.write_text(json.dumps({"keys": [original_jwk, next_jwk]}))
                update = cli("gateway", "clients", "keys", "set", local_client_id,
                             "--jwks", str(overlap), "--expect-revision", "0")
                assert update["key_revision"] == 1 and not update["export_pending"]
                assert cli("gateway", "clients", "keys", "set", local_client_id,
                           "--jwks", str(overlap), "--expect-revision", "0") == update
                fresh = renew(fresh, authentication())
                fresh = renew(fresh, authentication(next_key, "rotated"))
                replacement = home / "replacement.json"
                replacement.write_text(json.dumps({"keys": [next_jwk]}))
                update = cli("gateway", "clients", "keys", "set", local_client_id,
                             "--jwks", str(replacement), "--expect-revision", "1")
                assert update["key_revision"] == 2 and update["key_ids"] == ["rotated"]
                stale = subprocess.run([str(binary), "--home", str(home), "--json", "gateway", "clients", "keys", "set",
                    local_client_id, "--jwks", str(overlap), "--expect-revision", "0"], capture_output=True, timeout=20)
                assert stale.returncode != 0
                _, rejected = http("/oauth/token", form={"grant_type": "refresh_token", "client_id": client_id,
                    **authentication(), "resource": resource, "refresh_token": fresh["refresh_token"]}, status=400)
                assert json.loads(rejected)["error"] == "invalid_client"
                signing_key, signing_kid = next_key, "rotated"
                fresh = renew(fresh, authentication())
                replacement.unlink()
                overlap.unlink()
                exported = json.loads(export.read_text())
                assert exported["client"] == local_client_id and exported["version"] == (5 if args.subject_binding else 4) and exported["key_revision"] == 2
                assert "token" not in exported and len(exported["oauth"]["assertion"]["keys"]) == 1
                stop(gateway)
                gateway = start("gateway", "run", "--listen", address)
                for _ in range(200):
                    assert gateway.poll() is None
                    try:
                        http("/.well-known/oauth-authorization-server")
                        break
                    except urllib.error.URLError:
                        time.sleep(0.025)
                fresh = renew(fresh, authentication())
            if args.subject_binding:
                call(fresh["access_token"], "gent_identity", {}, subject="synthetic-user-b", error=True)
                saved = (home / "gateway/state.json").read_text()
                assert "synthetic-user-a" not in saved and "synthetic-user-b" not in saved
                assert json.loads(saved)["version"] == 6
                assert json.loads(export.read_text())["subject_key"] == "test/subject"
            cli("gateway", "clients", "revoke", local_client_id)
            http("/mcp", bearer=fresh["access_token"], status=401)
            stop(gateway)
            stop(daemon)
            for log in log_paths:
                assert not any(value in log.read_text() for value in private_values)
            print(json.dumps({"status": "passed", "proof": "gateway-oauth-cli",
                "authentication": "private_key_jwt" if args.private_key_jwt else "client_secret_post", "checks": [
                "discovery", "local owner consent", "PKCE", "issuer and state callback", "restart",
                "refresh", "replay revocation", "reconnect identity", "host revocation", "private logs"] + ([
                "pinned JWKS", "no shared secret", "persistent assertion replay rejection", "key overlap and retirement",
                "key-update retry", "stale update rejection", "grant and agent continuity after key update"] if args.private_key_jwt else []) + ([
                "user-scoped conversation isolation", "grant user pin", "missing and argument-supplied user rejection",
                "user continuity through refresh restart and reauthorization", "hashed user persistence"] if args.subject_binding else [])}))
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
