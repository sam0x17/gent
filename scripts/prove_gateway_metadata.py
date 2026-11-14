#!/usr/bin/env python3
"""Opt-in public HTTPS metadata import through the CLI; no gateway or model calls."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gent", type=Path, required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--redirect-uri", required=True)
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
        export = node / "host.json"
        setup = (
            "gateway", "clients", "add", "metadata-host",
            "--conversation-key", "test/conversation",
            "--oauth-resource", "https://node.invalid/mcp",
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
        print(json.dumps({
            "status": "passed", "proof": "public-client-metadata-import",
            "metadata": args.metadata, "selected_callback": args.redirect_uri,
            "key_ids": keys["key_ids"], "key_revision": keys["key_revision"],
            "repeated_setup": "passed", "unchanged_refresh": "passed",
            "wrong_revision_nonmutation": "passed", "shared_secret": False,
            "gateway_started": False,
        }))


if __name__ == "__main__":
    main()
