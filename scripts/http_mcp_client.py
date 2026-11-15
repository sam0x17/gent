"""Stateless JSON-RPC requests for HTTP/TLS MCP acceptance fixtures."""

import json
import urllib.error
import urllib.request


def rpc(opener, url, method, params, token, expected=200):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
        },
    )
    try:
        with opener.open(request, timeout=5) as response:
            assert response.status == expected
            return json.load(response)
    except urllib.error.HTTPError as error:
        assert error.code == expected, f"unexpected HTTP status {error.code}"
        error.close()
        return None
