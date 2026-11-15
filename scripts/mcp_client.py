"""Minimal JSON-RPC client shared by Gent native acceptance fixtures."""
import json
import selectors
import subprocess
import time
import uuid


class Client:
    def __init__(self, command, client_name="gent-generic-proof"):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.counter = 0
        self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": client_name, "version": "1"}})
        self.write({"jsonrpc": "2.0", "method": "notifications/initialized"})
        declared = self.rpc("tools/list", {})["result"]["tools"]
        assert "gent_register" in {tool["name"] for tool in declared}

    def write(self, payload):
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()

    def rpc(self, method, params):
        self.counter += 1
        self.write({"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params})
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if not selector.select(max(0, deadline - time.monotonic())):
                    raise AssertionError("MCP response timed out")
                line = self.process.stdout.readline()
                assert line, "MCP process closed stdout"
                response = json.loads(line)
                if response.get("id") == self.counter:
                    return response
        raise AssertionError("no matching response")

    def call(self, name, arguments=None, error=False, meta=None):
        params = {"name": name, "arguments": arguments or {}}
        if meta is not None:
            params['_meta'] = meta
        response = self.rpc("tools/call", params)
        if error:
            assert "error" in response or response.get("result", {}).get("isError"), response
            return response
        assert "error" not in response, response
        result = response["result"]
        assert not result.get("isError"), result
        return json.loads(result["content"][0]["text"]), result

    def request_id(self, meta=None):
        value, _ = self.call("gent_request_ids", meta=meta)
        request = value["request_ids"][0]
        assert str(uuid.UUID(request)) == request and uuid.UUID(request).version == 7
        return request

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.process.stdout.close()
        self.process.stderr.close()
