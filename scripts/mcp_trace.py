"""Transparent MCP tracing and response parsing for native host fixtures."""

import fcntl
import json
import os
import subprocess
import sys
import threading


def proxy(command, trace):
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def pump(source, destination, direction):
        for line in iter(source.readline, b""):
            event = {
                "pid": os.getpid(),
                "direction": direction,
                "frame": json.loads(line),
            }
            with trace.open("a") as log:
                fcntl.flock(log, fcntl.LOCK_EX)
                log.write(json.dumps(event) + "\n")
            destination.write(line)
            destination.flush()
        if direction == "request":
            destination.close()

    outgoing = threading.Thread(
        target=pump, args=(process.stdout, sys.stdout.buffer, "response")
    )
    outgoing.start()
    pump(sys.stdin.buffer, process.stdin, "request")
    outgoing.join()
    return process.wait()


def responses(trace):
    calls, values = {}, []
    if not trace.exists():
        return values
    for line in trace.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        frame = event["frame"]
        key = (event["pid"], frame.get("id"))
        if event["direction"] == "request" and frame.get("method") == "tools/call":
            calls[key] = frame["params"]
        if event["direction"] == "response" and key in calls:
            result = frame.get("result", {})
            assert not frame.get("error") and not result.get("isError"), frame
            value = json.loads(result["content"][0]["text"])
            values.append((calls[key], value))
    return values
