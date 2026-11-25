#!/usr/bin/env python3
"""Probe exact-literal continuation admission on a disposable native Claude terminal."""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID, uuid4

from host_terminal import Terminal


LITERAL = "please continue"
ENVELOPE = "GENT_FIXTURE_INTERNAL_ENVELOPE"
SENDER = """
let submitted = 0;
export function register(on) {
  on('prompt.submit', async ($, e, next) => {
    await $.ui.log('FIXTURE_SENDER ' + JSON.stringify(e), {to:'debug'});
    return next(e);
  });
  on('classic.StopFailure', async ($, e, next) => {
    if (!e.agent_id && e.error === 'unknown'
        && e.last_assistant_message?.includes('input[0].tools[0].type') && submitted < 2) {
      const text = submitted++ === 0 ? 'please continue' : 'GENT_FIXTURE_INTERNAL_ENVELOPE';
      $.clock.after(500, async () => {
        const receipt = await $.prompt.submit({text,asUser:true});
        await $.ui.log('FIXTURE_RESULT ' + JSON.stringify(receipt), {to:'debug'});
      });
    }
    return next(e);
  });
}
"""
OBSERVER = """
export function register(on) {
  on('prompt.submit', async ($, e, next) => {
    await $.ui.log('FIXTURE_ORIGIN ' + JSON.stringify(e), {to:'debug'});
    if (e.origin?.kind === 'plugin' && e.origin.name === 'sender'
        && e.text === 'GENT_FIXTURE_INTERNAL_ENVELOPE') {
      // Give the terminal a frame to render during admission, as a daemon
      // check might. A private envelope must stay hidden even on slow I/O.
      await $.process.run(['/bin/sleep','0.25']);
      return next({...e, text:'please continue'});
    }
    return next(e);
  });
  on('turn.complete', async ($, e, next) => {
    await $.ui.log('FIXTURE_END ' + JSON.stringify({
      id:e.turnId, reason:e.reason, aborted:e.isAborted}), {to:'debug'});
    return next(e);
  });
}
"""


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def classic_hook(root):
    event = json.load(sys.stdin)
    path = Path(event["transcript_path"]).resolve()
    assert path.is_relative_to(root / "config/projects")
    # The native message eventually carries provenance. Can the retained hook
    # read that same message, with this prompt_id, before admitting it?
    snapshot = rows(path)
    entry = {
        "event": event,
        "host_env": {
            key: hashlib.sha256(value.encode()).hexdigest()
            for key, value in os.environ.items() if key.startswith("CLAUDE_")
        },
        "current_user": any(
            row.get("type") == "user" and row.get("promptId") == event["prompt_id"]
            for row in snapshot
        ),
        "queue_rows": [row for row in snapshot if row["type"] == "queue-operation"],
    }
    with (root / "classic.jsonl").open("a") as out:
        out.write(json.dumps(entry) + "\n")
    print("{}")


class LoopbackProvider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        if self.path.partition("?")[0].endswith("/count_tokens"):
            status, body = 200, {"input_tokens": 4}
        else:
            status, body = 400, {"type": "error", "error": {
                "type": "invalid_request_error",
                "message": "Invalid value in input[0].tools[0].type. Supported values include function.",
            }}
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())


def plugin(root, name, module):
    directory = root / name
    (directory / ".claude-plugin").mkdir(parents=True)
    (directory / ".claude-plugin/plugin.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
    (directory / "hooks").mkdir()
    (directory / "hooks/hooks.json").write_text('{"modules":["./register.ts"]}')
    (directory / "hooks/register.ts").write_text(module)
    return directory


def log_events(debug, label):
    marker = " (to debug): FIXTURE_" + label + " "
    return [json.loads(line.partition(marker)[2])
            for line in debug.read_text().splitlines() if marker in line]


def prove(host, root):
    config, work, debug = root / "config", root / "work", root / "debug"
    config.mkdir()
    work.mkdir()
    session = str(uuid4())
    api_key = "gent-loopback-fixture"
    environment = dict(
        HOME=str(root), PATH=os.environ["PATH"], LANG="C.UTF-8", TERM="xterm-256color",
        CLAUDE_CONFIG_DIR=str(config), ANTHROPIC_API_KEY=api_key,
        HTTP_PROXY="http://127.0.0.1:1", HTTPS_PROXY="http://127.0.0.1:1", NO_PROXY="127.0.0.1",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", DISABLE_AUTOUPDATER="1",
        CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL="1",
    )
    version = subprocess.check_output([host, "--version"], env=environment, text=True).split()[0]
    (config / ".claude.json").write_text(json.dumps({
        "hasCompletedOnboarding": True, "lastOnboardingVersion": version, "theme": "dark",
        "customApiKeyResponses": {"approved": [api_key[-20:]], "rejected": []},
    }))
    hook = shlex.join([sys.executable, str(Path(__file__).resolve()), "--hook", str(root)])
    (config / "settings.json").write_text(json.dumps({"hooks": {
        key: [{"hooks": [{"type": "command", "command": hook, "onFailure": "block"}]}]
        for key in ["UserPromptSubmit", "StopFailure"]
    }}))
    with ExitStack() as cleanup:
        provider = ThreadingHTTPServer(("127.0.0.1", 0), LoopbackProvider)
        cleanup.callback(provider.server_close)
        threading.Thread(target=provider.serve_forever, daemon=True).start()
        cleanup.callback(provider.shutdown)
        environment["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{provider.server_port}"
        terminal = Terminal([
            "/usr/bin/env", "-i", *[f"{k}={v}" for k, v in environment.items()], host,
            "--setting-sources", "user", "--strict-mcp-config", "--tools", "Read",
            "--no-chrome", "--permission-mode", "dontAsk", "--model", "claude-sonnet-4-6",
            "--session-id", session, "--plugin-dir", str(plugin(root, "sender", SENDER)),
            "--plugin-dir", str(plugin(root, "observer", OBSERVER)), "--debug-file", str(debug),
        ], work, root / "terminal.raw")
        cleanup.callback(terminal.close)

        def wait(predicate, label):
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if predicate():
                    return
                terminal.drain()
            raise AssertionError("timed out waiting for " + label)

        wait(lambda: "ask on" in terminal.text or "askon" in terminal.text.replace(" ", ""),
             "the disposable terminal")
        terminal.settle()
        terminal.send(LITERAL)
        wait(lambda: len(log_events(debug, "END")) == 3, "three failed native turns")
        terminal.settle()

        human = {"kind": "composer"}
        automatic = {"kind": "plugin", "name": "sender", "asUser": True}
        origins = log_events(debug, "ORIGIN")
        assert [(e["text"], e["origin"]) for e in origins] == [
            (LITERAL, human), (LITERAL, automatic), (ENVELOPE, automatic)]
        assert [e["origin"] for e in log_events(debug, "SENDER")] == [human]
        assert all(e.keys() == {"origin", "text", "wait"} for e in origins)
        assert log_events(debug, "RESULT") == [{"text": LITERAL, "origin": automatic}] * 2
        ends = log_events(debug, "END")
        assert len({e["id"] for e in ends}) == 3
        assert all(e["reason"] == "error" and not e["aborted"] for e in ends)

        classic = rows(root / "classic.jsonl")
        inputs = [r for r in classic if r["event"]["hook_event_name"] == "UserPromptSubmit"]
        errors = [r["event"] for r in classic if r["event"]["hook_event_name"] == "StopFailure"]
        assert len(inputs) == len(errors) == 3
        assert all(e["error"] == "unknown" and "input[0].tools[0].type" in e["last_assistant_message"]
                   for e in errors)
        assert inputs[0]["host_env"] == inputs[1]["host_env"], (
            "check whether the host now identifies plugin submissions in the hook environment"
        )
        ids = []
        for entry, failure in zip(inputs, errors, strict=True):
            event = entry["event"]
            assert event["session_id"] == session and event["prompt"] == LITERAL
            assert set(event) == {"session_id", "transcript_path", "cwd", "prompt_id",
                                  "permission_mode", "hook_event_name", "prompt"}, sorted(event)
            assert not entry["current_user"], "Claude now exposes the current row at admission"
            assert failure["prompt_id"] == event["prompt_id"]
            ids.append(UUID(event["prompt_id"]))
            assert all(set(row) <= {"type", "sessionId", "timestamp", "operation", "content"}
                       for row in entry["queue_rows"])
        assert len(set(ids)) == 3
        assert set(ids).isdisjoint(UUID(e["id"]) for e in ends)
        transcript = rows(Path(inputs[0]["event"]["transcript_path"]))
        users = [row for row in transcript if row["type"] == "user"]
        assert [row["message"]["content"] for row in users] == [LITERAL] * 3
        assert [row["origin"] for row in users] == [{"kind": "human"}, automatic, automatic]
        assert [UUID(row["promptId"]) for row in users] == ids
        assert users[-1]["promptRewritten"] is True
        assert not any(row.get("attachment", {}).get("type") == "goal_status" for row in transcript)
        # Claude renders submitted text before the second plugin's rewrite.
        rendered = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", terminal.text)
        assert re.search(r"Prompt from the sender plugin\s+❯\s*" + ENVELOPE, rendered)
        print(f"Claude Code {version}: human and plugin literals have the same retained-hook "
              "body, fresh unbound prompt IDs and no readable current user row. The submitting "
              "plugin does not intercept its own input. The terminal displays the envelope "
              "before the other plugin rewrites it.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claude", default="claude")
    parser.add_argument("--hook", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.hook:
        classic_hook(args.hook)
    else:
        executable = shutil.which(args.claude)
        if not executable:
            parser.error("Claude Code executable was not found")
        with tempfile.TemporaryDirectory(prefix="gent-claude-chat-admission-") as folder:
            prove(executable, Path(folder))
