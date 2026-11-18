#!/usr/bin/env python3
"""Opt-in PTY setup proof with disposable services and host configuration.

Uses the real systemd/launchd manager and optionally an isolated native Codex
server. Makes no model calls and never changes the real host integrations.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import pty
import select
import shlex
import shutil
import subprocess
import tempfile
import time
import tomllib


def terminal(command, env, replies):
    master, slave = pty.openpty()
    output = bytearray()
    seen = []
    process = None
    try:
        process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, env=env)
        os.close(slave)
        slave = None
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            if select.select([master], [], [], .05)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                output.extend(data)
                text = output.decode(errors="replace")
                for prompt, reply in replies.items():
                    if prompt in text and prompt not in seen:
                        seen.append(prompt)
                        os.write(master, reply)
            elif process.poll() is not None:
                break
        else:
            raise AssertionError("setup prompt timed out: " + output.decode(errors="replace"))
        return process.wait(timeout=5), output.decode(errors="replace"), seen
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        if slave is not None:
            os.close(slave)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--codex", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="gent-guided-")).resolve()
    print("Private proof output: " + str(root), flush=True)
    home = root / "node"
    user = root / "user"
    user.mkdir()
    env = dict(os.environ, HOME=str(user), CODEX_HOME=str(root / "codex"),
               CLAUDE_CONFIG_DIR=str(root / "claude"), SHELL="/bin/zsh", TERM="dumb")
    env.pop("XDG_CONFIG_HOME", None)
    env.pop("ZDOTDIR", None)
    env.pop("GENT_HOME", None)
    base = [str(args.binary.resolve()), "--home", str(home)]
    prompts = ["Set up Gent for Codex CLI?", "Set up Gent for Codex in VS Code?",
               "Set up Gent for Claude Code (CLI and VS Code)?"]
    replies = {p: b"n\n" for p in prompts}
    replies.update({"Enable startup before login?": b"n\n", "Install shell PATH and completions?": b"n\n",
                    "Make all supported chats on this system discoverable by Gent?": b"n\n"})

    def cli(*args):
        result = subprocess.run(base + ["--json", *args], env=env, capture_output=True,
                                text=True, check=True, timeout=60)
        return json.loads(result.stdout)

    def run(name, arguments, answers, expected):
        code, text, seen = terminal(base + arguments, env, answers)
        (root / (name + ".log")).write_text(text)
        assert code == expected, text
        return text, seen

    native = False
    try:
        text, seen = run("fresh", ["setup", "--local", "guided-proof"], replies, 0)
        assert all(p in seen for p in prompts)
        assert text.index("Gent daemon is running.") < text.index(prompts[0])
        assert cli("daemon", "status")["daemon"]["running"]
        identity = (home / "identity.key").read_bytes()
        assert not Path(env["CODEX_HOME"]).exists() and not Path(env["CLAUDE_CONFIG_DIR"]).exists()

        # A failed native startup must not hide the remaining integration prompts.
        fakebin = root / "bin"
        fakebin.mkdir()
        fake = fakebin / "codex"
        fake.write_text("#!/bin/sh\necho 'fixture startup unavailable' >&2\nexit 9\n")
        fake.chmod(0o700)
        env["PATH"] = str(fakebin) + os.pathsep + env["PATH"]
        selected = dict(replies, **{p: b"y\n" for p in prompts})
        selected["Install shell PATH and completions?"] = b"y\n"
        text, seen = run("partial", ["setup"], selected, 3)
        assert all(p in seen for p in prompts) and "gent integration start codex" in text
        assert cli("daemon", "status")["daemon"]["running"]
        assert cli("integration", "status", "codex")["state"] == "configured"
        assert cli("integration", "status", "claude-code")["state"] == "configured"
        assert "gent shell" in (user / ".zshrc").read_text()
        assert (home / "identity.key").read_bytes() == identity

        if args.codex:
            fake.write_text("#!/bin/sh\nexec " + shlex.quote(str(args.codex.resolve())) + ' "$@"\n')
            native = True
            run("native-retry", ["setup"], selected, 0)
            assert cli("integration", "status", "codex", "--live")["runtime"]["connected"]

        snapshots = {p: p.read_bytes() for directory in (user, Path(env["CODEX_HOME"]), Path(env["CLAUDE_CONFIG_DIR"]))
                     for p in directory.rglob("*") if p.is_file() and p.suffix in (".toml", ".json", ".zshrc")}
        for name, arguments in [("no-input", ["setup", "--no-input"]),
                                ("json", ["setup", "--json"]),
                                ("verbose", ["setup", "--verbose"])]:
            text, seen = run(name, arguments, {}, 0)
            assert not seen and not any(p in text for p in prompts)
        text, seen = run("decline-existing", ["daemon", "install"], replies, 0)
        assert all(p in seen for p in prompts)
        assert all(p.read_bytes() == data for p, data in snapshots.items())
        assert (home / "identity.key").read_bytes() == identity

        cancelled = dict(replies)
        cancelled[prompts[0]] = b"\x04"
        run("interrupted", ["setup"], cancelled, 1)
        assert cli("daemon", "status")["daemon"]["running"]
        assert (home / "identity.key").read_bytes() == identity
        run("resume", ["setup"], replies, 0)
        assert not tomllib.loads((home / "config.toml").read_text())["discovery"]["enabled"]
        print("PASS: guided prompts, daemon readiness, every integration, partial failure/retry, shell hooks, cancellation, identity retention and noninteractive setup", flush=True)
    finally:
        if native:
            subprocess.run([str(args.codex.resolve()), "app-server", "daemon", "stop"],
                           env=env, check=True, capture_output=True, timeout=30)
        cli("daemon", "uninstall")
    # Retain private logs; runtime state and host configuration are disposable.
    for directory in (home, user, Path(env["CODEX_HOME"]), Path(env["CLAUDE_CONFIG_DIR"])):
        if directory.exists():
            shutil.rmtree(directory)


if __name__ == "__main__":
    main()
