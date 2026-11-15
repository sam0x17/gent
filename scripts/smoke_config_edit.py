#!/usr/bin/env python3
"""Exercise config editing through a PTY, isolated profiles and a real daemon.

Python 3.11+. No model or service calls. Removes only its disposable state.
Run: python3 scripts/smoke_config_edit.py target/debug/gent
"""

import errno
import json
import os
import pty
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

EDITOR = r"""
import json, os, subprocess, sys
from pathlib import Path
assert os.isatty(0) and os.isatty(1)
path = Path(sys.argv[-1])
assert path.stat().st_mode & 0o777 == 0o600
assert path.parent.stat().st_mode & 0o777 == 0o700
Path(os.environ["EDIT_RECEIPT"]).write_text(json.dumps({
    "arguments": sys.argv[1:-1], "path": str(path)
}))
action = os.environ.get("EDIT_ACTION", "edit")
if action == "fail":
    sys.exit(19)
if action == "noop":
    sys.exit(0)
text = path.read_text() + "\n# exact editor formatting\n[editor_preference]\ncolor = 'blue'\n"
if action == "invalid":
    text = "secret = 'DO_NOT_ECHO_THIS_VALUE\n"
if action in ("concurrent", "switch"):
    command = json.loads(os.environ["EDIT_CONCURRENT"])
    subprocess.run(command, check=True, capture_output=True)
if action == "atomic":
    replacement = path.with_suffix(".replacement")
    replacement.write_text(text)
    replacement.chmod(0o600)
    replacement.replace(path)
else:
    path.write_text(text)
"""


def terminal(command, env):
    master, slave = pty.openpty()
    process = None
    output = bytearray()
    try:
        process = subprocess.Popen(
            command,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            start_new_session=True,
        )
        os.close(slave)
        slave = None
        deadline = time.monotonic() + 30
        while True:
            if time.monotonic() > deadline:
                raise AssertionError("terminal command timed out")
            if select.select([master], [], [], 0.05)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                output.extend(chunk)
            elif process.poll() is not None:
                break
        return process.wait(timeout=5), output.decode()
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        os.close(master)
        if slave is not None:
            os.close(slave)


class Fixture:
    def __init__(self, binary, root):
        self.binary, self.root = binary, root
        self.home = root / "state"
        self.base = [binary, "--home", str(self.home)]
        self.receipt = root / "editor-receipt.json"
        editor = root / "editor with spaces.py"
        editor.write_text(EDITOR)
        self.editor = shlex.join([sys.executable, str(editor)])
        self.env = dict(os.environ, EDIT_RECEIPT=str(self.receipt))
        self.env.pop("VISUAL", None)
        self.env.pop("EDITOR", None)
        self.cli("cluster", "new", "proof", "--local")
        self.path = self.home / "config.toml"
        self.original = self.path.read_bytes()

    def cli(self, *args):
        result = subprocess.run(
            self.base + ["--json", *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
        return json.loads(result.stdout)

    def edit(self, action="edit", args=(), context=None, **env):
        self.receipt.unlink(missing_ok=True)
        selection = ["--cluster", context] if context else []
        return terminal(
            self.base + selection + ["config", "edit", *args],
            dict(self.env, EDIT_ACTION=action, **env),
        )

    def reset(self):
        self.path.write_bytes(self.original)

    def saved(self, result, expected):
        code, output = result
        assert code == 0, output
        receipt = json.loads(self.receipt.read_text())
        assert receipt["arguments"] == expected, receipt
        assert not Path(receipt["path"]).parent.exists()
        assert self.path.read_bytes() == self.original + (
            b"\n# exact editor formatting\n[editor_preference]\ncolor = 'blue'\n"
        )
        assert self.path.stat().st_mode & 0o777 == 0o600


def exercise(f):
    checks = []
    literal = ["$HOME", "`touch should-not-exist`", ";", "$(id)"]
    f.saved(
        f.edit(VISUAL=f.editor + " " + shlex.join(literal), EDITOR="missing-editor"),
        literal,
    )
    checks.append("VISUAL precedence, quoted paths and literal arguments")
    f.reset()
    f.saved(f.edit(VISUAL=" ", EDITOR=f.editor), [])
    checks.append("EDITOR fallback")
    f.reset()
    f.saved(
        f.edit(
            "atomic",
            args=["--editor", f.editor + " explicit"],
            VISUAL="missing-editor",
            EDITOR="missing-editor",
        ),
        ["explicit"],
    )
    checks.append("explicit override and atomic editor replacement")
    f.reset()
    stamp = f.path.stat()
    code, output = f.edit("noop", EDITOR=f.editor)
    assert code == 0 and "No configuration changes" in output, output
    assert f.path.stat().st_ino == stamp.st_ino
    assert f.path.stat().st_mtime_ns == stamp.st_mtime_ns
    checks.append("no-op leaves original inode and modification time")
    for action in ("fail", "invalid"):
        code, output = f.edit(action, EDITOR=f.editor)
        assert code != 0 and "draft retained" in output, output
        assert "DO_NOT_ECHO_THIS_VALUE" not in output
        receipt = json.loads(f.receipt.read_text())
        assert Path(receipt["path"]).exists()
        assert f.path.read_bytes() == f.original
    code, output = f.edit(EDITOR="/no/such/editor")
    assert code != 0 and "draft retained" in output, output
    checks.append("failed launch, failed exit and invalid TOML retain private draft")
    drafts = sorted(f.home.glob(".config-edit-*"))
    code, output = f.edit(args=["--json"], EDITOR=f.editor)
    assert code != 0 and "interactive terminal without --json" in output
    assert not f.receipt.exists()
    result = subprocess.run(
        f.base + ["config", "edit"],
        check=False,
        capture_output=True,
        text=True,
        env=dict(f.env, EDITOR=f.editor),
        timeout=10,
    )
    assert result.returncode != 0 and "interactive terminal" in result.stderr
    assert not f.receipt.exists() and sorted(f.home.glob(".config-edit-*")) == drafts
    checks.append("headless and JSON reject before editor or draft creation")
    f.path.write_text("secret = 'DO_NOT_ECHO_THIS_VALUE\n")
    code, output = f.edit(EDITOR=f.editor)
    assert code != 0 and "cannot resolve the cluster profile" in output, output
    assert "DO_NOT_ECHO_THIS_VALUE" not in output and not f.receipt.exists()
    f.reset()
    checks.append("invalid original refuses without echoing TOML values")

    # Selection stays bound to the physical profile while an editor is open.
    peer = f.root / "peer"
    subprocess.run(
        [f.binary, "--home", str(peer), "cluster", "new", "peer", "--local"],
        check=True,
        capture_output=True,
        timeout=15,
    )
    own_id = tomllib.loads(f.path.read_text())["cluster"]["id"]
    peer_path = peer / "config.toml"
    peer_original = peer_path.read_bytes()
    f.cli("cluster", "add", str(peer))
    code, output = f.edit(context="peer", EDITOR=f.editor)
    assert code == 0, output
    assert "editor_preference" in peer_path.read_text()
    peer_path.write_bytes(peer_original)
    f.cli("cluster", "switch", "peer")
    code, output = f.edit(
        "switch",
        EDITOR=f.editor,
        EDIT_CONCURRENT=json.dumps(f.base + ["cluster", "switch", own_id]),
    )
    assert code == 0, output
    assert "editor_preference" in peer_path.read_text()
    assert "editor_preference" not in f.path.read_text()
    checks.append("explicit and active profiles stay pinned across context switch")
    f.reset()

    # Only apply publishes shared settings. A real signed mutation during the
    # editor also exercises the daemon's projection lock and stale-save check.
    with (f.root / "daemon.log").open("w+") as log:
        daemon = subprocess.Popen(f.base + ["daemon", "run"], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while True:
                assert daemon.poll() is None, "daemon exited"
                try:
                    before = f.cli("cluster")
                    break
                except subprocess.CalledProcessError:
                    assert time.monotonic() < deadline, "daemon did not become ready"
                    time.sleep(0.05)
            code, output = f.edit(
                "concurrent",
                EDITOR=f.editor,
                EDIT_CONCURRENT=json.dumps(f.base + ["node", "name", "set", "newer"]),
            )
            assert code != 0 and "changed while the editor was open" in output, output
            assert "draft retained" in output
            assert f.cli("node", "name") == "newer"
            assert "editor_preference" not in f.path.read_text()
            checks.append("concurrent signed daemon projection wins; draft retained")

            # Give the editor a controlled shared-name change, keeping the
            # native command and validation path identical to earlier runs.
            editor = f.root / "rename.py"
            editor.write_text(
                "import pathlib, sys\n"
                "p = pathlib.Path(sys.argv[-1])\n"
                "p.write_text(p.read_text().replace('name = \"proof\"', 'name = \"edited\"'))\n"
            )
            before = f.cli("cluster")
            code, output = f.edit(EDITOR=shlex.join([sys.executable, str(editor)]))
            assert code == 0 and "config apply" in output, output
            assert tomllib.loads(f.path.read_text())["cluster"]["name"] == "edited"
            assert f.cli("cluster")["cluster"] == before["cluster"]
            applied = f.cli("config", "apply")
            assert applied["state"] == "applied", applied
            after = f.cli("cluster")
            assert after["cluster"]["name"] == "edited", after
            checks.append("save leaves signed state unchanged until explicit apply")
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
    return checks


def main():
    binary = str(
        Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/gent").resolve()
    )
    with tempfile.TemporaryDirectory(prefix="gent-edit-", dir="/tmp") as directory:
        checks = exercise(Fixture(binary, Path(directory).resolve()))
    print(json.dumps({"passed": True, "checks": checks}, indent=2))


if __name__ == "__main__":
    main()
