#!/usr/bin/env python3
"""Check human output, JSON compatibility and terminal-only progress locally."""

import errno
import json
import os
import pty
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    os.umask(0o077)
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(
        prefix="gent-ui-", dir=os.environ.get("TMPDIR", "/tmp")
    ) as directory:
        root = Path(directory)
        cargo = root / "cargo"
        (cargo / "bin").mkdir(parents=True)
        installed = cargo / "bin/gent"
        shutil.copy2(binary, installed)
        installed.chmod(0o755)
        shim = root / "git"
        shim.write_text(
            f"#!{sys.executable}\nimport os, sys, time\ntime.sleep(0.5)\n"
            + "if os.environ.get('GENT_PROOF_SSH_ONLY') and any(v.startswith('https://') for v in sys.argv): sys.exit(1)\n"
            + 'print("'
            + "a" * 40
            + '\\trefs/tags/stable")\n'
        )
        shim.chmod(0o700)
        env = dict(
            os.environ,
            CARGO_HOME=str(cargo),
            PATH=str(root) + os.pathsep + os.environ["PATH"],
            TERM="xterm-256color",
        )
        env.pop("NO_COLOR", None)
        base = [str(installed), "--home", str(root / "state")]
        subprocess.run(
            base + ["cluster", "new", "cli-proof", "--local"],
            check=True,
            capture_output=True,
            env=env,
        )

        def run(args, terminal=False, extra=None):
            settings = dict(env, **(extra or {}))
            if not terminal:
                result = subprocess.run(
                    base + args,
                    capture_output=True,
                    env=settings,
                    text=True,
                    check=False,
                    timeout=15,
                )
                assert result.returncode == 0, result.stderr
                assert "\x1b" not in result.stdout + result.stderr
                return result.stdout
            master, slave = pty.openpty()
            process = subprocess.Popen(
                base + args,
                stdin=subprocess.DEVNULL,
                stdout=slave,
                stderr=slave,
                env=settings,
            )
            os.close(slave)
            output = bytearray()
            try:
                while True:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    output.extend(chunk)
                assert process.wait(timeout=15) == 0
            finally:
                os.close(master)
                if process.poll() is None:
                    process.kill()
                    process.wait()
            return output.decode()

        human = run(["update", "check"])
        assert "gent  Updates" in human and "Update available" in human
        assert not human.lstrip().startswith("{")
        raw = run(["update", "check", "--json"])
        verbose = run(["--verbose", "update", "check"])
        assert json.loads(raw) == json.loads(verbose)
        assert json.loads(raw)["repository"].startswith("https://")
        fallback = json.loads(
            run(["--json", "update", "check"], extra={"GENT_PROOF_SSH_ONLY": "1"})
        )
        assert fallback["repository"].startswith("ssh://")
        assert fallback["blessed_commit"] == json.loads(raw)["blessed_commit"]
        both = run(["--json", "--verbose", "update", "check"])
        assert both == raw
        animated = run(["update", "check"], terminal=True)
        assert "\x1b[2K" in animated and "Checking GitHub stable" in animated
        assert any(frame in animated for frame in "⡀⡄⡆⣆⣦⣶⣿")
        for flags in (["--json"], ["--verbose"]):
            response = run([*flags, "update", "check"], terminal=True)
            assert "\x1b" not in response
            assert json.loads(response) == json.loads(raw)
        dumb = run(["update", "check"], terminal=True, extra={"TERM": "dumb"})
        assert "\x1b" not in dumb
        no_color = run(["update", "check"], terminal=True, extra={"NO_COLOR": "1"})
        assert "\x1b[36m" not in no_color and "\x1b[1;36m" not in no_color
        assert "\x1b[2K" in no_color
        print(
            "PASS readable output, JSON/verbose equivalence, dot-block animation, pipes, TERM=dumb, NO_COLOR and HTTPS/SSH discovery"
        )


if __name__ == "__main__":
    main()
