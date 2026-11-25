#!/usr/bin/env python3
"""Verify the channel compatibility floor using three prebuilt Gent executables."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


def prove(root, legacy, baseline, candidate):
    # Run detached copies. An installed executable can discover its installation
    # directory even when GENT_HOME points at a temporary cluster.
    binaries = []
    for name, source in [("legacy", legacy), ("baseline", baseline), ("candidate", candidate)]:
        binaries.append(shutil.copy2(source, root / name))
    legacy, baseline, candidate = binaries
    env = {"HOME": str(root), "GENT_HOME": str(root / "node"), "PATH": os.defpath}

    def run(binary, *args, probe=False):
        result = subprocess.run(
            [binary, "--json", *args], cwd=root, env=env, capture_output=True, timeout=20
        )
        if probe and result.returncode:
            return None
        result.check_returncode()
        return json.loads(result.stdout)

    @contextmanager
    def daemon(binary):
        with subprocess.Popen(
            [binary, "daemon", "run"], cwd=root, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ) as proc:
            try:
                deadline = time.monotonic() + 20
                while run(binary, "cluster", "status", probe=True) is None:
                    if proc.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError(f"{Path(binary).name} daemon failed readiness")
                    time.sleep(0.1)
                yield
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()

    def current(binary):
        return run(binary, "cluster", "channel", "get")["channel"]

    def select(binary, channel, request_id):
        return run(binary, "--request-id", request_id, "cluster", "channel", "set", channel)

    run(legacy, "cluster", "new", "bootstrap", "--local")
    with daemon(legacy):
        assert "release_channel" not in run(legacy, "cluster", "status")
    assert current(baseline) == "stable"
    with daemon(baseline):
        assert run(baseline, "cluster", "status")["release_channel"] == "stable"
    with daemon(legacy):
        assert run(legacy, "cluster", "renew")["state"] == "applied"

    beta_id = str(uuid.uuid4())
    with daemon(baseline):
        applied = select(baseline, "beta", beta_id)
        assert applied["state"] == "applied"
        assert select(baseline, "beta", beta_id)["revision"] == applied["revision"]
    assert current(candidate) == "beta"
    with daemon(candidate):
        assert run(candidate, "cluster", "status")["release_channel"] == "beta"
        assert run(candidate, "cluster", "renew")["state"] == "applied"

    # Exercise binary rollback while beta is active, then roll the selection
    # back to stable. Replaying the old request must preserve that decision.
    with daemon(baseline):
        assert run(baseline, "cluster", "status")["release_channel"] == "beta"
        assert select(baseline, "stable", str(uuid.uuid4()))["state"] == "applied"
        assert select(baseline, "beta", beta_id)["revision"] == applied["revision"]
    for binary in [candidate, baseline]:
        assert current(binary) == "stable"
        with daemon(binary):
            assert run(binary, "cluster", "status")["release_channel"] == "stable"
    print("Passed legacy bootstrap, beta activation, binary rollback and return to stable.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy", type=Path, required=True, help="pre-channel Gent")
    parser.add_argument("--baseline", type=Path, required=True, help="first channel-capable Gent")
    parser.add_argument("--candidate", type=Path, required=True, help="newer channel-capable Gent")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="gent-channel-") as directory:
        prove(Path(directory), args.legacy, args.baseline, args.candidate)


if __name__ == "__main__":
    main()
