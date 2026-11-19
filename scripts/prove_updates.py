#!/usr/bin/env python3
"""Exercise real Cargo updates in disposable Git, node and installation state.

Never contacts a release service or a live node. Requires --features test-updates
in the fixture builds; these binaries cannot be accepted by production Gent.
"""

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from mcp_client import Client
from mcp_fixtures import PNG


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, default=Path(__file__).resolve().parent.parent
    )
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument(
        "--seed-cache", type=Path,
        help="Copy an existing release target to speed up the fixture's initial build",
    )
    args = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="gent-upd-") as directory:
        root = Path(directory).resolve()
        repo, install, home = root / "repo", root / "cargo", root / "node"
        repo.mkdir()
        source = args.source.resolve()
        files = subprocess.check_output(
            [
                "git",
                "-C",
                str(source),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ]
        ).split(b"\0")
        for entry in files:
            if entry:
                relative = Path(os.fsdecode(entry))
                if (source / relative).is_file():
                    (repo / relative).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source / relative, repo / relative)

        def git(*argv):
            return subprocess.check_output(
                ["git", "-C", str(repo), *argv], stderr=subprocess.DEVNULL, text=True
            ).strip()

        git("init", "-q")
        for setting in ("user.name", "user.email"):
            git(
                "config",
                setting,
                subprocess.check_output(
                    ["git", "-C", str(source), "config", setting], text=True
                ).strip(),
            )
        git("add", ".")
        git("commit", "-qm", "Updater proof fixture A")
        a = git("rev-parse", "HEAD")
        daemon_source = repo / "crates/gent-daemon/src/lib.rs"
        daemon_source.write_text(
            daemon_source.read_text().replace(
                '"Gent daemon listening at {}"',
                '"Gent updater proof B daemon listening at {}"',
            )
        )
        git("add", ".")
        git("commit", "-qm", "Updater proof fixture B")
        b = git("rev-parse", "HEAD")
        git("commit", "--allow-empty", "-qm", "Updater proof fixture C")
        c = git("rev-parse", "HEAD")
        git("commit", "--allow-empty", "-qm", "Updater proof fixture D")
        d = git("rev-parse", "HEAD")
        with (repo / "crates/gent-link/src/main.rs").open("a") as file:
            file.write('\ncompile_error!("intentional updater build failure");\n')
        git("add", ".")
        git("commit", "-qm", "Updater proof broken fixture")
        broken = git("rev-parse", "HEAD")
        git("tag", "stable", a)
        env = dict(
            os.environ,
            GENT_TEST_UPDATE_ROOT=str(install),
            GENT_TEST_UPDATE_REPOSITORY=repo.as_uri(),
            GENT_TEST_UPDATE_INTERVAL="2",
            GENT_TEST_UPDATE_FAIL_COMMIT=c,
            GENT_TEST_UPDATE_NOTIFICATIONS=str(root / "notifications"),
            CARGO_TARGET_DIR=str(args.cache.resolve() / a),
            CARGO_BUILD_JOBS="4",
            CARGO_NET_GIT_FETCH_WITH_CLI="true",
        )
        # MCP helper processes inherit these test-only variables too.
        os.environ.update(env)
        updates = install / ".gent-updates"
        updates.mkdir(parents=True)
        (updates / "target").symlink_to(args.cache.resolve(), target_is_directory=True)
        binary = install / "bin/gent"
        base = [str(binary), "--home", str(home)]

        def cli(*argv, check=True):
            return subprocess.run(
                base + ["--json", *argv],
                env=env,
                check=check,
                capture_output=True,
                text=True,
                timeout=600 if argv[:2] == ("update", "install") else 60,
            )

        def status():
            path = updates / "status.json"
            return json.loads(path.read_text()) if path.exists() else {}

        def wait(check, label, seconds=600):
            deadline = time.monotonic() + seconds
            while not check():
                assert daemon is None or daemon.poll() is None, (
                    label,
                    (root / "daemon.log").read_text(),
                )
                if time.monotonic() > deadline:
                    raise AssertionError(
                        (
                            label,
                            status(),
                            (updates / "build.log").read_text()[-3000:]
                            if (updates / "build.log").exists()
                            else "",
                        )
                    )
                time.sleep(0.05)

        def tag(commit):
            git("tag", "-f", "stable", commit)

        def revision():
            return json.loads(cli("version").stdout)["commit"]

        def phase(value):
            return status().get("phase") == value

        def notifications():
            path = root / "notifications"
            return path.read_text().splitlines() if path.exists() else []

        def unchanged():
            assert revision() == a
            assert not (updates / "pending.json").exists()
            assert notifications() == []

        daemon = None
        clients = []
        try:
            with (root / "initial-build.log").open("w") as log:
                if args.seed_cache:
                    shutil.copytree(args.seed_cache.resolve(), args.cache.resolve() / a)
                    subprocess.run(
                        [
                            "cargo", "clean", "--manifest-path", str(repo / "Cargo.toml"),
                            "--locked", "--release", "-p", "gent-link", "-p", "gent-daemon",
                            "-p", "gent-crypto", "-p", "gent-protocol",
                        ],
                        env=env, stdout=log, stderr=log, check=True, timeout=120,
                    )
                initial_started = time.monotonic()
                result = subprocess.run(
                    [
                        "cargo",
                        "install",
                        "--git",
                        repo.as_uri(),
                        "--rev",
                        a,
                        "--locked",
                        "--root",
                        str(install),
                        "--features",
                        "test-updates",
                        "gent-link",
                    ],
                    env=env,
                    stdout=log,
                    stderr=log,
                    timeout=1200,
                    check=False,
                )
                assert result.returncode == 0, (root / "initial-build.log").read_text()[
                    -6000:
                ]
                print(
                    f"Initial fixture build: {time.monotonic() - initial_started:.1f}s",
                    flush=True,
                )
            assert revision() == a
            initial_build = json.loads(cli("version").stdout)
            assert initial_build["dirty"] is False
            initial_binary = root / "initial-gent"
            shutil.copy2(binary, initial_binary)

            def dependency_artifacts(target):
                return {
                    str(path.relative_to(target)): (
                        path.stat().st_size, path.stat().st_mtime_ns
                    )
                    for path in (target / "release").rglob("*.rlib")
                    if not path.name.startswith("libgent_")
                }

            dependencies = dependency_artifacts(args.cache.resolve() / a)
            assert dependencies, "initial release did not populate the dependency cache"
            cli("cluster", "new", "update-proof", "--local")
            cli("update", "disable")
            with (root / "daemon.log").open("w") as log:
                daemon = subprocess.Popen(
                    base + ["daemon", "run"], env=env, stdout=log, stderr=log
                )
            wait(
                lambda: cli("daemon", "status", check=False).returncode == 0,
                "initial daemon startup",
                15,
            )
            pid = daemon.pid
            time.sleep(3)
            assert not (updates / "status.json").exists(), (
                "disabled updater performed a check"
            )
            cli("update", "enable")
            wait(lambda: phase("current"), "current version check")
            assert not (updates / "build.log").exists(), "current version invoked cargo"
            assert notifications() == []
            print("PASS disabled checks and same-version install avoidance", flush=True)
            tag(broken)
            wait(lambda: phase("failed"), "intentional Cargo failure")
            unchanged()
            print(
                "PASS failed build preserves executable and running daemon", flush=True
            )
            tag(b)
            wait(
                lambda: phase("building") and status().get("blessed_commit") == b,
                "build B",
            )
            cli("update", "disable")
            wait(lambda: phase("disabled"), "disable during build")
            unchanged()
            print("PASS disabling during build prevents publication", flush=True)
            cli("update", "enable")
            wait(lambda: phase("building"), "second build B")
            tag(a)
            wait(
                lambda: (
                    phase("failed")
                    or (phase("current") and status().get("blessed_commit") == a)
                ),
                "stable moved during build",
            )
            unchanged()
            print("PASS moved stable tag prevents stale publication", flush=True)
            wait(lambda: phase("current"), "old stable check")
            for name in ("sender", "receiver"):
                client = Client(
                    base
                    + [
                        "mcp",
                        "serve",
                        "--binding",
                        str(home / "bindings" / (name + ".key")),
                    ]
                )
                clients.append(client)
                client.call("gent_register", {"name": name, "provider": "update-proof"})
            sender, receiver = clients
            identity = receiver.call("gent_identity")[0]["agent"]["id"]
            attempt = {
                "recipient": identity,
                "request_id": sender.request_id(),
                "text": "pending during update",
                "files": [
                    {"name": "pixel.png", "media_type": "image/png", "data_base64": PNG}
                ],
            }
            sent = sender.call("gent_send_non_blocking", attempt)[0]
            tag(b)
            wait(lambda: phase("building"), "successful build B")
            during = []
            build_deadline = time.monotonic() + 600
            while phase("building"):
                assert time.monotonic() < build_deadline, "build did not finish"
                if len(during) < 16:
                    during.append(
                        sender.call(
                            "gent_send_non_blocking",
                            {
                                "recipient": identity,
                                "request_id": sender.request_id(),
                                "text": "sent while compiling",
                            },
                        )[0]
                    )
                assert receiver.call("gent_identity")[0]["agent"]["id"] == identity
                assert receiver.call("gent_inbox")[0]
                time.sleep(0.25)
            wait(
                lambda: (
                    revision() == b
                    and phase("current")
                    and not (updates / "pending.json").exists()
                ),
                "B activation",
            )
            assert daemon.pid == pid and daemon.poll() is None
            assert (
                "Gent updater proof B daemon listening"
                in (root / "daemon.log").read_text()
            )
            assert not (args.cache.resolve() / a).exists(), "legacy cache was not adopted"
            assert dependency_artifacts(args.cache.resolve() / "shared") == dependencies, (
                "third-party dependencies were rebuilt between revisions"
            )
            for line in (updates / "build.log").read_text().splitlines():
                if "Finished `release`" in line:
                    print(f"Cached update: {line.strip()}", flush=True)
            print(
                "PASS shared dependency cache, legacy adoption and changed daemon code",
                flush=True,
            )
            wait(
                lambda: notifications() == [b], "successful automatic notification", 10
            )
            # The continuity sample fits in one inbox page.
            inbox = receiver.call("gent_inbox")[0]
            assert during, "no messages sent during compilation"
            assert {m["id"] for m in inbox} == {sent["message_id"]} | {
                message["message_id"] for message in during
            }
            image = next(m for m in inbox if m["id"] == sent["message_id"])
            assert image["files"][0]["data_base64"] == PNG
            assert receiver.call("gent_identity")[0]["agent"]["id"] == identity
            assert sender.call("gent_send_non_blocking", attempt)[0]["duplicate"] is True
            reply = receiver.call(
                "gent_reply",
                {
                    "message_id": sent["message_id"],
                    "request_id": receiver.request_id(),
                    "text": "reply after restart",
                },
            )[0]
            assert sender.call("gent_inbox")[0][0]["id"] == reply["message_id"]
            print(
                "PASS atomic activation, same PID, retained MCP sessions, image bytes, replies and deduplication",
                flush=True,
            )

            # Start the verified candidate while publication still holds its
            # lock. Readiness must finish the journal after the lock is released.
            daemon.terminate()
            daemon.wait(timeout=15)
            new_build = json.loads(cli("version").stdout)
            pending = {
                "version": 1, "home": str(home), "old": initial_build, "new": new_build,
                "old_hash": hashlib.sha256(initial_binary.read_bytes()).hexdigest(),
                "new_hash": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "starting": False, "automatic": False,
            }
            with (updates / "update.lock").open("r+") as publication:
                fcntl.flock(publication, fcntl.LOCK_EX)
                (updates / "pending.json").write_text(json.dumps(pending))
                with (root / "daemon.log").open("a") as log:
                    daemon = subprocess.Popen(
                        base + ["daemon", "run"], env=env, stdout=log, stderr=log
                    )
                wait(
                    lambda: cli("daemon", "status", check=False).returncode == 0,
                    "serve during startup publication contention", 15,
                )
                assert (updates / "pending.json").exists()
            pid = daemon.pid
            wait(lambda: not (updates / "pending.json").exists(), "reconcile readiness", 15)
            assert json.loads(cli("update", "status").stdout)["running"]["commit"] == b
            assert receiver.call("gent_inbox")[0] == inbox
            print("PASS startup lock contention preserves serving and completes activation", flush=True)

            tag(c)
            wait(lambda: phase("rolled_back"), "startup rollback")
            assert revision() == b and daemon.pid == pid
            wait(
                lambda: cli("daemon", "status", check=False).returncode == 0,
                "rollback daemon readiness",
            )
            time.sleep(3)
            assert phase("rolled_back") and status()["failed_commit"] == c
            assert receiver.call("gent_inbox")[0] == inbox
            retry = cli("update", "install")
            assert json.loads(retry.stdout)["state"] == "updated"
            wait(lambda: phase("rolled_back"), "manual retry rollback")
            assert revision() == b
            assert notifications() == [b], "failed updates must not notify"
            print(
                "PASS one notification for successful automatic installation, none for current or failed releases",
                flush=True,
            )
            print(
                "PASS failed-start rollback, retry suppression, explicit retry and durable inbox",
                flush=True,
            )

            # Simulate a cargo install that changes disk without restarting the
            # daemon. A later update must not require journal.old == daemon.build.
            replacement = install / "bin/gent-manual-install"
            shutil.copy2(initial_binary, replacement)
            replacement.replace(binary)
            before = json.loads(cli("update", "status").stdout)
            assert before["cli"]["commit"] == before["installed"]["commit"] == a
            assert before["running"]["commit"] == b
            tag(d)
            wait(
                lambda: revision() == d and phase("current")
                and not (updates / "pending.json").exists(),
                "activate after a different manually installed revision",
            )
            assert daemon.pid == pid
            assert json.loads(cli("update", "status").stdout)["running"]["commit"] == d
            assert receiver.call("gent_inbox")[0] == inbox
            print("PASS differing CLI/daemon revisions activate and report the real running build", flush=True)
        finally:
            for client in clients:
                client.close()
            if daemon is not None and daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()


if __name__ == "__main__":
    main()
