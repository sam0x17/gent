"""Run in a logged-in Mac terminal to inspect one local notification from the built tray."""
import json
from pathlib import Path
import select
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]


def build_tray():
    build = subprocess.run(
        ["cargo", "build", "--locked", "-p", "gent-link", "--message-format=json-render-diagnostics"],
        cwd=ROOT, stdout=subprocess.PIPE, check=True,
    )
    for line in build.stdout.splitlines():
        record = json.loads(line)
        if record["reason"] == "build-script-executed":
            executable = Path(record["out_dir"]) / "Gent.app/Contents/MacOS/GentDesktop"
            if executable.is_file():
                subprocess.run(["/usr/bin/codesign", "--verify", "--strict",
                                "-R=identifier link.gent.notifications", executable.parents[2]], check=True)
                return executable
    raise RuntimeError("Cargo did not produce the Gent tray bundle")


def deliver(tray, notice_id):
    attempt = str(uuid.uuid4())
    message = {"id": notice_id, "attempt": attempt, "title": "Gent local sender check",
               "body": f"Local fixture {notice_id[:8]}"}
    tray.stdin.write(json.dumps({"notification": message}).encode() + b"\n")
    deadline = time.monotonic() + 135
    while time.monotonic() < deadline:
        if not select.select([tray.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
            break
        line = tray.stdout.readline()
        if not line:
            raise RuntimeError("The tray exited. Run this from a graphical login session.")
        if line.startswith(b"{"):
            reply = json.loads(line)
            if reply.get("op") == "notification_result" and reply.get("attempt") == attempt:
                return reply["accepted"]
    raise RuntimeError("No matching native acknowledgment before the deadline")


def main():
    if sys.platform != "darwin":
        sys.exit("Run on macOS.")
    executable = build_tray()
    notice_id = str(uuid.uuid4())
    # Stand in for the supervisor on both pipes. The account watcher and daemon never start.
    with subprocess.Popen([executable, ROOT / "assets/branding/inkling-512.png", "tray"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0) as tray:
        try:
            print("Allow Gent notifications if prompted.", flush=True)
            if not deliver(tray, notice_id) and not deliver(tray, notice_id):
                sys.exit("Gent did not receive native acceptance. Check Notifications > Gent.")
            print(f"Native acceptance for {notice_id[:8]}. Inspect the sender name and icon.")
            input("Leave the entry in Notification Center and press Return to replay it. ")
            if not deliver(tray, notice_id):
                sys.exit("The replay was not acknowledged.")
            print("Replay acknowledged. Check that the fixture still has one entry and report its sender and icon.")
        finally:
            tray.stdin.close()
            try:
                tray.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tray.kill()


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        sys.exit(str(error))
