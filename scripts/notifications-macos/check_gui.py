"""Run in a logged-in Mac terminal to inspect one local notification from the built tray."""
import argparse
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]


def build_tray():
    build = subprocess.run(
        ["cargo", "build", "--locked", "-p", "gent-link", "--message-format=json-render-diagnostics"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if build.returncode:
        raise RuntimeError(f"stage=build_failed status={build.returncode}")
    for line in build.stdout.splitlines():
        record = json.loads(line)
        if record["reason"] == "build-script-executed":
            executable = Path(record["out_dir"]) / "Gent.app/Contents/MacOS/GentDesktop"
            if executable.is_file():
                subprocess.run(["/usr/bin/codesign", "--verify", "--strict",
                                "-R=identifier link.gent.notifications", executable.parents[2]], check=True)
                return executable
    raise RuntimeError("Cargo did not produce the Gent tray bundle")


STAGES = {"no_gui", "lookup", "registration_unavailable", "settings_requested", "settings_received",
          "permission_requested", "permission_pending", "permission_error", "permission_granted", "permission_not_granted",
          "already_delivered", "submission_requested", "submission_error", "submitted"}
DOMAINS = {"UNErrorDomain", "NSPOSIXErrorDomain", "NSCocoaErrorDomain", "NSOSStatusErrorDomain",
           "RBSRequestErrorDomain", "RBSServiceErrorDomain", "NSMachErrorDomain",
           "NSExecutableErrorDomain", "FBSOpenApplicationServiceErrorDomain", "other"}


def diagnostic(reply):
    stage = reply.get("stage")
    if stage not in STAGES:
        return None
    fields = [f"stage={stage}"]
    allowed = {"preferred": {"same", "other", "missing"}, "domain": DOMAINS, "underlying_domain": DOMAINS,
               "authorization": {"not_determined", "denied", "authorized", "provisional", "unknown"}}
    for key, choices in allowed.items():
        if reply.get(key) in choices:
            fields.append(f"{key}={reply[key]}")
    for key in ("code", "underlying_code"):
        if type(reply.get(key)) is int:
            fields.append(f"{key}={reply[key]}")
    if type(reply.get("translocated")) is bool:
        fields.append(f"translocated={reply['translocated']}")
    print(" ".join(fields), flush=True)
    return stage


def line_before(stream, child, deadline):
    while time.monotonic() < deadline:
        if select.select([stream], [], [], min(0.25, max(0, deadline - time.monotonic())))[0]:
            line = stream.readline()
            if line:
                return line
            raise RuntimeError("stage=gui_stream_closed")
        if child.poll() is not None:
            raise RuntimeError(f"stage=launcher_exit status={child.returncode}")
    raise RuntimeError("stage=reply_timeout")


@contextmanager
def tray(executable, launch):
    args = [ROOT / "assets/branding/inkling-512.png", "tray"]
    with ExitStack() as cleanup:
        errors = cleanup.enter_context(tempfile.TemporaryFile())
        gui_errors = cleanup.enter_context(tempfile.NamedTemporaryFile())
        if launch == "direct":
            child = subprocess.Popen([executable, *args, "--notification-diagnostics"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=gui_errors, bufsize=0)
            writer, reader = child.stdin, child.stdout
        else:
            pipes = Path(cleanup.enter_context(tempfile.TemporaryDirectory()))
            input_path, output_path = pipes / "in", pipes / "out"
            os.mkfifo(input_path, 0o600)
            os.mkfifo(output_path, 0o600)
            def endpoint(path, flags, mode):
                return cleanup.enter_context(os.fdopen(os.open(path, flags | os.O_NONBLOCK), mode, buffering=0))
            input_guard = endpoint(input_path, os.O_RDONLY, "rb")
            writer = endpoint(input_path, os.O_WRONLY, "wb")
            reader = endpoint(output_path, os.O_RDONLY, "rb")
            output_guard = endpoint(output_path, os.O_WRONLY, "wb")
            child = subprocess.Popen(["/usr/bin/open", "-n", "-g", "-W", "--stdin", input_path,
                                      "--stdout", output_path, "--stderr", gui_errors.name, "-a", executable.parents[2],
                                      "--args", *args, "--launch-services", "--notification-diagnostics"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            first = line_before(reader, child, time.monotonic() + 30)
            if first != b"gent-desktop-ready\n":
                if first.startswith(b"{"):
                    diagnostic(json.loads(first))
                raise RuntimeError("stage=handshake_failed")
            if launch == "ls":
                input_guard.close()
                output_guard.close()
            print("stage=gui_connected", flush=True)
            yield writer, reader, child
        finally:
            writer.close()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            reader.close()
            # Never print raw OS messages, file paths, userInfo, or notification contents.
            for source, log in [("launcher", errors), ("gui", gui_errors)]:
                log.seek(0)
                data = log.read(65536)
                for domain, code in re.findall(rb"Domain=([A-Za-z0-9.]+) Code=(-?\d+)", data):
                    name = domain.decode("ascii")
                    if name in DOMAINS:
                        print(f"stage=system_error source={source} domain={name} code={int(code)}", flush=True)
                for line in data.splitlines():
                    if b"sandbox_extension_issue_file_to_process" in line and b"fail" in line.lower():
                        errno = " errno=1" if b"EPERM" in line or b"operation not permitted" in line.lower() else ""
                        print(f"stage=sandbox_extension_error source={source}{errno}", flush=True)


def deliver(connection, notice_id):
    writer, reader, child = connection
    attempt = str(uuid.uuid4())
    message = {"id": notice_id, "attempt": attempt, "title": "Gent local sender check",
               "body": f"Local fixture {notice_id[:8]}", "diagnose": True}
    writer.write(json.dumps({"notification": message}).encode() + b"\n")
    deadline = time.monotonic() + 135
    stage = None
    while True:
        line = line_before(reader, child, deadline)
        if not line.startswith(b"{"):
            continue
        reply = json.loads(line)
        if reply.get("op") == "notification_diagnostic" and reply.get("attempt") in (None, attempt):
            stage = diagnostic(reply)
        if reply.get("op") == "notification_result" and reply.get("attempt") == attempt:
            return reply.get("accepted") is True, stage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launch", choices=["ls", "direct", "both"], default="ls")
    parser.add_argument("--location", choices=["applications", "build"], default="applications")
    options = parser.parse_args()
    if sys.platform != "darwin":
        sys.exit("Run on macOS.")
    executable = build_tray()
    with ExitStack() as cleanup:
        if options.location == "applications":
            applications = Path.home() / "Applications"
            try:
                applications.mkdir()
            except FileExistsError:
                pass
            else:
                applications.chmod(0o755)
            root = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="Gent QA ", dir=applications)))
            app = root / "Gent.app"
            shutil.copytree(executable.parents[2], app)
            executable = app / "Contents/MacOS/GentDesktop"
            # Match the installed bundle's modes even from a private build/cache.
            for path in app.rglob("*"):
                path.chmod(0o755 if path.is_dir() or path == executable else 0o644)
            app.chmod(0o755)
            root.chmod(0o755)
            subprocess.run(["/usr/bin/codesign", "--verify", "--strict",
                            "-R=identifier link.gent.notifications", app], check=True)
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        failures = 0
        for launch in (["ls", "direct"] if options.launch == "both" else [options.launch]):
            print(f"launch={launch} location={options.location} signature=verified sha256={digest}", flush=True)
            try:
                with tray(executable, launch) as connection:
                    check_notice(connection)
            except (BrokenPipeError, RuntimeError) as error:
                failures += 1
                print(str(error), flush=True)
        if failures:
            sys.exit(1)


def check_notice(connection):
    notice_id = str(uuid.uuid4())
    accepted, stage = deliver(connection, notice_id)
    deadline = time.monotonic() + 135
    while not accepted and stage == "permission_pending" and time.monotonic() < deadline:
        time.sleep(1)
        accepted, stage = deliver(connection, notice_id)
    if not accepted and stage == "permission_granted":
        accepted, stage = deliver(connection, notice_id)
    if not accepted:
        raise RuntimeError("Native acceptance pending. Report the stage lines above.")
    print("Inspect the sender and icon above Gent local sender check.")
    input("Leave the entry in Notification Center and press Return to replay it. ")
    accepted, stage = deliver(connection, notice_id)
    if not accepted or stage != "already_delivered":
        raise RuntimeError("Replay did not find the retained entry. Report the stage lines above.")
    print("Replay found the retained entry. Report the sender, icon and visible entry count.")


if __name__ == "__main__":
    try:
        main()
    except (BrokenPipeError, RuntimeError) as error:
        sys.exit(str(error))
