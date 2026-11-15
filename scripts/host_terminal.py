"""PTY lifecycle helper for isolated native-host acceptance fixtures."""

import errno
import fcntl
import os
import pty
import re
import select
import signal
import struct
import termios
import time


class Terminal:
    def __init__(self, command, work, path):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(work)
            os.execvpe(
                command[0],
                command,
                dict(os.environ, TERM="xterm-256color", DISABLE_AUTOUPDATER="1"),
            )
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
        self.log = path.open("ab")
        self.text = ""
        self.accepted_test_folder = False
        self.trust_ready_at = None
        self.trust_selected_at = None

    def drain(self, seconds=0.1):
        if select.select([self.fd], [], [], seconds)[0]:
            try:
                data = os.read(self.fd, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    raise AssertionError(
                        "host terminal exited; inspect terminal.raw"
                    ) from error
                raise
            assert data, "host terminal exited"
            self.log.write(data)
            self.log.flush()
            # Answer the terminal cursor query without inventing user input.
            if b"\x1b[6n" in data:
                os.write(self.fd, b"\x1b[1;1R")
            self.text += re.sub(
                r"\x1b\[[0-?]*[ -/]*[@-~]", "", data.decode(errors="replace")
            )
            if not self.accepted_test_folder and "Yes,Itrustthisfolder" in re.sub(
                r"\s+", "", self.text
            ):
                self.accepted_test_folder = True
                # Wait for startup rendering/terminal negotiation to settle.
                self.trust_ready_at = time.monotonic() + 1
        if self.trust_ready_at is not None and time.monotonic() >= self.trust_ready_at:
            os.write(self.fd, b"\x1b[B")
            self.trust_ready_at = None
            self.trust_selected_at = time.monotonic() + 1
        if (
            self.trust_selected_at is not None
            and time.monotonic() >= self.trust_selected_at
        ):
            os.write(self.fd, b"\r")
            self.trust_selected_at = None

    def send(self, text):
        os.write(self.fd, b"\x1b[200~" + text.encode() + b"\x1b[201~")
        self.drain(0.2)
        os.write(self.fd, b"\r")

    def settle(self):
        # Slash-command rendering differs by host/version. Identity assertions
        # below verify the transition, rather than interpreting UI copy.
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            self.drain()

    def close(self):
        def reaped(timeout):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if os.waitpid(self.pid, os.WNOHANG)[0]:
                    return True
                if select.select([self.fd], [], [], 0.05)[0]:
                    try:
                        data = os.read(self.fd, 65536)
                        self.log.write(data)
                        self.log.flush()
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
            return False

        try:
            if reaped(0.1):
                return
            # Let the host close its MCP children before terminating its group.
            self.send("/exit")
            if reaped(5):
                return
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(self.pid, sig)
                except ProcessLookupError:
                    pass
                if reaped(5):
                    return
            raise AssertionError(f"host process {self.pid} did not exit after SIGKILL")
        finally:
            os.close(self.fd)
            self.log.close()
