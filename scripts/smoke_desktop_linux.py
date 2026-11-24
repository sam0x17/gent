#!/usr/bin/env python3
"""Run under dbus-run-session and Xvfb with GTK 3, python3-gi-cairo, AT-SPI, AyatanaAppIndicator, xdotool and a WM."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
from queue import Empty, Queue
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import uuid

from gi.repository import Gio, GLib
from desktop_fixture_browser import install_fixture_browser
from desktop_tabs_linux import exercise_enrolled_without_daemon, exercise_setup, exercise_tabs, wait_for
from mcp_client import Client


class TrayHost:
    """Receive the real indicator registration and invoke its exported D-Bus menu."""
    name = "org.kde.StatusNotifierWatcher"
    xml = """<node><interface name="org.kde.StatusNotifierWatcher">
      <method name="RegisterStatusNotifierItem"><arg type="s" direction="in"/></method>
      <property name="IsStatusNotifierHostRegistered" type="b" access="read"/>
    </interface></node>"""

    def __init__(self, desktop_socket):
        self.desktop_socket = desktop_socket
        self.registrations = Queue()
        iface = Gio.DBusNodeInfo.new_for_xml(self.xml).interfaces[0]
        acquired = threading.Event()
        # AT-SPI uses the main thread's default context. Keep its callbacks off the tray thread.
        context = GLib.MainContext.new()
        context.push_thread_default()
        try:
            self.bus = Gio.bus_get_sync(Gio.BusType.SESSION)
            self.object_id = self.bus.register_object("/StatusNotifierWatcher", iface, self.register,
                                                      lambda *_: GLib.Variant("b", True), None)
            self.owner = Gio.bus_own_name_on_connection(self.bus, self.name, Gio.BusNameOwnerFlags.DO_NOT_QUEUE,
                                                        lambda *_: acquired.set(), None)
        finally:
            context.pop_thread_default()
        self.loop = GLib.MainLoop.new(context, False)
        self.thread = threading.Thread(target=self.loop.run, daemon=True)
        self.thread.start()
        assert acquired.wait(5), "use a fresh D-Bus session for the fixture tray"

    def register(self, _, sender, path, iface, method, params, invocation):
        arg, = params.unpack()
        self.registrations.put((sender, arg) if arg.startswith("/") else (arg, "/StatusNotifierItem"))
        invocation.return_value(None)

    def call(self, target, path, iface, method, params):
        return self.bus.call_sync(target, path, iface, method, params, None,
                                  Gio.DBusCallFlags.NONE, 4000, None).unpack()

    def menu(self, state):
        try:
            target, item = self.registrations.get(timeout=12)
        except Empty:
            owner, = self.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetNameOwner", GLib.Variant("(s)", (self.name,)))
            raise AssertionError(f"No tray registration for {state!r} within 12s "
                                 f"(desktop socket present={self.desktop_socket.is_socket()}, "
                                 f"fixture owns watcher={owner == self.bus.get_unique_name()}, "
                                 f"watcher thread alive={self.thread.is_alive()})") from None
        menu, = self.call(target, item, "org.freedesktop.DBus.Properties", "Get",
                          GLib.Variant("(ss)", ("org.kde.StatusNotifierItem", "Menu")))
        def ready():
            _, layout = self.call(target, menu, "com.canonical.dbusmenu", "GetLayout",
                                  GLib.Variant("(iias)", (0, 1, ["label"])))
            items = {props["label"]: index for index, props, _ in layout[2] if "label" in props}
            return items if state in items else None

        items = wait_for(ready, "daemon status in tray menu")

        def click(label):
            self.call(target, menu, "com.canonical.dbusmenu", "Event",
                      GLib.Variant("(isvu)", (items[label], "clicked", GLib.Variant("i", 0), 0)))
        return click

    def close(self):
        Gio.bus_unown_name(self.owner)
        self.bus.unregister_object(self.object_id)
        self.loop.quit()
        self.thread.join(3)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def enroll_fixture_nodes(binary, home, created):
    """Enroll two peers over local stdio and activate a signed host mapping for one."""
    shim = home.parent / "bin"
    shim.mkdir()
    ssh = shim / "ssh"
    ssh.write_text('#!/bin/sh\nexec "$FIXTURE_GENT" --home "$FIXTURE_OWNER" cluster pairing-serve\n')
    ssh.chmod(0o700)
    def join(child):
        joined = subprocess.run(
            [binary, "--home", child, "--json", "cluster", "join", created["cluster"]["id"],
             "--via", "fixture", "--name", "fixture-" + child.name],
            env=dict(os.environ, PATH=f'{shim}:{os.environ["PATH"]}', FIXTURE_GENT=str(binary),
                     FIXTURE_OWNER=str(home)), stdout=subprocess.PIPE, check=True, timeout=30)
        return json.loads(joined.stdout)["node"]

    remote = join(home.parent / "remote")
    child = home.parent / "web"
    node = join(child)
    parent = created["node"]

    def owner(action):
        body = {"role": "owner", "credential": (home / "owner.key").read_text().strip(), "action": action}
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(15)
            sock.connect(str(home / "daemon.sock"))
            sock.sendall(json.dumps(body).encode() + b"\n")
            with sock.makefile("rb") as response:
                result = json.loads(response.readline())
        assert result["status"] == "ok", result
        return result["data"]

    prepared = owner({"op": "prepare_hosted_node", "node_id": node["id"], "home": str(child)})
    assert prepared["prepared"] and prepared["hosted_by"] == parent["id"], prepared
    signed = owner({"op": "configure", "request_id": str(uuid.uuid4()), "edit": {
        "op": "host_node", "node_id": node["id"], "parent": parent["id"]}})
    assert signed["applied"], signed
    return remote, node


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--setup-only", action="store_true", help="exercise fresh setup and enrollment with the daemon stopped")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not args.setup_only:
        subprocess.run([sys.executable, Path(__file__).with_name("dashboard_gtk.py")], check=True)
        # Each proof gets its own GTK process, accessibility bus, watcher and node home.
        with tempfile.TemporaryDirectory(prefix="gent-setup-runtime-") as runtime:
            env = dict(os.environ, XDG_RUNTIME_DIR=runtime)
            env.pop("AT_SPI_BUS_ADDRESS", None)
            subprocess.run(["dbus-run-session", "--", "xvfb-run", "-a", sys.executable,
                            __file__, "--setup-only", binary], env=env, check=True)
    with tempfile.TemporaryDirectory(prefix="gent-desk-") as folder, ExitStack() as cleanup:
        home = Path(folder) / 'node with % space'
        os.environ.update(HOME=folder, XDG_DATA_HOME=folder+"/data", XDG_CONFIG_HOME=folder+"/config",
                          XDG_CACHE_HOME=folder+"/cache")
        base = [str(binary), "--home", str(home)]
        def cli(*args, **kwargs):
            return subprocess.run(base + list(args), timeout=20, check=True, capture_output=True, **kwargs)
        def launch(*args):
            process = subprocess.Popen(base + list(args))
            cleanup.callback(stop, process)
            return process
        def visible():
            return subprocess.run(["xdotool", "search", "--onlyvisible", "--name", "^Gent Desktop$"],
                                  text=True, capture_output=True).stdout.strip()
        if args.setup_only:
            tray = TrayHost(home / "auth/desktop/desktop.sock")
            cleanup.callback(tray.close)
            setup = launch("desktop")
            exercise_setup()
            assert not (home / "config.toml").exists()
            quit_setup = tray.menu("Quit Gent Desktop")
            created = json.loads(cli("--json", "cluster", "new", "desktop-test", "--local").stdout)
            exercise_enrolled_without_daemon(created["node"])
            quit_setup("Quit Gent Desktop")
            assert setup.wait(timeout=12) == 0
            return
        browser = install_fixture_browser(Path(folder))
        created = json.loads(cli("--json", "cluster", "new", "desktop-test", "--local").stdout)
        # Stdio enrollment requires a configuration relay in the parent's snapshot.
        key = home / "fixture-relay.key"
        key.touch(mode=0o600)
        key.write_text(secrets.token_hex(32))
        with (home / "config.toml").open("a") as cfg:
            cfg.write('\n[relay]\nendpoint = "http://127.0.0.1:9"\ncredential_file = "fixture-relay.key"\n'
                      '\n[transport]\ndirect = "off"\nrelays = []\n')
        daemon = launch("daemon", "run")
        wait_for(lambda: (home/"daemon.sock").is_socket(), "daemon")
        remote, hosted = enroll_fixture_nodes(binary, home, created)
        fixture = Client(base + ["mcp", "serve", "--binding", str(home / "fixture.key")])
        cleanup.callback(fixture.close)
        agent = fixture.call("gent_register", {"name": "Fixture conversation", "provider": "generic-mcp"})[0]["agent"]
        quiet = Client(base + ["mcp", "serve", "--binding", str(home / "quiet.key")])
        cleanup.callback(quiet.close)
        quiet.call("gent_register", {"name": "A quiet chat", "provider": "generic-mcp"})
        tray = TrayHost(home / "desktop.sock")
        cleanup.callback(tray.close)
        cli("desktop", "enable")
        def close_desktop():
            if (home / "desktop.sock").exists():
                cli("desktop", "disable")
        cleanup.callback(close_desktop)
        click = tray.menu("Daemon running")
        assert not visible(), "autostart opened the window"
        app, = [p for p in (Path(folder)/"data/applications").glob("*.desktop") if p.name != browser]
        entry, = (Path(folder)/"config/autostart").glob("*.desktop")
        assert "--background" in entry.read_text() and "--background" not in app.read_text()
        click("Open Gent Desktop")
        first = wait_for(visible, "window opened by tray")
        exercise_tabs(cli, fixture, agent, remote, hosted, created["node"])
        assert 'name = "desktop-published"' in (home / "config.toml").read_text()
        cli("desktop")
        assert visible() == first, "second launch duplicated the window"
        subprocess.run(["xdotool","windowactivate","--sync",first,"key","alt+F4"], check=True)
        wait_for(lambda: not visible(), "window hidden")
        # Launch the generated .desktop file with the freedesktop Exec parser.
        subprocess.run(["gio", "launch", str(app)], check=True, timeout=8)
        assert wait_for(visible, "launcher reopened window") == first
        click("Quit Gent Desktop")
        wait_for(lambda: not visible(), "tray quit")
        assert daemon.poll() is None and json.loads(cli("daemon", "status", "--json").stdout)["daemon"]["running"]
        wait_for(lambda: not (home / "desktop.sock").exists(), "tray socket released")
        cli("desktop", "disable")
        assert not entry.exists() and not app.exists()
        cli("desktop", "--background")
        assert not (home / "desktop.sock").exists(), "delayed login defeated opt-out"

        # Preserve unrelated entries even if one occupies our expected filename.
        app.write_text("[Desktop Entry]\nName=User's application\n")
        refused = subprocess.run(base + ["desktop", "enable"], capture_output=True, timeout=10)
        assert refused.returncode != 0 and b"unmanaged desktop login entry" in refused.stderr
        assert "User's application" in app.read_text() and not entry.exists()
        app.unlink()
        cli("desktop", "enable")
        tray.menu("Daemon running")
        cli("desktop", "disable")
        wait_for(lambda: not (home / "desktop.sock").exists(), "disable closed the running tray")
        assert daemon.poll() is None
        print("PASS: local, remote and hosted node rename, cancel and validation error, fresh setup, stopped daemon, unified member rows and selection, MCP dashboard widgets, button delivery, live update/delete, chats, settings, cluster publish, tray and login lifecycle")


if __name__ == "__main__":
    main()
