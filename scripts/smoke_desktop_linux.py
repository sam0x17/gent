#!/usr/bin/env python3
"""Run under dbus-run-session and Xvfb, with GTK 3, AyatanaAppIndicator, xdotool and a WM."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
from queue import Queue
import subprocess
import tempfile
import threading
import time

from gi.repository import Gio, GLib


def wait_for(check, description):
    end = time.monotonic() + 12
    while time.monotonic() < end:
        result = check()
        if result:
            return result
        time.sleep(.1)
    raise RuntimeError("Timed out waiting for " + description)


class TrayHost:
    """Receive the real indicator registration and invoke its exported D-Bus menu."""
    name = "org.kde.StatusNotifierWatcher"
    xml = """<node><interface name="org.kde.StatusNotifierWatcher">
      <method name="RegisterStatusNotifierItem"><arg type="s" direction="in"/></method>
      <property name="IsStatusNotifierHostRegistered" type="b" access="read"/>
    </interface></node>"""

    def __init__(self):
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION)
        self.registrations = Queue()
        iface = Gio.DBusNodeInfo.new_for_xml(self.xml).interfaces[0]
        self.object_id = self.bus.register_object("/StatusNotifierWatcher", iface, self.register,
                                                  lambda *_: GLib.Variant("b", True), None)
        acquired = threading.Event()
        self.owner = Gio.bus_own_name_on_connection(self.bus, self.name, Gio.BusNameOwnerFlags.DO_NOT_QUEUE,
                                                     lambda *_: acquired.set(), None)
        self.loop = GLib.MainLoop()
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
        target, item = self.registrations.get(timeout=12)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="gent-desk-") as folder, ExitStack() as cleanup:
        home = Path(folder) / 'node with % space'
        env = dict(os.environ, HOME=folder, XDG_DATA_HOME=folder+"/data", XDG_CONFIG_HOME=folder+"/config")
        base = [str(args.binary.resolve()), "--home", str(home)]
        def cli(*args, **kwargs):
            return subprocess.run(base + list(args), env=env, timeout=20, check=True, capture_output=True, **kwargs)
        def launch(*args):
            process = subprocess.Popen(base + list(args), env=env)
            cleanup.callback(stop, process)
            return process
        def visible():
            return subprocess.run(["xdotool", "search", "--onlyvisible", "--name", "^Gent Desktop$"],
                                  text=True, capture_output=True).stdout.strip()
        cli("cluster", "new", "desktop-test", "--local")
        daemon = launch("daemon", "run")
        wait_for(lambda: (home/"daemon.sock").is_socket(), "daemon")
        tray = TrayHost()
        cleanup.callback(tray.close)
        cli("desktop", "enable")
        click = tray.menu("Daemon running")
        assert not visible(), "autostart opened the window"
        app, = (Path(folder)/"data/applications").glob("*.desktop")
        entry, = (Path(folder)/"config/autostart").glob("*.desktop")
        assert "--background" in entry.read_text() and "--background" not in app.read_text()
        click("Open Gent Desktop")
        first = wait_for(visible, "window opened by tray")
        cli("desktop")
        assert visible() == first, "second launch duplicated the window"
        subprocess.run(["xdotool","windowactivate","--sync",first,"key","alt+F4"], check=True)
        wait_for(lambda: not visible(), "window hidden")
        # Launch the generated .desktop file with the freedesktop Exec parser.
        subprocess.run(["gio", "launch", str(app)], env=env, check=True, timeout=8)
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
        refused = subprocess.run(base + ["desktop", "enable"], env=env, capture_output=True, timeout=10)
        assert refused.returncode != 0 and b"unmanaged desktop login entry" in refused.stderr
        assert "User's application" in app.read_text() and not entry.exists()
        app.unlink()
        cli("desktop", "enable")
        tray.menu("Daemon running")
        cli("desktop", "disable")
        wait_for(lambda: not (home / "desktop.sock").exists(), "disable closed the running tray")
        assert daemon.poll() is None
        print("PASS: tray menu, single window, close/reopen, quit, login opt-out, file ownership and daemon independence")


if __name__ == "__main__":
    main()
