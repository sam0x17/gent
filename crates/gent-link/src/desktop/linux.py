"""GTK desktop companion. Its parent owns the authenticated local daemon connection."""
import json
import os
import sys
import time

try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("Gdk", "3.0")
    from gi.repository import Gdk, GdkPixbuf, GLib, Gtk
except (ImportError, ValueError):
    sys.exit("Gent Desktop needs Python 3 with PyGObject and GTK 3 (python3-gi and gir1.2-gtk-3.0 on Debian/Ubuntu).")

ICON, MODE = sys.argv[1:]
if not Gtk.init_check()[0]:
    sys.exit("Gent Desktop could not connect to the graphical display.")
GLib.set_application_name("Gent Desktop")


def label(text="", style=None):
    widget = Gtk.Label(label=text, xalign=0)
    if style:
        widget.get_style_context().add_class(style)
    return widget


class Desktop:
    def __init__(self):
        self.pending = False
        self.buffer = bytearray()
        self.model = {}
        self.last_read = 0.0
        self.window = Gtk.Window(title="Gent Desktop")
        self.window.set_default_size(850, 605)
        self.window.set_icon_from_file(ICON)
        self.window.connect("delete-event", lambda *_: self.window.hide_on_delete())
        header = Gtk.HeaderBar(title="Gent Desktop", show_close_button=True)
        self.refresh = Gtk.Button.new_from_icon_name("view-refresh-symbolic", Gtk.IconSize.BUTTON)
        self.refresh.set_tooltip_text("Refresh status")
        self.refresh.get_accessible().set_name("Refresh status")
        self.refresh.connect("clicked", lambda *_: self.refresh_tab())
        header.pack_end(self.refresh)
        self.window.set_titlebar(header)
        header.show_all()

        css = Gtk.CssProvider()
        css.load_from_data(b".node-title { font-size: 1.6em; font-weight: bold; } .metric { font-size: 1.45em; font-weight: bold; } .section { font-weight: bold; } .quiet { opacity: .72; }")
        Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14, border_width=20)
        self.tabs = Gtk.Notebook()
        self.tabs.set_scrollable(True)
        self.window.add(self.tabs)
        self.tabs.append_page(outer, Gtk.Label(label="Status"))
        identity = Gtk.Box(spacing=12)
        identity.pack_start(Gtk.Image.new_from_pixbuf(GdkPixbuf.Pixbuf.new_from_file_at_scale(ICON, 46, 46, True)), False, False, 0)
        titles = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.node = label("Gent", "node-title")
        self.cluster = label("", "quiet")
        titles.pack_start(self.node, True, True, 0)
        titles.pack_start(self.cluster, True, True, 0)
        identity.pack_start(titles, True, True, 0)
        self.state = label("Connecting…", "section")
        identity.pack_end(self.state, False, False, 0)
        outer.pack_start(identity, False, False, 0)
        outer.pack_start(Gtk.Separator(), False, False, 0)

        metrics = Gtk.Box(spacing=24, homogeneous=True)
        self.values = {}
        for key, title in (("sync", "Sync"), ("queue", "Queued"), ("chats", "Known chats")):
            column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            column.pack_start(label(title, "quiet"), False, False, 0)
            self.values[key] = label("—", "metric")
            column.pack_start(self.values[key], False, False, 0)
            metrics.pack_start(column, True, True, 0)
        outer.pack_start(metrics, False, False, 0)
        self.table = Gtk.ListStore(str, str, str)
        view = Gtk.TreeView(model=self.table)
        for i, title in enumerate(("Peer", "Directory", "Last transport")):
            column = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=i)
            column.set_expand(i == 0)
            column.set_resizable(True)
            view.append_column(column)
        self.empty = label("Waiting for daemon status…", "quiet")
        self.scroll = Gtk.ScrolledWindow()
        self.scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.scroll.add(view)
        outer.pack_start(self.scroll, True, True, 0)
        outer.pack_start(self.empty, True, True, 0)
        self.connection = label("", "quiet")
        outer.pack_start(self.connection, False, False, 0)
        self.error = label()
        self.error.set_line_wrap(True)
        outer.pack_start(self.error, False, False, 0)
        actions = Gtk.Box(spacing=8)
        self.toggle = Gtk.Button(label="Start daemon")
        self.toggle.connect("clicked", lambda *_: self.send("stop" if self.model.get("can_stop") else "start"))
        actions.pack_start(self.toggle, False, False, 0)
        self.restart = Gtk.Button(label="Restart")
        self.restart.connect("clicked", lambda *_: self.send("restart"))
        actions.pack_start(self.restart, False, False, 0)
        outer.pack_end(actions, False, False, 0)
        self.pages = {
            "dashboard": DashboardPane(), "chats": DirectoryPane("chats"),
            "nodes": DirectoryPane("nodes"), "settings": SettingsPane(),
            **{name: ManagementPane(name) for name in ("cluster", "permissions", "about")},
        }
        for name, page in self.pages.items():
            self.tabs.append_page(page, Gtk.Label(label=name.title()))
        self.tabs.show_all()
        self.tabs.connect("switch-page", lambda _, page, index: page.load() if index else self.send("refresh"))
        self.scroll.hide()
        self.error.hide()
        self.buttons()
        self.install_tray()
        GLib.io_add_watch(0, GLib.PRIORITY_DEFAULT, GLib.IO_IN | GLib.IO_HUP | GLib.IO_ERR, self.receive)
        GLib.timeout_add_seconds(15, self.tick)
        if MODE == "setup":
            self.tabs.set_current_page(self.tabs.page_num(self.pages["cluster"]))
        if MODE in ("window", "setup"):
            self.show()
        else:
            self.send("refresh")

    def install_tray(self):
        menu = Gtk.Menu()
        self.tray_state = Gtk.MenuItem(label="Checking daemon…")
        self.tray_state.set_sensitive(False)
        menu.append(self.tray_state)
        menu.append(Gtk.SeparatorMenuItem())
        for name, action in (("Open Gent Desktop", self.show), ("Quit Gent Desktop", Gtk.main_quit)):
            item = Gtk.MenuItem(label=name)
            item.connect("activate", lambda _, action=action: action())
            menu.append(item)
        menu.show_all()
        for namespace in ("AyatanaAppIndicator3", "AppIndicator3"):
            try:
                gi.require_version(namespace, "0.1")
                api = getattr(__import__("gi.repository", fromlist=[namespace]), namespace)
            except (ImportError, ValueError, AttributeError):
                continue
            import hashlib
            tag = hashlib.sha256(os.fsencode(ICON)).hexdigest()[:16]
            self.tray = api.Indicator.new("gent-" + tag, ICON, api.IndicatorCategory.APPLICATION_STATUS)
            self.tray.set_status(api.IndicatorStatus.ACTIVE)
            self.tray.set_title("Gent Desktop")
            self.tray.set_menu(menu)
            return
        self.tray = Gtk.StatusIcon.new_from_file(ICON)
        self.tray.set_title("Gent Desktop")
        self.tray.set_tooltip_text("Gent Desktop")
        self.tray.connect("activate", lambda *_: self.show())
        self.tray.connect("popup-menu", lambda icon, button, ts: menu.popup(None, None, Gtk.StatusIcon.position_menu, icon, button, ts))
        self.tray.set_visible(True)

    def show(self):
        self.window.present()
        self.refresh_tab()

    def refresh_tab(self):
        index = self.tabs.get_current_page()
        if index > 0:
            self.tabs.get_nth_page(index).load()
        else:
            self.send("refresh")

    def buttons(self):
        self.toggle.set_label("Stop daemon" if self.model.get("running") or self.model.get("can_stop") else "Start daemon")
        self.toggle.set_sensitive(not self.pending and bool(self.model.get("can_start") or self.model.get("can_stop")))
        self.restart.set_sensitive(not self.pending and bool(self.model.get("can_stop")))
        self.refresh.set_sensitive(not self.pending)

    def send(self, action):
        if not self.pending:
            self.pending = True
            self.buttons()
            print(action, flush=True)

    def tick(self):
        if self.window.get_visible() and self.tabs.get_nth_page(self.tabs.get_current_page()) is self.pages["dashboard"]:
            self.pages["dashboard"].load()
        if self.window.get_visible() or time.monotonic() - self.last_read >= 60:
            self.send("refresh")
        return True

    def receive(self, _fd, _condition):
        data = os.read(0, 65536)
        if not data:
            Gtk.main_quit()
            return False
        self.buffer.extend(data)
        while b"\n" in self.buffer:
            line, _, self.buffer = self.buffer.partition(b"\n")
            message = json.loads(line)
            if "page" in message:
                self.pages[message["page"]].receive(message)
                continue
            if message.get("quit"):
                Gtk.main_quit()
                return False
            if message.get("show"):
                self.show()
            else:
                self.update(message)
        return True

    def update(self, model):
        self.pending = False
        self.last_read = time.monotonic()
        self.error.set_text(model.get("error", ""))
        self.error.set_visible(bool(model.get("error")))
        if "error" not in model:
            self.model = model
            self.node.set_text(model.get("node") or "Gent")
            self.cluster.set_text(model.get("cluster") or "Local daemon")
            self.state.set_text(model["state"])
            self.tray_state.set_label("Daemon " + model["state"].lower())
            for k, value in self.values.items():
                raw = model.get(k)
                value.set_text("—" if raw is None else str(raw).capitalize())
            self.connection.set_text(model.get("connection") or "")
            self.table.clear()
            for peer in model["peers"]:
                self.table.append((peer["name"] or "Unknown", (peer["state"] or "Unknown").capitalize(), peer["route"] or "—"))
            self.scroll.set_visible(bool(model["peers"]))
            self.empty.set_text("No peers in the directory." if model["running"] else "Daemon status is unavailable." if model["state"] != "Stopped" else "The daemon is stopped.")
            self.empty.set_visible(not model["peers"])
        self.buttons()
