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


def notice_label():
    widget = label()
    widget.set_line_wrap(True)
    widget.set_no_show_all(True)
    widget.connect("notify::label", lambda w, _: w.set_visible(bool(w.get_text())))
    return widget


class ClusterPane(Gtk.ScrolledWindow):
    def __init__(self, send, refresh_after_operation):
        super().__init__()
        self.send = send
        self.enrolled = MODE != "setup"
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, border_width=16)
        self.add(outer)
        self.health = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.pack_start(self.health, False, False, 0)

        identity = Gtk.Box(spacing=12)
        identity.pack_start(Gtk.Image.new_from_pixbuf(GdkPixbuf.Pixbuf.new_from_file_at_scale(ICON, 42, 42, True)), False, False, 0)
        titles = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.cluster = label("", "node-title")
        self.node = label("", "quiet")
        titles.pack_start(self.cluster, False, False, 0)
        titles.pack_start(self.node, False, False, 0)
        identity.pack_start(titles, True, True, 0)
        self.health.pack_start(identity, False, False, 0)

        daemon = Gtk.Box(spacing=8)
        self.state = label("", "section")
        daemon.pack_start(self.state, False, False, 0)
        self.toggle = Gtk.Button()
        self.toggle.connect("clicked", lambda *_: self.send("stop" if self.can_stop else "start"))
        daemon.pack_start(self.toggle, False, False, 0)
        self.restart = Gtk.Button(label="Restart")
        self.restart.connect("clicked", lambda *_: self.send("restart"))
        daemon.pack_start(self.restart, False, False, 0)
        self.health.pack_start(daemon, False, False, 0)

        metrics = Gtk.Box(spacing=20)
        self.values = {}
        for key, title in (("sync", "Sync"), ("queue", "Queued"), ("chats", "Known chats")):
            metric = Gtk.Box(spacing=6)
            metric.pack_start(label(title, "quiet"), False, False, 0)
            self.values[key] = label("—", "section")
            metric.pack_start(self.values[key], False, False, 0)
            metrics.pack_start(metric, False, False, 0)
        self.health.pack_start(metrics, False, False, 0)
        self.connection = label("", "quiet")
        self.health.pack_start(self.connection, False, False, 0)

        self.error = label()
        self.error.set_line_wrap(True)
        outer.pack_start(self.error, False, False, 0)
        self.account = ManagementPane("cluster", refresh_after_operation)
        self.account.set_border_width(0)
        self.account.expander.set_expanded(not self.enrolled)
        outer.pack_start(self.account, False, False, 0)
        self.members = DirectoryPane("nodes", refresh_after_operation)
        self.members.set_border_width(0)
        outer.pack_start(self.members, True, True, 0)

    def load(self):
        self.account.load()
        self.send("refresh")

    def buttons(self, model, pending):
        self.can_stop = bool(model.get("can_stop"))
        self.toggle.set_label("Stop daemon" if model.get("running") or self.can_stop else "Start daemon")
        self.toggle.set_sensitive(not pending and bool(model.get("can_start") or self.can_stop))
        self.restart.set_sensitive(not pending and self.can_stop)

    def update(self, model):
        self.error.set_text(model.get("error") or "")
        self.error.set_visible(bool(model.get("error")))
        if "state" not in model:
            return
        self.cluster.set_text(model.get("cluster") or "Cluster")
        self.node.set_text("Local node · " + (model.get("node") or "—"))
        self.state.set_text("Daemon " + model["state"].lower())
        for key, value in self.values.items():
            raw = model.get(key)
            value.set_text("—" if raw is None else str(raw).capitalize())
        self.connection.set_text(model.get("connection") or "")
        self.connection.set_visible(bool(model.get("connection")))
        self.members.receive(model["nodes"])
        enrolled = model["enrolled"]
        self.health.set_visible(enrolled)
        self.members.set_visible(enrolled)
        if enrolled != self.enrolled:
            self.enrolled = enrolled
            self.account.expander.set_expanded(not enrolled)


class Desktop:
    def __init__(self):
        self.pending = False
        self.refresh_queued = False
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
        css.load_from_data(b".node-title { font-size: 1.6em; font-weight: bold; } .section { font-weight: bold; } .quiet { opacity: .72; }")
        Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        self.tabs = Gtk.Notebook()
        self.tabs.set_scrollable(True)
        self.window.add(self.tabs)
        self.cluster = ClusterPane(self.send, self.refresh_after_operation)
        self.dashboard = DashboardPane()
        pages = {
            "Status": self.cluster, "Dashboard": self.dashboard, "Chats": DirectoryPane("chats"),
            "Settings": SettingsPane(), "Permissions": ManagementPane("permissions"), "About": ManagementPane("about"),
        }
        for title, page in pages.items():
            self.tabs.append_page(page, Gtk.Label(label=title))
        self.replies = {title.lower(): page for title, page in pages.items()}
        self.replies.update(cluster=self.cluster.account, nodes=self.cluster.members)
        self.tabs.show_all()
        self.cluster.health.hide()
        self.cluster.members.hide()
        self.cluster.error.hide()
        self.tabs.connect("switch-page", lambda _, page, index: page.load())
        self.cluster.buttons(self.model, self.pending)
        self.install_tray()
        GLib.io_add_watch(0, GLib.PRIORITY_DEFAULT, GLib.IO_IN | GLib.IO_HUP | GLib.IO_ERR, self.receive)
        GLib.timeout_add_seconds(15, self.tick)
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
        self.tabs.get_nth_page(self.tabs.get_current_page()).load()

    def refresh_after_operation(self):
        # An in-flight snapshot may predate the mutation.
        if self.pending:
            self.refresh_queued = True
        else:
            self.send("refresh")

    def send(self, action):
        if not self.pending:
            self.pending = True
            self.cluster.buttons(self.model, self.pending)
            print(action, flush=True)

    def tick(self):
        if self.window.get_visible() and self.tabs.get_nth_page(self.tabs.get_current_page()) is self.dashboard:
            self.dashboard.load()
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
                self.replies[message["page"]].receive(message)
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
        self.cluster.update(model)
        if "state" in model:
            self.model = model
            self.tray_state.set_label("Daemon " + model["state"].lower())
        if self.refresh_queued:
            self.refresh_queued = False
            self.send("refresh")
        else:
            self.cluster.buttons(self.model, self.pending)
