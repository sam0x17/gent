# Embedded after linux.py in the same private frontend process.
def page_request(op, **fields):
    print(json.dumps(dict(op=op, **fields)), flush=True)


class DirectoryPane(Gtk.Box):
    def __init__(self, name):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, border_width=16)
        self.name = name
        self.busy = False
        self.rows = []
        self.columns = ([("name", "Chat"), ("node", "Node"), ("provider", "Provider"),
                         ("state", "Registration"), ("id", "Chat ID")] if name == "chats" else
                        [("name", "Node"), ("state", "Status"), ("role", "Role"),
                         ("host", "Hosted by"), ("id", "Node ID")])
        self.search = Gtk.SearchEntry(placeholder_text="Filter " + name)
        self.search.connect("search-changed", lambda *_: self.render())
        self.pack_start(self.search, False, False, 0)
        self.store = Gtk.ListStore(*([str] * len(self.columns)))
        view = Gtk.TreeView(model=self.store)
        for i, (_, title) in enumerate(self.columns):
            column = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=i)
            column.set_resizable(True)
            column.set_sort_column_id(i)
            view.append_column(column)
        scroll = Gtk.ScrolledWindow()
        scroll.add(view)
        self.pack_start(scroll, True, True, 0)
        self.status = label()
        self.pack_start(self.status, False, False, 0)

    def load(self):
        if not self.busy:
            self.busy = True
            self.status.set_text("Loading…")
            page_request(self.name)

    def receive(self, reply):
        self.busy = False
        self.rows = reply.get("rows", [])
        self.render()
        if "error" in reply:
            self.status.set_text(reply["error"])

    def render(self):
        self.store.clear()
        query = self.search.get_text().strip().casefold()
        for row in self.rows:
            cells = [str(row.get(key) or "—") for key, _ in self.columns]
            if any(query in cell.casefold() for cell in cells):
                self.store.append(cells)
        self.status.set_text(f"{len(self.store)} of {len(self.rows)} {self.name}")


class SettingsPane(Gtk.Box):
    options = (("login", "Start Gent Desktop at graphical login"),
               ("updates", "Automatically update Gent"),
               ("discovery", "Discover and publish native chats"),
               ("direct", "Prefer direct connections"), ("udp", "Allow UDP for direct connections"),
               ("helper", "Offer this node as a transport helper"))

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, border_width=16)
        self.busy = self.updating = False
        self.values = {}
        self.stack = Gtk.Stack()
        self.pack_start(self.stack, True, True, 0)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.stack.add_named(form, "preferences")
        self.checks = {}
        for key, title in self.options:
            if key in ("login", "direct"):
                form.pack_start(label("General" if key == "login" else "Network", "section"), False, False, 0)
            button = Gtk.CheckButton(label=title)
            button.connect("toggled", self.toggle, key)
            form.pack_start(button, False, False, 0)
            self.checks[key] = button
        form.pack_start(label("Network changes take effect when the daemon restarts.", "quiet"), False, False, 0)
        edit = Gtk.Button(label="Edit full configuration…")
        edit.set_halign(Gtk.Align.START)
        edit.connect("clicked", lambda *_: self.request("edit"))
        form.pack_start(edit, False, False, 0)
        editor = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.stack.add_named(editor, "document")
        hint = label("Save locally writes config.toml. Publish also submits node and cluster names and policy to the cluster.")
        hint.set_line_wrap(True)
        editor.pack_start(hint, False, False, 0)
        self.text = Gtk.TextView(monospace=True)
        scroll = Gtk.ScrolledWindow()
        scroll.add(self.text)
        editor.pack_start(scroll, True, True, 0)
        actions = Gtk.Box(spacing=8)
        for title, callback in (("Cancel", lambda: self.request("discard")),
                                ("Save locally", lambda: self.save(False)),
                                ("Save and publish…", lambda: self.save(True))):
            button = Gtk.Button(label=title)
            button.connect("clicked", lambda _, action=callback: action())
            actions.pack_start(button, False, False, 0)
        editor.pack_start(actions, False, False, 0)
        self.status = label()
        self.status.set_line_wrap(True)
        self.pack_start(self.status, False, False, 0)
        self.stack.set_sensitive(False)

    def request(self, op, **fields):
        if not self.busy:
            self.busy = True
            self.stack.set_sensitive(False)
            self.status.set_text("")
            page_request(op, **fields)

    def load(self):
        if self.stack.get_visible_child_name() != "document":
            self.request("settings")

    def toggle(self, button, key):
        if not self.updating:
            self.request("set", key=key, enabled=button.get_active())

    def save(self, publish):
        if publish:
            dialog = Gtk.MessageDialog(transient_for=self.get_toplevel(), modal=True,
                                       message_type=Gtk.MessageType.QUESTION, buttons=Gtk.ButtonsType.CANCEL,
                                       text="Publish these shared settings to the cluster?")
            dialog.add_button("Save and publish", Gtk.ResponseType.OK)
            def response(window, choice):
                window.destroy()
                if choice == Gtk.ResponseType.OK:
                    self.submit(True)
            dialog.connect("response", response)
            dialog.show_all()
            return
        self.submit(False)

    def submit(self, publish):
        buf = self.text.get_buffer()
        self.request("save", text=buf.get_text(*buf.get_bounds(), True), publish=publish)

    def receive(self, reply):
        self.busy = False
        self.updating = True
        self.values = reply.get("values", self.values)
        for key, button in self.checks.items():
            button.set_active(bool(self.values.get(key)))
            button.set_sensitive(key in self.values)
        self.updating = False
        self.stack.set_sensitive(True)
        if "document" in reply:
            self.text.get_buffer().set_text(reply["document"])
            self.stack.set_visible_child_name("document")
        elif "error" not in reply:
            self.text.get_buffer().set_text("")
            self.stack.set_visible_child_name("preferences")
        self.status.set_text(reply.get("error") or reply.get("notice") or "")
