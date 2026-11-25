# Embedded after linux.py in the same private frontend process.
def page_request(op, **fields):
    print(json.dumps(dict(op=op, **fields)), flush=True)


class DirectoryPane(Gtk.Box):
    def __init__(self, name, refresh_snapshot=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, border_width=16)
        self.name = name
        self.refresh_snapshot = refresh_snapshot
        self.busy = False
        self.rows = None
        self.error = None
        self.columns = ([("name", "Chat"), ("node", "Node"), ("provider", "Provider"),
                         ("state", "Registration"), ("id", "Chat ID")] if name == "chats" else
                        [("name", "Node"), ("state", "Status"), ("role", "Role"),
                         ("directory", "Directory"), ("route", "Last transport"),
                         ("host", "Hosted by"), ("id", "Node ID")])
        if name == "nodes":
            self.pack_start(label("Nodes", "section"), False, False, 0)
        placeholder = "Filter " + name
        self.search = Gtk.SearchEntry(placeholder_text=placeholder)
        self.search.get_accessible().set_name(placeholder)
        self.search.connect("search-changed", lambda *_: self.render())
        self.pack_start(self.search, False, False, 0)
        # GtkTreeView can take row tooltips from a non-displayed markup column.
        self.store = Gtk.ListStore(*([str] * (len(self.columns) + (name == "nodes"))))
        view = self.table = Gtk.TreeView(model=self.store)
        if name == "nodes":
            view.set_tooltip_column(len(self.columns))
        for i, (_, title) in enumerate(self.columns):
            column = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=i)
            column.set_resizable(True)
            column.set_sort_column_id(i)
            view.append_column(column)
        scroll = Gtk.ScrolledWindow()
        if name == "nodes":
            scroll.set_min_content_height(135)
        scroll.add(view)
        self.pack_start(scroll, True, True, 0)
        self.status = label()
        self.pack_start(self.status, False, False, 0)

        self.actions = ActionBar(self)
        self.pack_start(self.actions, False, False, 0)
        self.table.get_selection().connect("changed", self.actions.update)
        self.notice = notice_label()
        self.pack_start(self.notice, False, False, 0)

    def selection(self):
        model, selected = self.table.get_selection().get_selected()
        if selected is None:
            return None
        return dict(zip((key for key, _ in self.columns), model[selected]))

    def load(self):
        if self.refresh_snapshot is not None:
            self.refresh_snapshot()
        elif not self.busy:
            self.busy = True
            self.status.set_text("Loading…")
            page_request("chats")

    def receive(self, reply):
        if reply.get("operation"):
            self.actions.completed(reply)
            if "error" not in reply:
                self.load()
            return
        self.busy = False
        self.actions.configure(reply.get("actions", []))
        rows = reply.get("rows", [])
        self.error = reply.get("error")
        if rows != self.rows:
            self.rows = rows
            self.render()
        else:
            self.update_count()

    def render(self):
        selected = self.selection()
        self.store.clear()
        query = self.search.get_text().strip().casefold()
        for row in self.rows or []:
            cells = [str(row.get(key) or "—") for key, _ in self.columns]
            if any(query in cell.casefold() for cell in cells):
                if self.name == "nodes":
                    detail = row.get("status_detail")
                    cells.append(GLib.markup_escape_text(detail) if detail else None)
                item = self.store.append(cells)
                if selected and row["id"] == selected["id"]:
                    self.table.get_selection().select_iter(item)
        self.update_count()

    def update_count(self):
        self.status.set_text(self.error or f"{len(self.store)} of {len(self.rows or [])} {self.name}")


class ReleaseChannelRow(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        row = Gtk.Box(spacing=8)
        title = "Cluster release channel"
        row.pack_start(label(title), False, False, 0)
        self.choice = Gtk.ComboBoxText()
        self.choice.get_accessible().set_name(title)
        for channel in ("stable", "beta"):
            self.choice.append(channel, channel.capitalize())
        row.pack_start(self.choice, False, False, 0)
        self.retry = Gtk.Button(label="Retry request")
        self.retry.set_no_show_all(True)
        self.retry.connect("clicked", self.retry_request)
        row.pack_start(self.retry, False, False, 0)
        self.pack_start(row, False, False, 0)
        hint = label("Switching channels requests one update per node, even when automatic updates are paused.", "quiet")
        hint.set_line_wrap(True)
        self.pack_start(hint, False, False, 0)
        self.detail = notice_label()
        self.pack_start(self.detail, False, False, 0)
        self.current = None
        self.busy = self.pending = False
        self.choice.set_sensitive(False)
        self.changed = self.choice.connect("changed", self.select)

    def load(self):
        if not self.busy:
            self.busy = True
            self.choice.set_sensitive(False)
            self.retry.set_sensitive(False)
            page_request("release_channel")

    def retry_request(self, _button):
        if not self.busy:
            self.busy = True
            self.retry.set_sensitive(False)
            self.detail.set_text("Retrying the same request…")
            page_request("retry_release_channel")

    def show_current(self):
        with self.choice.handler_block(self.changed):
            if self.current in ("stable", "beta"):
                self.choice.set_active_id(self.current)
            else:
                self.choice.set_active(-1)

    def select(self, choice):
        channel = choice.get_active_id()
        self.show_current()
        if not self.busy and choice.get_sensitive() and channel and channel != self.current:
            self.busy = True
            choice.set_sensitive(False)
            self.detail.set_text(f"Requesting {channel.capitalize()}…")
            page_request("set_release_channel", channel=channel)

    def receive(self, reply):
        self.busy = False
        self.current = reply.get("current")
        self.pending = reply.get("pending") is True
        self.show_current()
        self.choice.set_sensitive(self.current in ("stable", "beta") and reply.get("can_set") is True)
        self.retry.set_visible(reply.get("retry") is True)
        self.retry.set_sensitive(reply.get("retry") is True)
        self.detail.set_text(reply.get("notice", ""))


class SettingsPane(Gtk.Box):
    options = (("login", "Start Gent Desktop at graphical login"),
               ("updates", "Automatically update Gent"),
               ("babysitter", "Resume goals after provider failures"), ("discovery", "Discover and publish native chats"),
               ("direct", "Prefer direct connections"), ("udp", "Allow UDP for direct connections"),
               ("helper", "Offer this node as a transport helper"))

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, border_width=16)
        self.busy = self.updating = False
        self.values = {}
        self.stack = Gtk.Stack()
        self.pack_start(self.stack, True, True, 0)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        form_scroll = Gtk.ScrolledWindow()
        form_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        form_scroll.add(form)
        self.stack.add_named(form_scroll, "preferences")
        self.channel = ReleaseChannelRow()
        self.checks = {}
        for key, title in self.options:
            if key in ("login", "direct"):
                form.pack_start(label("General" if key == "login" else "Network", "section"), False, False, 0)
            button = Gtk.CheckButton(label=title)
            button.connect("toggled", self.toggle, key)
            form.pack_start(button, False, False, 0)
            self.checks[key] = button
            if key == "updates":
                form.pack_start(self.channel, False, False, 0)
            if key == "babysitter":
                self.pricing = Gtk.LinkButton.new_with_label("https://gent.link/pricing", "Babysitter requires Gent Pro · View plans")
                self.pricing.set_halign(Gtk.Align.START)
                self.pricing.set_no_show_all(True)
                form.pack_start(self.pricing, False, False, 0)
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
            self.channel.load()

    def poll_channel(self):
        if self.channel.pending and self.stack.get_visible_child_name() != "document":
            self.channel.load()

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
            available = key in self.values and (key != "babysitter" or self.values.get("paid") is True)
            button.set_active(bool(available and self.values[key]))
            button.set_sensitive(available)
        self.pricing.set_visible(self.values.get("paid") is False)
        self.updating = False
        self.stack.set_sensitive(True)
        if "document" in reply:
            self.text.get_buffer().set_text(reply["document"])
            self.stack.set_visible_child_name("document")
        elif "error" not in reply:
            self.text.get_buffer().set_text("")
            self.stack.set_visible_child_name("preferences")
        self.status.set_text(reply.get("error") or reply.get("notice") or "")
