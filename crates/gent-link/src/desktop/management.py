# Shared native action dialogs for the directories, account, and permission editor.
class ActionBar(Gtk.Box):
    def __init__(self, pane):
        super().__init__(spacing=6)
        self.pane = pane
        self.buttons = []
        self.busy = False

    def configure(self, specs):
        if specs == [spec for _, spec in self.buttons]:
            return
        for button, _ in self.buttons:
            button.destroy()
        self.buttons = []
        for spec in specs:
            button = Gtk.Button(label=spec["title"])
            button.connect("clicked", lambda _, s=spec: self.open(s))
            self.pack_start(button, False, False, 0)
            self.buttons.append((button, spec))
        self.show_all()
        self.update()

    def update(self, *_):
        for button, spec in self.buttons:
            enabled = True
            if spec.get("row"):
                row = self.pane.selection()
                enabled = bool(row and row["state"] not in ("Revoked", "Retired"))
                if spec["kind"] in ("remove_node", "node_role") and row:
                    enabled = row["state"] != "local" and row.get("role") != "Owner"
            button.set_sensitive(enabled and not self.busy)

    def open(self, spec):
        values = dict(spec.get("values", {}), kind=spec["kind"])
        target = ""
        row = self.pane.selection() if spec.get("row") else None
        if row:
            values["id"] = row["id"]
            target = row["name"] + "\n" + row["id"]
        elif spec.get("row"):
            return
        if not (spec.get("fields") or spec.get("confirm")):
            self.send(values)
            return
        dialog = Gtk.Dialog(title=spec["title"].rstrip("…"), transient_for=self.get_toplevel(),
                            modal=True, destroy_with_parent=True)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        submit = dialog.add_button(spec.get("submit", spec["title"].rstrip("…")), Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.CANCEL)
        body = dialog.get_content_area()
        body.set_border_width(16)
        body.set_spacing(8)
        for text in (target, spec.get("confirm") or spec.get("hint")):
            if text:
                line = label(text)
                line.set_max_width_chars(58)
                line.set_line_wrap(True)
                body.pack_start(line, False, False, 0)
        inputs = {}
        for field in spec.get("fields", []):
            key = field["key"]
            body.pack_start(label(field["title"]), False, False, 0)
            if "choices" in field:
                control = Gtk.ComboBoxText()
                for value, title in field["choices"]:
                    control.append(value, title)
                control.set_active(0)
                if key == "role" and row:
                    control.set_active_id("admin" if row.get("role") == "Admin" else "member")
                inputs[key] = control.get_active_id
            else:
                control = Gtk.Entry()
                if row and key in row:
                    control.set_text(row[key])
                control.set_visibility(not field.get("secret", False))
                control.set_width_chars(42)
                inputs[key] = control.get_text
                control.connect("changed", lambda *_: submit.set_sensitive(all(read().strip() for read in inputs.values())))
            body.pack_start(control, False, False, 0)
        submit.set_sensitive(all(read().strip() for read in inputs.values()))
        def response(window, choice):
            if choice == Gtk.ResponseType.OK:
                values.update({key: read().strip() for key, read in inputs.items()})
            window.destroy()
            if choice == Gtk.ResponseType.OK:
                self.send(values)

        dialog.connect("response", response)
        dialog.show_all()

    def send(self, action):
        if self.busy:
            return
        self.busy = True
        self.update()
        self.pane.notice.set_text("Waiting for sign-in in your browser…" if action["kind"] == "sign_in" else "Working…")
        page_request("manage", action=action)

    def completed(self, reply):
        self.busy = False
        self.update()
        self.pane.notice.set_text(reply.get("error") or reply.get("notice", ""))
        if "private_code" in reply:
            dialog = Gtk.Dialog(title=reply["notice"], modal=True, transient_for=self.get_toplevel(),
                                destroy_with_parent=True)
            dialog.add_button("Done", Gtk.ResponseType.CLOSE)
            body = dialog.get_content_area()
            body.set_border_width(16)
            body.set_spacing(8)
            body.pack_start(label("Enter this private code on the new node within 15 minutes."), False, False, 0)
            code = Gtk.Entry(text=reply["private_code"], editable=False)
            code.set_width_chars(46)
            body.pack_start(code, False, False, 0)
            dialog.connect("response", lambda window, _: window.destroy())
            dialog.show_all()
            code.select_region(0, -1)


class AboutLogo(Gtk.Layout):
    def __init__(self):
        super().__init__()
        self.source = GdkPixbuf.Pixbuf.new_from_file(ICON)
        self.image = Gtk.Image()
        self.image.get_accessible().set_name("Gent logo")
        self.put(self.image, 0, 0)
        self.size = 0
        self.connect("size-allocate", self.resize)

    def resize(self, _, rect):
        size = max(1, min(512, rect.width, rect.height))
        if size != self.size:
            self.image.set_from_pixbuf(self.source.scale_simple(size, size, GdkPixbuf.InterpType.BILINEAR))
            self.size = size
        self.move(self.image, (rect.width - size) // 2, (rect.height - size) // 2)


class ManagementPane(Gtk.Box):
    def __init__(self, name, refresh_snapshot=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12, border_width=18)
        self.name = name
        self.loading = False
        self.reload_queued = False
        self.refresh_snapshot = refresh_snapshot
        body = self
        if name == "about":
            self.set_orientation(Gtk.Orientation.HORIZONTAL)
            self.pack_start(AboutLogo(), True, True, 0)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, valign=Gtk.Align.CENTER)
            self.pack_start(body, False, False, 0)
        if name == "cluster":
            self.expander = Gtk.Expander()
            self.title = label("Account", "section")
            self.expander.set_label_widget(self.title)
            self.pack_start(self.expander, False, False, 0)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_start=18)
            self.expander.add(body)
        else:
            self.title = label("", "node-title")
            body.pack_start(self.title, False, False, 0)
        self.detail = label()
        self.detail.set_selectable(True)
        self.detail.set_line_wrap(True)
        self.detail.set_yalign(0)
        if name == "permissions":
            scroll = Gtk.ScrolledWindow()
            scroll.add(self.detail)
            body.pack_start(scroll, True, True, 0)
        else:
            body.pack_start(self.detail, False, False, 0)
        if name == "about":
            link = Gtk.LinkButton.new_with_label("https://gent.link", "https://gent.link")
            link.set_halign(Gtk.Align.START)
            body.pack_start(link, False, False, 0)
        self.actions = ActionBar(self)
        body.pack_start(self.actions, False, False, 0)
        self.notice = notice_label()
        (self if name == "cluster" else body).pack_start(self.notice, False, False, 0)

    def load(self):
        if not self.loading:
            self.loading = True
            page_request(self.name)

    def receive(self, reply):
        if reply.get("operation"):
            self.actions.completed(reply)
            if self.refresh_snapshot is not None:
                if "error" not in reply:
                    self.refresh_snapshot()
                if self.loading:
                    self.reload_queued = True
                else:
                    self.load()
            elif "error" not in reply:
                self.load()
            return
        self.loading = False
        self.title.set_text(reply.get("title", self.name.title()))
        self.detail.set_text(reply.get("error") or reply.get("detail", ""))
        self.actions.configure(reply.get("actions", []))
        if self.reload_queued:
            self.reload_queued = False
            self.load()
