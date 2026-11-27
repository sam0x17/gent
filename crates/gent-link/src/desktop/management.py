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


def about_text(reply):
    """Build selectable GTK text. Only exact repository permalinks become links."""
    import re
    from html import escape

    root = "https://github.com/sam0x17/gent"
    links = set()

    def link(text, url):
        if not url:
            return escape(text)
        links.add(url)
        return f'<a href="{escape(url)}">{escape(text)}</a>'

    def string(value):
        return value if isinstance(value, str) else ""

    detail = string(reply.get("error") or reply.get("detail"))
    release = reply.get("latest_release")
    release = release if isinstance(release, dict) and not reply.get("error") else {}
    version = string(release.get("version")).removeprefix("v")
    release_url = None
    if re.fullmatch(r"[0-9][0-9A-Za-z.+-]{0,127}", version):
        expected = f"{root}/releases/tag/v{version}"
        if release.get("url") == expected:
            release_url = expected

    installed = string(reply.get("version"))
    revision = string(reply.get("revision"))
    text = escape(detail)
    prefix = f"Version {installed} · "
    if installed and detail.startswith(prefix):
        text = "Version " + link(installed, release_url if installed == version else None) + " · "
        rest = detail[len(prefix):]
        short = revision[:12]
        if re.fullmatch(r"[0-9a-f]{40}", revision) and rest.startswith(short):
            target = reply.get("revision_url")
            revision_url = target if target in (release_url, f"{root}/commit/{revision}") else None
            text += link(short, revision_url)
            rest = rest[len(short):]
        text += escape(rest)

    notes = string(release.get("notes"))
    if not notes.strip():
        notes = ""
    if version or notes:
        heading = "Release notes" if notes else "Latest release"
        if version:
            heading += (" for " if notes else " ") + link("v" + version, release_url)
        text += ("\n\n" if text else "") + "<b>" + heading + "</b>"
        if notes:
            text += "\n\n" + escape(notes)
    return text, links, bool(version or notes)


class AboutLogo(Gtk.Image):
    def __init__(self):
        super().__init__()
        self.source = GdkPixbuf.Pixbuf.new_from_file(ICON)
        self.get_accessible().set_name("Gent logo")
        self.size = 0
        self.connect("size-allocate", self.resize)

    # Let the available space determine the icon size, even after shrinking a
    # window that previously displayed the full-resolution image.
    def do_get_preferred_width(self):
        return 0, 0

    def do_get_preferred_height(self):
        return 0, 0

    def resize(self, _, rect):
        size = max(1, min(512, rect.width, rect.height))
        if size != self.size:
            self.set_from_pixbuf(self.source.scale_simple(size, size, GdkPixbuf.InterpType.BILINEAR))
            self.size = size


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
            self.about_body = body
            self.about_links = set()
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
        if name == "about":
            from gi.repository import Pango
            self.detail.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
            self.detail.set_halign(Gtk.Align.FILL)
            self.detail.connect("activate-link", self.open_about_link)
            self.about_scroll = Gtk.ScrolledWindow()
            self.about_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            self.about_scroll.add(self.detail)
            body.pack_start(self.about_scroll, True, True, 0)
        elif name == "permissions":
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

    def open_about_link(self, _label, uri):
        if uri in self.about_links:
            Gtk.show_uri_on_window(self.get_toplevel(), uri, Gtk.get_current_event_time())
        return True

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
        if self.name == "about":
            text, self.about_links, expanded = about_text(reply)
            if self.detail.get_label() != text:
                self.detail.set_markup(text)
                self.about_scroll.get_vadjustment().set_value(0)
            self.about_body.set_valign(Gtk.Align.FILL if expanded else Gtk.Align.CENTER)
            self.about_scroll.set_min_content_height(64)
            self.detail.set_max_width_chars(44 if expanded else 32)
            self.set_child_packing(self.about_body, expanded, True, 0, Gtk.PackType.START)
        else:
            self.detail.set_text(reply.get("error") or reply.get("detail", ""))
        self.actions.configure(reply.get("actions", []))
        if self.reload_queued:
            self.reload_queued = False
            self.load()
