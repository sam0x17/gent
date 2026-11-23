class DashboardPane(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8, border_width=12)
        self.rows = None
        self.notice = label()
        self.flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, column_spacing=10,
                                row_spacing=10, homogeneous=False, valign=Gtk.Align.START)
        self.flow.set_min_children_per_line(1)
        self.flow.set_max_children_per_line(4)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.add(self.flow)
        self.pack_start(scroll, True, True, 0)
        self.pack_start(self.notice, False, False, 0)

    def load(self):
        page_request("dashboard")

    def receive(self, reply):
        if "rows" not in reply:
            self.notice.set_text(reply.get("error") or reply.get("notice", ""))
            return
        rows = reply["rows"]
        if self.rows == rows:
            return
        self.rows = rows
        for child in self.flow.get_children():
            self.flow.remove(child)
        for row in rows:
            board = row["board"]
            frame = Gtk.Frame(label=board["title"])
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, border_width=12)
            box.set_size_request(255, -1)
            box.pack_start(label(row["chat"], "quiet"), False, False, 0)
            frame.add(box)
            for w in board["widgets"]:
                v, kind = w["value"], w["kind"]
                if kind == "button":
                    button = Gtk.Button(label=w["label"], tooltip_text=v)
                    button.connect("clicked", lambda _, r=row, k=w["id"]: page_request(
                        "dashboard_click", agent=r["agent"], revision=r["revision"], widget=k))
                    box.pack_start(button, False, False, 0)
                    continue
                caption = label(w["label"], "section")
                box.pack_start(caption, False, False, 0)
                if kind == "graph":
                    plot = Gtk.DrawingArea()
                    plot.set_size_request(120, 48)
                    plot.connect("draw", self.plot, v)
                    caption.set_tooltip_text(str(v))
                    box.pack_start(plot, False, False, 0)
                    shown = str(v[-1]) if v else "—"
                elif kind in ("progress", "gauge"):
                    low, high = w.get("min", 0), w.get("max", 100)
                    fraction = (v - low) / (high - low)
                    bar = Gtk.ProgressBar(fraction=fraction) if kind == "progress" else Gtk.LevelBar(value=fraction)
                    box.pack_start(bar, False, False, 0)
                    shown = str(v)
                else:
                    shown = "\n".join(v) if kind == "events" else v
                value = label(shown + (" " + w["unit"] if w.get("unit") else ""))
                value.set_line_wrap(True)
                value.set_max_width_chars(38)
                value.set_selectable(True)
                box.pack_start(value, False, False, 0)
            self.flow.add(frame)
        self.notice.set_text("" if rows else "No chats have published a dashboard.")
        self.flow.show_all()

    @staticmethod
    def plot(view, cr, points):
        if not points:
            return False
        width, height = view.get_allocated_width()-4, view.get_allocated_height()-4
        low, high = min(points), max(points)
        cr.set_source_rgb(0.15, 0.55, 0.76)
        cr.set_line_width(2)
        for i, value in enumerate(points):
            x = 2 + width * i / max(1, len(points)-1)
            y = 2 + height * ((high-value)/(high-low) if high != low else .5)
            if i == 0:
                cr.move_to(x, y)
            cr.line_to(x + .1, y)
        cr.stroke()
        return False
