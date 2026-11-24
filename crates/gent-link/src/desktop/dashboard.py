import unicodedata

from gi.repository import Pango


def dashboard_web_url(value):
    if not isinstance(value, str) or any(
        c == "\\" or c.isspace() or unicodedata.category(c) == "Cc" for c in value
    ):
        return False
    try:
        uri = GLib.Uri.parse(value, GLib.UriFlags.ENCODED | GLib.UriFlags.PARSE_RELAXED)
    except GLib.Error:
        return False
    return uri.get_scheme() in ("http", "https") and bool(uri.get_host())


def dashboard_label(text, style=None):
    widget = label(text, style)
    widget.set_line_wrap(True)
    widget.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
    return widget


class DashboardGrid(Gtk.Fixed):
    column_width = 280
    minimum_height = 160
    gap = 10

    def do_get_request_mode(self):
        return Gtk.SizeRequestMode.HEIGHT_FOR_WIDTH

    def do_get_preferred_width(self):
        return 0, self.column_width

    def measure_rows(self, width):
        cards = self.get_children()
        columns = max(1, min(4, width // self.column_width))
        rows = []
        minimums = []
        for start in range(0, len(cards), columns):
            children = cards[start:start + columns]
            count = len(children)
            base, extra = divmod(width - self.gap * (count - 1), count)
            row = [(card, max(1, base + (i < extra))) for i, card in enumerate(children)]
            rows.append(row)
            natural = max(card.get_preferred_height_for_width(w)[1] for card, w in row)
            minimums.append(max(self.minimum_height, natural))
        return rows, minimums

    def do_get_preferred_height_for_width(self, width):
        _, minimums = self.measure_rows(width)
        height = sum(minimums) + self.gap * max(0, len(minimums) - 1)
        return height, height

    def do_get_preferred_height(self):
        return self.do_get_preferred_height_for_width(self.column_width)

    def do_size_allocate(self, allocation):
        self.set_allocation(allocation)
        rows, heights = self.measure_rows(allocation.width)
        remaining = max(sum(heights), allocation.height - self.gap * (len(rows) - 1))
        cards_left = sum(map(len, rows))
        # Reserve the most demanding rows first. Divide remaining height in
        # proportion to card count so the wider cards in a short row get less height.
        for i in sorted(range(len(rows)), key=lambda i: heights[i] / len(rows[i]), reverse=True):
            count = len(rows[i])
            heights[i] = max(heights[i], remaining * count // cards_left)
            remaining -= heights[i]
            cards_left -= count

        y = allocation.y
        for row, height in zip(rows, heights):
            x = allocation.x
            for card, width in row:
                rect = Gdk.Rectangle()
                rect.x, rect.y, rect.width, rect.height = x, y, width, height
                card.size_allocate(rect)
                x += width + self.gap
            y += height + self.gap


class DashboardPane(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8, border_width=12)
        self.rows = None
        self.notice = notice_label()
        self.grid = DashboardGrid()
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.add(self.grid)
        self.pack_start(scroll, True, True, 0)
        self.pack_start(self.notice, False, False, 0)

    def load(self):
        page_request("dashboard")

    def receive(self, reply):
        if "rows" not in reply:
            self.notice.set_text(reply.get("error") or reply.get("notice", ""))
            return
        rows = reply["rows"]
        self.notice.set_text("" if rows else "No chats have published a dashboard.")
        if self.rows != rows:
            self.rows = rows
            for card in self.grid.get_children():
                self.grid.remove(card)
            for row in rows:
                self.grid.put(self.card(row), 0, 0)
            self.grid.show_all()

    def card(self, row):
        board = row["board"]
        frame = Gtk.Frame(label=board["title"])
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, border_width=12)
        frame.get_label_widget().set_ellipsize(Pango.EllipsizeMode.END)
        frame.get_label_widget().set_tooltip_text(board["title"])
        box.pack_start(dashboard_label(row["chat"], "quiet"), False, False, 0)
        frame.add(box)
        for w in board["widgets"]:
            v, kind = w["value"], w["kind"]
            if kind == "link":
                if dashboard_web_url(v):
                    link = Gtk.LinkButton.new_with_label(v, w["label"])
                    link.set_tooltip_text(v)
                    link.get_child().set_ellipsize(Pango.EllipsizeMode.END)
                    box.pack_start(link, False, False, 0)
                else:
                    box.pack_start(dashboard_label(w["label"]), False, False, 0)
                continue
            if kind == "button":
                button = Gtk.Button(label=w["label"], tooltip_text=v)
                button.get_child().set_ellipsize(Pango.EllipsizeMode.END)
                button.connect("clicked", lambda _, r=row, k=w["id"]: page_request(
                    "dashboard_click", agent=r["agent"], revision=r["revision"], widget=k))
                box.pack_start(button, False, False, 0)
                continue
            caption = dashboard_label(w["label"], "section")
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
            value = dashboard_label(shown + (" " + w["unit"] if w.get("unit") else ""))
            value.set_max_width_chars(38)
            value.set_selectable(True)
            box.pack_start(value, False, False, 0)
        return frame

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
