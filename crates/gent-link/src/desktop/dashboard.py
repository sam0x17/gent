import base64
import math
import re
import unicodedata

from gi.repository import Atk, Pango


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


class DashboardGraphic(Gtk.DrawingArea):
    def __init__(self, width, height, title, description, upscale):
        super().__init__()
        self.width, self.height = width, height
        self.upscale = upscale
        accessible = self.get_accessible()
        accessible.set_role(Atk.Role.IMAGE)
        accessible.set_name(title)
        accessible.set_description(description)

    def do_get_request_mode(self):
        return Gtk.SizeRequestMode.HEIGHT_FOR_WIDTH

    def do_get_preferred_width(self):
        return 1, min(260, self.width)

    def do_get_preferred_height_for_width(self, width):
        if not self.upscale:
            width = min(width, self.width)
        height = max(1, math.ceil(width * self.height / self.width))
        if not self.upscale:
            height = min(360, height)
        return height, height

    def do_get_preferred_height(self):
        return self.do_get_preferred_height_for_width(self.do_get_preferred_width()[1])


def dashboard_chart(widget):
    description = widget.get("chart_description", "")
    svg = widget.get("chart_svg")
    if not svg:
        return dashboard_label(description or "Chart unavailable")
    try:
        gi.require_version("Rsvg", "2.0")
        from gi.repository import Rsvg
        # The supervisor generates this field. Published widget values are data only.
        handle = Rsvg.Handle.new_from_data(svg.encode("utf-8"))
        sized, width, height = handle.get_intrinsic_size_in_pixels()
        if not sized or width <= 0 or height <= 0:
            raise ValueError("missing chart dimensions")
    except (GLib.Error, ImportError, ValueError, AttributeError):
        return dashboard_label(description or "Chart unavailable")

    def draw(view, cr):
        rect = Rsvg.Rectangle()
        rect.width, rect.height = view.get_allocated_width(), view.get_allocated_height()
        handle.render_document(cr, rect)
        return False

    view = DashboardGraphic(int(width), int(height), widget["label"], description, upscale=True)
    view.connect("draw", draw)
    return view


def dashboard_image(title, value):
    if not isinstance(value, str) or len(value) > 32 * 1024:
        return dashboard_label("Image unavailable")
    header, _, encoded = value.partition(",")
    image_format = {"data:image/png;base64": "png", "data:image/jpeg;base64": "jpeg"}.get(header)
    if not image_format:
        return dashboard_label("Image unavailable")

    def limit_size(loader, width, height):
        if not (0 < width <= 2048 and 0 < height <= 2048 and width * height <= 1_048_576):
            # GdkPixbuf uses (0, 0) in its own metadata probe to stop before decoding pixels.
            loader.set_size(0, 0)

    try:
        data = base64.b64decode(encoded, validate=True)
        end = b"\x00\x00\x00\x00IEND\xaeB\x60\x82" if image_format == "png" else b"\xff\xd9"
        if not data.endswith(end):
            return dashboard_label("Image unavailable")
        loader = GdkPixbuf.PixbufLoader.new_with_type(image_format)
        loader.connect("size-prepared", limit_size)
        try:
            loader.write(data)
        finally:
            loader.close()
        pixbuf = loader.get_pixbuf()
        if pixbuf is None:
            return dashboard_label("Image unavailable")
    except (GLib.Error, ValueError):
        return dashboard_label("Image unavailable")
    width, height = pixbuf.get_width(), pixbuf.get_height()

    def draw(view, cr):
        scale = min(1, view.get_allocated_width() / width, view.get_allocated_height() / height)
        cr.translate((view.get_allocated_width() - width * scale) / 2, 0)
        cr.scale(scale, scale)
        Gdk.cairo_set_source_pixbuf(cr, pixbuf, 0, 0)
        cr.paint()
        return False

    view = DashboardGraphic(width, height, title, f"{image_format.upper()} image, {width} × {height} pixels", upscale=False)
    view.connect("draw", draw)
    return view


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
        if reply.get("unchanged"):
            self.show_dashboard_notice(self.rows)
            return
        if "rows" not in reply:
            self.notice.set_text(reply.get("error") or reply.get("notice", ""))
            return
        rows = reply["rows"]
        self.show_dashboard_notice(rows)
        if self.rows != rows:
            self.rows = rows
            for card in self.grid.get_children():
                self.grid.remove(card)
            for row in rows:
                self.grid.put(self.card(row), 0, 0)
            self.grid.show_all()

    def show_dashboard_notice(self, rows):
        self.notice.set_text("" if rows else "No chats have published a dashboard.")

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
            unit = " " + w["unit"] if w.get("unit") else ""
            if kind == "metric":
                metric = dashboard_label("")
                title = GLib.markup_escape_text(re.sub(r"[:\s]+\Z", "", w["label"]))
                number = GLib.markup_escape_text(str(v) + unit)
                metric.set_markup(f"<b>{title}:</b> {number}")
                metric.set_selectable(True)
                box.pack_start(metric, False, False, 0)
                continue
            caption = dashboard_label(w["label"], "section")
            box.pack_start(caption, False, False, 0)
            if kind == "image":
                box.pack_start(dashboard_image(w["label"], v), False, False, 0)
                continue
            if kind in ("graph", "bar", "pie", "radar", "scatter"):
                box.pack_start(dashboard_chart(w), False, False, 0)
                if kind != "graph":
                    continue
                shown = str(v[-1]) if v else "—"
            elif kind in ("progress", "gauge"):
                low, high = w.get("min", 0), w.get("max", 100)
                fraction = (v - low) / (high - low)
                bar = Gtk.ProgressBar(fraction=fraction) if kind == "progress" else Gtk.LevelBar(value=fraction)
                box.pack_start(bar, False, False, 0)
                shown = str(v)
            else:
                shown = "\n".join(v) if kind == "events" else v
            value = dashboard_label(shown + unit)
            value.set_max_width_chars(38)
            value.set_selectable(True)
            box.pack_start(value, False, False, 0)
        return frame
