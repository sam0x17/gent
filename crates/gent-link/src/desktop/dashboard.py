import base64
from collections import Counter
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
    widget.set_selectable(True)
    widget.set_line_wrap(True)
    widget.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
    return widget


def dashboard_reading(value, unit):
    if value is None:
        return "—"
    number = str(value).removesuffix(".0")
    if not unit:
        return number
    return number + ("" if unit == "%" else " ") + unit


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
    expand_short_row = True
    gap = 10

    def do_get_request_mode(self):
        return Gtk.SizeRequestMode.HEIGHT_FOR_WIDTH

    def do_get_preferred_width(self):
        return 0, self.column_width

    def columns(self, width):
        return max(1, min(4, width // self.column_width))

    def row_space(self, width, count):
        return width - self.gap * (count - 1)

    def chart_widths(self, width, inset):
        if width is None:
            return [260]
        widths = []
        for count in range(1, self.columns(width) + 1):
            content = self.row_space(width, count) / count - inset
            widths.append(max(160, min(16384, 8 * math.floor(content / 8 + .5))))
        return widths

    def measure_rows(self, width):
        cards = self.get_children()
        columns = self.columns(width)
        rows = []
        minimums = []
        for start in range(0, len(cards), columns):
            children = cards[start:start + columns]
            count = len(children) if self.expand_short_row else columns
            base, extra = divmod(self.row_space(width, count), count)
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


class DashboardColumns(DashboardGrid):
    """Lay out a section at its allocated width inside one board."""
    minimum_height = 0
    expand_short_row = False
    gap = 8

    def __init__(self, children, column_width):
        super().__init__()
        self.column_width = column_width
        self.count = len(children)
        for child in children:
            self.put(child, 0, 0)

    def columns(self, width):
        return max(1, min(self.count, (width + self.gap) // (self.column_width + self.gap)))


def dashboard_lane(lane):
    card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    card.get_style_context().add_class("gent-dashboard-lane")
    card.get_accessible().set_name(lane["label"])
    card.add(dashboard_label(lane["label"], "gent-dashboard-heading"))
    state = dashboard_label(lane["state"], "gent-dashboard-state")
    state.get_style_context().add_class(lane["tone"])
    state.set_halign(Gtk.Align.START)
    card.add(state)
    for line in lane["details"]:
        card.add(dashboard_label(line))
    return card


def dashboard_select_feed(field, title, text):
    dialog = Gtk.Dialog(title=title, transient_for=field.get_toplevel(), modal=True, destroy_with_parent=True)
    dialog.add_button("Close", Gtk.ResponseType.CLOSE)
    dialog.connect("response", lambda window, _: window.destroy())
    view = Gtk.TextView(editable=False, wrap_mode=Gtk.WrapMode.WORD_CHAR, left_margin=10, right_margin=10)
    view.get_accessible().set_name(title)
    buffer = view.get_buffer()
    buffer.set_text(text)
    buffer.place_cursor(buffer.get_start_iter())
    scroll = Gtk.ScrolledWindow()
    scroll.add(view)
    dialog.get_content_area().pack_start(scroll, True, True, 0)
    dialog.set_default_size(440, 320)
    dialog.show_all()
    view.grab_focus()


def dashboard_feed(title, rows, entire_feed=None):
    feed = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    feed.get_style_context().add_class("gent-dashboard-feed")
    feed.add(dashboard_label(title, "gent-dashboard-heading"))
    body = dashboard_label("\n".join(rows), "gent-dashboard-current")
    if entire_feed is not None:
        def populate(field, menu):
            name, text = entire_feed
            copy = Gtk.MenuItem(label="Copy entire feed")
            copy.connect("activate", lambda _: field.get_clipboard(Gdk.SELECTION_CLIPBOARD).set_text(text, -1))
            select = Gtk.MenuItem(label="Select feed text…")
            select.connect("activate", lambda _: dashboard_select_feed(field, name, text))
            for item in (copy, select):
                menu.append(item)
                item.show()

        body.connect("populate-popup", populate)
    feed.add(body)
    return feed


class DashboardFeedLayouts(Gtk.Stack):
    """Negotiate the feed height for the same page that receives the allocation."""
    def __init__(self, pair, split):
        super().__init__(homogeneous=False)
        self.pair, self.split = pair, split
        self.add(pair)
        self.add(split)
        self.right = pair.get_children()[1].get_children()[1]
        self.continued_at = len(split.get_children()[1].get_children()[1].get_text()) + 1
        self.spans_break = False
        for prop in ("cursor-position", "selection-bound"):
            self.right.connect("notify::" + prop, self.selection_changed)

    def page(self, width):
        return self.split if not self.spans_break and self.split.columns(width) == 3 else self.pair

    def selection_changed(self, *_):
        selected, start, end = self.right.get_selection_bounds()
        # The newline at the break belongs to the full label only.
        spans = selected and start < self.continued_at <= end
        if self.spans_break != spans:
            self.spans_break = spans
            self.queue_resize()

    def switch(self, old, new):
        # GtkStack restores focus to its last child and GtkLabel may select all
        # on focus. Restore the actual cursor, anchor and focus after switching.
        saved = []
        for column, card in enumerate(old.get_children()):
            for part, field in enumerate(card.get_children()):
                if not field.is_focus() and not field.get_selection_bounds()[0]:
                    continue
                anchor, cursor = field.props.selection_bound, field.props.cursor_position
                dest = min(column, 1)
                if part == 1 and column > 0:
                    if column == 2:
                        anchor += self.continued_at
                        cursor += self.continued_at
                    elif new == self.split and min(anchor, cursor) >= self.continued_at:
                        dest = 2
                        anchor -= self.continued_at
                        cursor -= self.continued_at
                target = new.get_children()[dest].get_children()[part]
                saved.append((target, anchor, cursor, field.is_focus()))
        self.set_visible_child(new)
        for target, _, _, focused in saved:
            if focused:
                target.grab_focus()
        for target, anchor, cursor, _ in saved:
            target.select_region(anchor, cursor)

    def do_get_preferred_height_for_width(self, width):
        return self.page(width).get_preferred_height_for_width(width)

    def do_size_allocate(self, allocation):
        new = self.page(allocation.width)
        old = self.get_visible_child()
        if old is not None and old != new:
            self.switch(old, new)
        Gtk.Stack.do_size_allocate(self, allocation)


def dashboard_feeds(left, right):
    pair = DashboardColumns([dashboard_feed(w["label"], w["value"]) for w in (left, right)], 280)
    rows = right["value"]
    if len(rows) < max(4, 2 * len(left["value"])):
        return pair
    title = right["label"]
    middle = (len(rows) + 1) // 2
    whole = (title, "\n".join(rows))
    split = DashboardColumns([dashboard_feed(left["label"], left["value"]),
                              dashboard_feed(title, rows[:middle], whole),
                              dashboard_feed(title + " (continued)", rows[middle:], whole)], pair.column_width)
    return DashboardFeedLayouts(pair, split)


DASHBOARD_CSS = b"""
.gent-dashboard { padding: 12px; outline-color: @theme_selected_bg_color; }
.gent-dashboard, .gent-dashboard viewport { background-color: @theme_bg_color; }
.gent-dashboard-card {
    background: @theme_base_color;
    color: @theme_text_color;
    border: 1px solid alpha(@theme_text_color, .15);
    border-radius: 10px;
    outline-color: @theme_selected_bg_color;
}
.gent-dashboard-card > border { border: none; }
.gent-dashboard-hide { min-width: 24px; min-height: 24px; padding: 0; }
.gent-dashboard-restore { min-height: 0; padding: 1px 2px; font-size: 0.9em; }
.gent-dashboard-restore > label { text-decoration-line: underline; }
.gent-dashboard-title { font-size: 18px; font-weight: bold; }
.gent-dashboard-publisher { color: mix(@theme_text_color, @theme_base_color, .30); }
.gent-dashboard-heading { font-weight: bold; }
.gent-dashboard-lane, .gent-dashboard-feed {
    background-color: mix(@theme_base_color, @theme_bg_color, .45);
    border: 1px solid alpha(@theme_text_color, .15);
    border-radius: 6px;
    padding: 9px;
}
.gent-dashboard-state {
    background-color: alpha(@theme_text_color, .07);
    border-left: 3px solid alpha(@theme_text_color, .45);
    padding: 2px 6px;
    font-weight: bold;
}
.gent-dashboard-state.info { border-color: @theme_selected_bg_color; }
.gent-dashboard-state.success { border-color: @success_color; }
.gent-dashboard-state.warning { border-color: @warning_color; }
.gent-dashboard-state.critical { border-color: @error_color; }
.gent-dashboard-current { font-feature-settings: "tnum"; }
.gent-dashboard-card levelbar trough { padding: 0; border: none; background: none; }
.gent-dashboard-card progressbar trough, .gent-dashboard-card progressbar progress,
.gent-dashboard-card levelbar block {
    margin: 0;
    padding: 0;
    min-height: 4px;
    border-radius: 3px;
    border: none;
}
.gent-dashboard-card progressbar trough, .gent-dashboard-card levelbar block.empty { background: alpha(@theme_text_color, .15); }
.gent-dashboard-card progressbar progress, .gent-dashboard-card levelbar block.filled { background: @theme_selected_bg_color; }
.gent-dashboard-link { padding: 2px 0; }
"""


class DashboardCard(Gtk.Frame):
    def __init__(self, title, publisher, agent=None):
        super().__init__(shadow_type=Gtk.ShadowType.NONE)
        self.get_style_context().add_class("gent-dashboard-card")
        self.body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin=15)
        self.add(self.body)
        header = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.title = dashboard_label(title, "gent-dashboard-title")
        self.publisher = dashboard_label(publisher, "gent-dashboard-publisher")
        header.add(self.title)
        header.add(self.publisher)
        heading = Gtk.Box(spacing=6)
        heading.pack_start(header, True, True, 0)
        if agent is not None:
            hide = Gtk.Button(label="×", tooltip_text="Hide dashboard", relief=Gtk.ReliefStyle.NONE)
            hide.set_valign(Gtk.Align.START)
            hide.get_style_context().add_class("gent-dashboard-hide")
            hide.get_accessible().set_name("Hide dashboard")
            hide.connect("clicked", lambda _: page_request("dashboard_hide", agent=agent))
            heading.pack_end(hide, False, False, 0)
        self.body.add(heading)
        self.get_accessible().set_name(title)

    def update_attachment_heading(self, *_):
        attachment = self.attachment
        compact = (attachment is not None and attachment.view is not None
                   and attachment.get_visible_child() == attachment.view)
        self.publisher.set_no_show_all(compact)
        self.publisher.set_visible(not compact)
        self.title.set_line_wrap(not compact)
        self.title.set_ellipsize(Pango.EllipsizeMode.END if compact else Pango.EllipsizeMode.NONE)
        self.body.set_margin_top(6 if compact else 15)
        self.body.set_margin_bottom(6 if compact else 15)
        self.body.set_spacing(4 if compact else 12)
        publisher = self.publisher.get_text()
        attribution = f"Published by {publisher}" if compact and publisher else ""
        self.get_accessible().set_description(attribution)
        self.title.get_accessible().set_description(attribution)
        tooltip = ". ".join(filter(None, (self.title.get_text(), attribution)))
        self.title.set_tooltip_text(tooltip if compact else None)

    def horizontal_inset(self):
        context = self.get_style_context()
        state = context.get_state()
        border, padding = context.get_border(state), context.get_padding(state)
        margins = self.body.get_margin_start() + self.body.get_margin_end()
        return border.left + border.right + padding.left + padding.right + margins

    def palette(self):
        context = self.get_style_context()
        state = context.get_state()
        background = context.get_property("background-color", state)
        # The viewport paints the themed canvas beneath translucent card surfaces.
        found, canvas = context.lookup_color("theme_bg_color")
        canvas = canvas if found else background

        def over(color, base):
            return [v * color.alpha + bg * (1 - color.alpha)
                    for v, bg in zip((color.red, color.green, color.blue), base)]

        surface = over(background, (canvas.red, canvas.green, canvas.blue))

        def channels(components):
            return [round(255 * v) for v in components]

        def foreground(widget):
            style = widget.get_style_context()
            return channels(over(style.get_color(style.get_state()), surface))

        # Both native bar fills share the card's focus outline accent.
        accent = context.get_property("outline-color", state)
        return {"surface": channels(surface), "text": foreground(self.title),
                "secondary": foreground(self.publisher), "accent": channels(over(accent, surface))}


class DashboardPane(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.get_style_context().add_class("gent-dashboard")
        provider = Gtk.CssProvider()
        provider.load_from_data(DASHBOARD_CSS)
        screen = self.get_screen()
        Gtk.StyleContext.add_provider_for_screen(screen, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        self.connect("destroy", lambda *_: Gtk.StyleContext.remove_provider_for_screen(screen, provider))
        # The first request needs the same style nodes before a publisher has supplied a card.
        self.empty_card = DashboardCard("", "")
        self.example = None
        self.all_hidden = False
        self.rows = None
        self.hidden = []
        self.grid_width = None
        self.last_layout = None
        self.refresh_source = 0
        self.load_requested = False
        self.notice = notice_label()
        self.showing_feedback = False
        self.restore = Gtk.MenuButton(label="Restore hidden dashboards", halign=Gtk.Align.END,
                                      relief=Gtk.ReliefStyle.NONE)
        self.restore.set_state_flags(Gtk.StateFlags.LINK, False)
        self.restore.get_style_context().add_class("gent-dashboard-restore")
        self.restore.set_no_show_all(True)
        self.pack_start(self.restore, False, False, 0)
        self.grid = DashboardGrid()
        self.grid.connect("size-allocate", self.grid_allocated)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.add(self.grid)
        self.vadjustment = scroll.get_vadjustment()
        self.pack_start(scroll, True, True, 0)
        self.pack_start(self.notice, False, False, 0)

        self.connect("map", lambda *_: self.load())
        self.connect("style-updated", self.queue_refresh)

    def load(self):
        self.load_requested = True
        self.queue_refresh()

    def grid_allocated(self, _, allocation):
        if allocation.width != self.grid_width:
            self.grid_width = allocation.width
            self.queue_refresh()

    def queue_refresh(self, *_):
        if not self.get_mapped():
            return
        if self.refresh_source:
            GLib.source_remove(self.refresh_source)
        if self.load_requested:
            self.refresh_source = GLib.idle_add(self.refresh)
        else:
            # A window drag may span many GTK frames. Render the last allocation.
            self.refresh_source = GLib.timeout_add(100, self.refresh)

    def refresh(self):
        self.refresh_source = 0
        if self.get_mapped():
            cards = self.grid.get_children()
            card = cards[0] if cards else self.empty_card
            layout = {"palette": card.palette(),
                      "chart_widths": self.grid.chart_widths(self.grid_width, card.horizontal_inset())}
            if self.load_requested or layout != self.last_layout:
                op = "dashboard" if self.load_requested else "dashboard_layout"
                self.load_requested = False
                self.last_layout = layout
                page_request(op, **layout)
        return False

    def set_hidden(self, hidden):
        if self.hidden == hidden:
            return
        self.hidden = hidden
        old_menu = self.restore.get_popup()
        if old_menu is not None:
            old_menu.destroy()
        if hidden:
            menu = Gtk.Menu()
            names = [f"{item['title']} — {item['chat']}" for item in hidden]
            counts = Counter(names)
            for item, name in zip(hidden, names):
                agent = item["agent"]
                if counts[name] > 1:
                    name = f"{name} ({agent})"
                choice = Gtk.MenuItem(label=name)
                choice.connect("activate", lambda _, agent=agent: page_request("dashboard_restore", agent=agent))
                menu.append(choice)
            menu.show_all()
            self.restore.set_popup(menu)
        self.restore.set_visible(bool(hidden))

    def displayed_rows(self):
        if self.example and not self.showing_feedback:
            return [self.example]
        return self.rows or []

    def receive(self, reply):
        previous = self.displayed_rows()
        was_example = self.example is not None and not self.showing_feedback
        locked = reply.get("pro_required", False)
        if locked or "rows" in reply:
            self.all_hidden = reply.get("all_hidden", False)
            self.rows = [] if locked else reply["rows"]
            self.example = reply.get("example") if not self.rows else None
        if locked:
            self.set_hidden([])
            self.showing_feedback = False
            self.notice.set_markup('Dashboards require an active Gent Pro plan for this cluster. '
                                   '<a href="https://gent.link/pricing">View plans</a>')
        else:
            if "hidden" in reply:
                self.set_hidden(reply["hidden"])
            feedback = reply.get("error") or reply.get("notice")
            if feedback:
                self.showing_feedback = True
                self.notice.set_text(feedback)
            elif not (self.showing_feedback and (reply.get("layout_only") or reply.get("stale"))):
                self.showing_feedback = False
                empty = "All dashboards are hidden." if self.all_hidden else "No chats have published a dashboard."
                self.notice.set_text(empty if self.rows == [] else "")
        displayed = self.displayed_rows()
        if previous != displayed:
            cards = self.grid.get_children()
            retained = 0
            # Ordinary widget/layout updates retain their existing redraw semantics.
            existing = cards if any(getattr(card, "attachment", None) is not None for card in cards) else []
            for card, old, row in zip(existing, previous, displayed):
                # The header holds the native hide action. Keep its frame (and
                # any loaded document) while the same board occupies this slot.
                if (old.get("agent"), old["chat"], old["board"]["title"]) != (
                    row.get("agent"), row["chat"], row["board"]["title"]
                ):
                    break
                if old != row:
                    self.card(row, card)
                retained += 1
            for card in cards[retained:]:
                card.destroy()
            for row in displayed[retained:]:
                self.grid.put(self.card(row), 0, 0)
            self.grid.show_all()
            if self.example and not was_example and not self.showing_feedback:
                self.vadjustment.set_value(self.vadjustment.get_lower())
            cards = self.grid.get_children()
            if cards:
                first = cards[0]
                if not retained:
                    for widget in (first, first.title, first.publisher):
                        widget.connect("style-updated", self.queue_refresh)
                self.queue_refresh()

    def card(self, row, frame=None):
        board = row["board"]
        if frame is None:
            frame = DashboardCard(board["title"], row["chat"], row.get("agent"))
        source = board.get("static_html")
        revision = row.get("revision")
        attachment = getattr(frame, "attachment", None)
        if attachment is not None and (attachment.source, attachment.revision) == (source, revision):
            body = attachment.native
            for child in body.get_children():
                child.destroy()
        else:
            for child in frame.body.get_children()[1:]:
                child.destroy()
            frame.attachment = None
            if attachment is not None:
                frame.update_attachment_heading()
            body = frame.body
            if isinstance(source, str) and source and (browser := dashboard_browser()):
                try:
                    frame.attachment = DashboardStatic(browser, source, revision)
                except (OSError, GLib.Error):
                    pass
                if frame.attachment is not None:
                    frame.attachment.connect("notify::visible-child", frame.update_attachment_heading)
                    frame.body.pack_start(frame.attachment, True, True, 0)
                    body = frame.attachment.native
        widgets = board["widgets"]
        for section in board.get("layout_v1", range(len(widgets))):
            if isinstance(section, dict):
                if "lanes" in section:
                    cards = [dashboard_lane(lane) for lane in section["lanes"]]
                    body.add(DashboardColumns(cards, 140))
                elif "feeds" in section:
                    left, right = section["feeds"]
                    body.add(dashboard_feeds(widgets[left], widgets[right]))
                continue
            w = widgets[section]
            v, kind = w["value"], w["kind"]
            if kind in ("button", "link") and not row.get("agent"):
                continue
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            body.add(box)
            if kind == "link":
                if dashboard_web_url(v):
                    link = Gtk.LinkButton.new_with_label(v, w["label"])
                    link.set_halign(Gtk.Align.START)
                    link.get_style_context().add_class("gent-dashboard-link")
                    link.set_tooltip_text(v)
                    link.get_child().set_ellipsize(Pango.EllipsizeMode.END)
                    box.pack_start(link, False, False, 0)
                else:
                    box.pack_start(dashboard_label(w["label"]), False, False, 0)
                continue
            if kind == "button":
                button = Gtk.Button(label=w["label"], tooltip_text=v)
                button.set_halign(Gtk.Align.START)
                button.get_child().set_ellipsize(Pango.EllipsizeMode.END)
                button.connect("clicked", lambda _, r=row, k=w["id"]: page_request(
                    "dashboard_click", agent=r["agent"], revision=r["revision"], widget=k))
                box.pack_start(button, False, False, 0)
                continue
            if kind == "metric":
                metric = dashboard_label("")
                title = GLib.markup_escape_text(re.sub(r"[:\s]+\Z", "", w["label"]))
                number = GLib.markup_escape_text(dashboard_reading(v, w.get("unit")))
                metric.set_markup(f"<b>{title}:</b> {number}")
                box.pack_start(metric, False, False, 0)
                continue
            caption = dashboard_label(w["label"], "gent-dashboard-heading")
            if kind in ("graph", "progress", "gauge"):
                heading = Gtk.Box(spacing=8)
                heading.pack_start(caption, True, True, 0)
                current = (v[-1] if v else None) if kind == "graph" else v
                readout = dashboard_label(dashboard_reading(current, w.get("unit")), "gent-dashboard-current")
                readout.set_xalign(1)
                heading.pack_end(readout, False, False, 0)
                box.add(heading)
            else:
                box.add(caption)
            if kind == "image":
                box.add(dashboard_image(w["label"], v))
                continue
            if kind in ("graph", "bar", "pie", "radar", "scatter"):
                box.add(dashboard_chart(w))
                continue
            if kind in ("progress", "gauge"):
                low, high = w.get("min", 0), w.get("max", 100)
                fraction = (v - low) / (high - low)
                bar = Gtk.ProgressBar(fraction=fraction) if kind == "progress" else Gtk.LevelBar(value=fraction)
                bar.get_accessible().set_name(w["label"])
                box.add(bar)
                continue
            shown = "\n".join(v) if kind == "events" else v
            value = dashboard_label(shown + (" " + w["unit"] if w.get("unit") else ""))
            value.set_max_width_chars(38)
            box.pack_start(value, False, False, 0)
        return frame
