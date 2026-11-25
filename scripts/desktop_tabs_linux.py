"""Drive the real tab widgets via AT-SPI in the smoke test's private graphical session."""
from collections import Counter
from itertools import groupby
import json
from pathlib import Path
import re
import subprocess
import time

import gi
import pyatspi

gi.require_version("Gdk", "3.0")
gi.require_version("GdkX11", "3.0")
from gi.repository import Gdk, GdkX11

from desktop_dashboard_samples import chart_widgets, image_uri


def wait_for(check, description, timeout=12):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = check()
        if result:
            return result
        time.sleep(.1)
    raise RuntimeError("Timed out waiting for " + description)


def find(name, role=None):
    def match(child):
        return (child.getState().contains(pyatspi.STATE_SHOWING)
                and (name is None or child.name == name)
                and (role is None or child.getRoleName() == role))
    return pyatspi.findDescendant(pyatspi.Registry.getDesktop(0), match)


def get(name, role=None, timeout=12):
    return wait_for(lambda: find(name, role), name or role, timeout)


def tab(name):
    item = get(name, "page tab")
    assert item.parent.querySelection().selectChild(item.getIndexInParent())


def click(name):
    button = wait_for(lambda: pyatspi.findDescendant(pyatspi.Registry.getDesktop(0), lambda c:
                       c.name == name and c.getRole() == pyatspi.ROLE_PUSH_BUTTON
                       and c.getState().contains(pyatspi.STATE_SHOWING)
                       and c.getState().contains(pyatspi.STATE_SENSITIVE)), name)
    assert button.queryAction().doAction(0), name


def member_table():
    return get(None, "table").queryTable()


def row(node_id):
    table = member_table()
    for index in range(table.nRows):
        if table.getAccessibleAt(index, table.nColumns - 1).name == node_id:
            return [table.getAccessibleAt(index, col).name for col in range(table.nColumns)]


def selected_member():
    table = member_table()
    selected, = table.getSelectedRows()
    return table.getAccessibleAt(selected, table.nColumns - 1).name


def check_member_tooltip(cell):
    # GTK's tooltip popup is visible on X11 but isn't exported in the AT-SPI tree.
    def tooltip_visible():
        ids = subprocess.check_output(["xdotool", "search", "--onlyvisible", "--pid", str(cell.get_process_id())])
        for xid in ids.split():
            window = GdkX11.X11Window.foreign_new_for_display(Gdk.Display.get_default(), int(xid))
            if window and window.get_type_hint() == Gdk.WindowTypeHint.TOOLTIP:
                return True
        return False

    x, y, width, height = cell.queryComponent().getExtents(pyatspi.DESKTOP_COORDS)
    subprocess.run(["xdotool", "mousemove", str(x + width // 2), str(y + height // 2)], check=True)
    wait_for(tooltip_visible, "hosted member tooltip")
    subprocess.run(["xdotool", "mousemove", "0", "0"], check=True)


def select_row(id_):
    cell = get(id_, "table cell")
    table = cell.parent.queryTable()
    index = table.getRowAtIndex(cell.getIndexInParent())
    if not table.isRowSelected(index):
        assert table.addRowSelection(index)


def check_node_action_row(node_id):
    select_row(node_id)
    titles = ("Add node…", "Rename node…", "Change role…", "Remove node…")
    buttons = [get(title) for title in titles]
    frame = get("Gent Desktop", "frame").queryComponent()
    coords = pyatspi.DESKTOP_COORDS
    window = frame.getExtents(coords)
    rects = [button.queryComponent().getExtents(coords) for button in buttons]
    assert all(r.y == rects[0].y and r.height == rects[0].height for r in rects), rects
    assert all(a.x + a.width <= b.x for a, b in zip(rects, rects[1:])), rects
    row_end = rects[-1].x + rects[-1].width
    assert window.x <= rects[0].x and row_end <= window.x + window.width
    assert window.y <= rects[0].y and rects[0].y + rects[0].height <= window.y + window.height
    xid = subprocess.check_output(["xdotool", "getactivewindow"], text=True).strip()

    def resize(width):
        subprocess.run(["xdotool", "windowsize", xid, str(width), str(window.height)], check=True)

    # Tab through a real overflow, and click each button only after GTK scrolls it into view.
    try:
        resize(420)
        wait_for(lambda: frame.getExtents(coords).width < row_end - rects[0].x, "window narrower than action row")
        assert buttons[0].queryComponent().grabFocus()
        row_y = buttons[0].queryComponent().getExtents(coords).y
        for index, button in enumerate(buttons):
            if index:
                subprocess.run(["xdotool", "key", "Tab"], check=True)
            wait_for(lambda: button.getState().contains(pyatspi.STATE_FOCUSED), "keyboard focus on " + button.name)

            def visible_rect():
                r = button.queryComponent().getExtents(coords)
                viewport = frame.getExtents(coords)
                if viewport.x <= r.x and r.x + r.width <= viewport.x + viewport.width:
                    return r

            r = wait_for(visible_rect, "entire button in view: " + button.name)
            assert r.y == row_y and r.height == rects[0].height
            subprocess.run(["xdotool", "mousemove", str(r.x + r.width // 2), str(r.y + r.height // 2),
                            "click", "1"], check=True)
            title = button.name.rstrip("…")
            get(title, "dialog")
            click("Cancel")
            wait_for(lambda: not find(title, "dialog"), "dismissed " + title)
    finally:
        resize(window.width)


def assert_selected_tab(title):
    item = get(title, "page tab")
    assert [page.name for page in item.parent] == ["Dashboard", "Status", "Chats", "Settings", "Permissions", "About"]
    wait_for(lambda: item.getState().contains(pyatspi.STATE_SELECTED), title + " selected")


def exercise_setup():
    assert_selected_tab("Status")
    get("Set up this node")
    get("Gent account: Signed out", "label")
    for title in ("Sign in with GitHub", "Create cluster…", "Join with invitation…"):
        get(title)
    assert not find("Nodes") and not find(None, "table") and not find("Known chats")
    click("Join with invitation…")
    get("Invitation code", "label")
    click("Cancel")


def exercise_enrolled_without_daemon(node):
    click("Refresh status")
    get("desktop-test", "label")
    get("Local node · " + node["name"], "label")
    get("Start daemon")
    get("Nodes", "label")
    assert get("Account", "toggle button").queryAction().doAction(0)
    get("Install or repair daemon…")
    assert not find("Create cluster…") and not find("Join with invitation…")


def dashboard_pixels(item):
    x, y, width, height = item.queryComponent().getExtents(pyatspi.DESKTOP_COORDS)
    assert width > 8 and height > 8
    # AT-SPI reports new allocations before the next X11 paint. Wait for two
    # identical frames at these coordinates before checking the visible pixels.
    previous = None

    def painted():
        nonlocal previous
        snap = Gdk.pixbuf_get_from_window(Gdk.get_default_root_window(), x, y, width, height)
        pixels = snap.get_pixels()
        if previous == pixels:
            return snap
        previous = pixels
    return wait_for(painted, "settled GTK pixels for " + item.name)


def assert_chart_pixels(snap, kind, updated):
    width, height = snap.get_width(), snap.get_height()
    pixels, stride, channels = snap.get_pixels(), snap.get_rowstride(), snap.get_n_channels()
    rows = [[pixels[k:k + 3] for k in range(y * stride, y * stride + width * channels, channels)]
            for y in range(height)]
    surface = rows[0][0]

    if kind in ("graph", "scatter"):
        # Locate horizontal gridlines from their common ink. The axes move with
        # the tick labels, and a two-pixel marker can disappear in a thumbnail.
        lines = []
        for y, row in enumerate(rows):
            color, count = Counter(row).most_common(1)[0]
            if color != surface and count > .6 * width:
                # Tick glyphs can contain the same antialias shade as the grid.
                spans = [list(xs) for solid, xs in groupby(range(width), lambda x: row[x] == color) if solid]
                spans = [xs for xs in spans if len(xs) >= 10]
                lines.append((spans[0][0], spans[-1][-1], y))
        assert lines, (kind, width, height)
        left, right, _ = max(lines, key=lambda line: line[1] - line[0])
        bottom = lines[-1][2]
        middle = (left + right) // 2
        between = range(left + (right - left) // 5, left + (right - left) // 3)
        connected = set()
        middle_ys = []
        for y, row in enumerate(rows[:bottom + 4]):
            # Subtract the background on this scanline, including gridlines.
            background = Counter(row[left + 3:right - 2]).most_common(1)[0][0]
            def ink(x):
                return max(abs(a - b) for a, b in zip(row[x], background)) > 24
            # A marker covers at least three adjacent pixels across its center.
            # A one-pixel x tick beneath the baseline can land at the same x.
            if sum(ink(x) for x in range(middle - 4, middle + 5)) >= 3:
                middle_ys.append(y)
            if y < bottom - 2:
                connected.update(x for x in between if ink(x))
        assert middle_ys, (kind, middle, bottom)
        assert (min(middle_ys) > .8 * bottom if updated else max(middle_ys) < .35 * bottom), middle_ys
        assert (len(connected) >= .9 * len(between) if kind == "graph" else not connected), (kind, connected)
    elif kind == "bar":
        # Each bar has several adjacent solid scanlines. Text and the thin axis
        # do not form a band. Measure their lengths in publication order.
        lengths = [max((sum(1 for _ in run) for color, run in groupby(row) if color != surface),
                       default=0) for row in rows]
        bars = []
        for wide, lines in groupby(lengths, key=lambda n: n > width * .06):
            band = list(lines)
            if wide and len(band) >= 3:
                bars.append(max(band))
        expected = [9, 1, 5] if updated else [3, 5, 2]
        assert len(bars) == 3, bars
        assert all(abs(n / max(bars) - value / max(expected)) < .03 for n, value in zip(bars, expected)), bars
    else:
        # Sector area reflects the published share in both legend layouts.
        # The radar's translucent interior forms its largest flat colored region.
        fills = Counter(color for row in rows for color in row if color != surface)
        if kind == "pie":
            counts = [n for _, n in fills.most_common(3)]
            expected = [.6, 1/3, 1/15] if updated else [.5, .3, .2]
            assert len(counts) == 3 and min(counts) > 300, counts
            assert all(abs(n / sum(counts) - share) < .025 for n, share in zip(counts, expected)), counts
        else:
            fill, area = fills.most_common(1)[0]
            assert area > 400, (fill, area)
            return sum(x for row in rows for x, color in enumerate(row) if color == fill) / area


def exercise_dashboard(fixture, agent, cli, xid):
    instruction = "Report the synthetic job status."
    url = "https://example.test/report"
    updated_url = "http://localhost:8042/done"
    board = {"title": "Fixture job", "widgets": [
        {"id": "inspect", "kind": "button", "label": "Inspect job", "value": instruction},
        {"id": "report", "kind": "link", "label": "Job report", "value": url},
        {"id": "status", "kind": "text", "label": "Job status", "value": "Job queued"},
        {"id": "rate", "kind": "metric", "label": "Throughput:", "value": 72.0, "unit": "%"},
        {"id": "log", "kind": "events", "label": "Recent events", "value": ["Queued", "Started"]},
        {"id": "work", "kind": "progress", "label": "Work completed", "value": 15.0, "min": 10, "max": 30, "unit": "ms"},
        {"id": "load", "kind": "gauge", "label": "Queue depth", "value": 6, "max": 8, "unit": "jobs"},
        *chart_widgets(),
        {"id": "preview", "kind": "image", "label": "Job preview", "value": image_uri("PNG")},
    ]}

    def open_report(expected):
        report = get("Job report")
        assert report.queryHyperlink().getURI(0) == expected[-1]
        assert report.queryAction().doAction(0)
        opened = Path.home() / "opened"
        wait_for(lambda: opened.exists() and opened.read_text().splitlines() == expected,
                 "fixture browser opened job report")

    def reveal(name, role):
        def match(obj):
            return obj.name == name and obj.getRole() == role
        item = wait_for(lambda: pyatspi.findDescendant(pyatspi.Registry.getDesktop(0), match), name)
        # GTK 3 returns sentinel coordinates for clipped widgets. Move the real
        # scrollbar until the widget intersects the viewport, then align its top.
        pane = item.parent
        while pane.getRoleName() != "scroll pane":
            pane = pane.parent
        view = pane.queryComponent().getExtents(pyatspi.DESKTOP_COORDS)
        bar, = [c.queryValue() for c in pane if c.getRoleName() == "scroll bar"
                and c.getState().contains(pyatspi.STATE_VERTICAL)]
        limit = int(bar.maximumValue)
        offsets = [bar.currentValue, *range(0, limit, max(1, view.height // 2)), limit]

        def extents():
            return item.queryComponent().getExtents(pyatspi.DESKTOP_COORDS)

        def fully_visible():
            r = extents()
            return view.y <= r.y and r.y + r.height <= view.y + view.height

        for offset in offsets:
            bar.currentValue = offset
            r = extents()
            if fully_visible():
                return item
            if r.y < view.y + view.height and r.y + r.height > view.y:
                bar.currentValue = min(limit, max(0, offset + r.y - view.y))
                wait_for(fully_visible, "whole widget visible: " + name)
                return item
        raise AssertionError("could not reveal " + name)

    def chart_pixels(updated):
        dimensions = {}
        radar_center = None
        for widget in chart_widgets():
            name, kind = widget["label"], widget["kind"]
            item = reveal(name, pyatspi.ROLE_IMAGE)
            detail = "ms" if kind in ("graph", "scatter") else kind
            assert name in item.description and detail in item.description, item.description

            snap = dashboard_pixels(item)
            dimensions[kind] = (snap.get_width(), snap.get_height())
            center = assert_chart_pixels(snap, kind, updated)
            if kind == "radar":
                radar_center = center

        preview = reveal("Job preview", pyatspi.ROLE_IMAGE)
        assert ("JPEG" if updated else "PNG") in preview.description

        def preview_painted():
            snap = dashboard_pixels(preview)
            width, height = snap.get_width(), snap.get_height()
            offset = height // 2 * snap.get_rowstride()
            p = snap.get_pixels()
            left = offset + (width // 2 - 60) * snap.get_n_channels()
            right = offset + (width // 2 + 60) * snap.get_n_channels()
            if updated:
                left, right = right, left
            return p[left] > 180 > p[left + 2] and p[right + 2] > 170 > p[right]
        wait_for(preview_painted, "two-color inline preview")
        return dimensions, radar_center

    def call(tool, **args):
        return fixture.call("gent_dashboard_" + tool, args)[0]

    empty = "No chats have published a dashboard."
    get(empty, "label")
    assert call("get") == {"revision": 0, "board": None}
    assert call("define", expected_revision=0, board=board)["revision"] == 1
    # Dashboard stays selected throughout. Allow two of the GTK timer's 15 s ticks.
    get(board["title"], "label", timeout=35)
    get(agent["name"], "label")
    restore = "Restore hidden dashboards"
    assert not find(restore)
    click("Hide dashboard")
    get("All dashboards are hidden.", "label")
    assert not find(board["title"], "label") and not find("Inspect job")
    assert call("get") == {"revision": 1, "board": board}
    tab("Chats")
    tab("Dashboard")
    assert get(restore).queryComponent().grabFocus()
    subprocess.run(["xdotool", "key", "space"], check=True)
    get(f"{board['title']} — {agent['name']}", "menu item")
    subprocess.run(["xdotool", "key", "Home", "Return"], check=True)
    get(board["title"], "label")
    assert not find(restore)
    open_report([url])
    for name in ("Job queued", "Throughput: 72%", "Queued\nStarted", "15 ms", "6 jobs"):
        get(name, "label")
    assert get(None, "progress bar").queryValue().currentValue == 0.25
    assert get(None, "level bar").queryValue().currentValue == 0.75
    narrow, _ = chart_pixels(updated=False)
    subprocess.run(["xdotool", "windowsize", "--sync", xid, "840", "690"], check=True)

    def redrawn():
        item = pyatspi.findDescendant(pyatspi.Registry.getDesktop(0), lambda c:
                                     c.name == "Stage counts" and c.getRole() == pyatspi.ROLE_IMAGE)
        if item:
            r = item.queryComponent().getExtents(pyatspi.DESKTOP_COORDS)
            w, h = narrow["bar"]
            return r.width > 1.5 * w and abs(r.height - h) <= 3

    wait_for(redrawn, "cached chart redrawn at wide card width with constant-height bars", timeout=5)
    wide, initial_center = chart_pixels(updated=False)
    for kind, (width, height) in wide.items():
        old_width, old_height = narrow[kind]
        assert width > 1.5 * old_width and height < old_height * 1.35, (kind, narrow, wide)
    print(f"GTK chart allocations before and after resize: {narrow} -> {wide}", flush=True)
    reveal("3 ms", pyatspi.ROLE_LABEL)
    reveal("Inspect job", pyatspi.ROLE_PUSH_BUTTON)

    assert fixture.call("gent_inbox")[0] == []
    click("Inspect job")
    message, = wait_for(lambda: fixture.call("gent_inbox")[0], "dashboard callback in publisher inbox")
    sender, = [a for a in json.loads(cli("--json", "agents").stdout) if a["provider"] == "desktop"]
    assert sender["name"] == "Gent Desktop" and message["sender"] == sender["id"]
    assert message["recipient"] == agent["id"]
    assert message["text"] == f"Dashboard action Inspect job (inspect) selected in Gent Desktop:\n{instruction}"
    fixture.call("gent_ack", {"message_id": message["id"]})

    assert call("update", expected_revision=1, values={"status": "Job done", "trend": [8, 1, 9],
                "work": 30, "load": 0.0, "log": ["Finished"], "report": updated_url, "rate": 18.125,
                "preview": image_uri("JPEG", reverse=True), "runs": [[1, 8], [2, 1], [3, 9]],
                **{key: [{"label": label, "value": n} for label, n in [("Build", 9), ("Test", 1), ("Ship", 5)]]
                   for key in ("counts", "share", "profile")}})["revision"] == 2
    get("Job done", "label", timeout=35)
    open_report([url, updated_url])
    for name in ("Throughput: 18.125%", "30 ms", "0 jobs", "Finished"):
        get(name, "label")
    assert get(None, "progress bar").queryValue().currentValue == 1
    assert get(None, "level bar").queryValue().currentValue == 0
    _, updated_center = chart_pixels(updated=True)
    # The right-hand spoke drops from the maximum to 1/9 of the maximum.
    assert updated_center < initial_center - 5, (initial_center, updated_center)
    reveal("9 ms", pyatspi.ROLE_LABEL)

    assert call("delete", expected_revision=2)["revision"] == 3
    get(empty, "label", timeout=35)
    assert not find(board["title"]) and not find("Inspect job")
    assert call("get") == {"revision": 3, "board": None}
    assert fixture.call("gent_inbox")[0] == []


def exercise_node_rename(cli, remote, hosted, parent):
    def open_rename(node):
        select_row(node["id"])
        click("Rename node…")
        dialog = get("Rename node", "dialog")
        get(node["name"] + "\n" + node["id"], "label")
        entry = pyatspi.findDescendant(dialog, lambda c: c.getRoleName() == "text")
        assert entry.queryText().getText(0, -1) == node["name"]
        return entry.queryEditableText()

    def members():
        return {n["id"]: n for n in json.loads(cli("--json", "nodes").stdout)}

    search = get("Filter nodes")
    search.queryEditableText().setTextContents(hosted["id"])
    get("1 of 3 nodes", "label")
    open_rename(hosted).setTextContents("cancelled fixture edit")
    click("Cancel")
    wait_for(lambda: not find("Rename node", "dialog"), "cancelled rename dialog dismissed")
    assert members()[hosted["id"]]["name"] == hosted["name"]

    open_rename(hosted).setTextContents("x" * 129)
    click("Rename")
    invalid = wait_for(lambda: pyatspi.findDescendant(pyatspi.Registry.getDesktop(0), lambda c:
             c.getRoleName() == "label" and c.getState().contains(pyatspi.STATE_SHOWING)
             and "1-128 bytes" in c.name), "rename validation error")
    notice = invalid.name
    assert row(hosted["id"])[0] == members()[hosted["id"]]["name"] == hosted["name"]

    changed = "Fixture CLI rename"
    cli("node", "rename", hosted["id"], changed)
    click("Refresh status")
    wait_for(lambda: row(hosted["id"])[0] == changed, "external rename in the refreshed table")
    get(notice, "label")
    assert selected_member() == hosted["id"] and search.queryText().getText(0, -1) == hosted["id"]
    hosted = dict(hosted, name=changed)

    expected = {node["id"]: node["name"] for node in (parent, remote, hosted)}
    for node, name in ((hosted, "Renamed web"), (remote, "Renamed remote"), (parent, "Renamed owner")):
        open_rename(node).setTextContents(name)
        click("Rename")
        wait_for(lambda: row(node["id"])[0] == name, "renamed row " + name)
        assert selected_member() == node["id"]
        if node == hosted:
            assert search.queryText().getText(0, -1) == hosted["id"]
            get("1 of 3 nodes", "label")
            search.queryEditableText().setTextContents("")
            get("3 of 3 nodes", "label")
        expected[node["id"]] = name
        directory = members()
        assert {key: member["name"] for key, member in directory.items()} == expected
        assert directory[hosted["id"]]["hosted_by"] == parent["id"]
    assert row(hosted["id"])[5] == expected[parent["id"]]


def exercise_tabs(cli, fixture, agent, remote, hosted, parent):
    desktop = pyatspi.Registry.getDesktop(0)

    assert_selected_tab("Dashboard")
    tab("Status")
    get("desktop-test", "label")
    get("Daemon running", "label")
    get("Stop daemon")
    get("Known chats", "label")
    get("3 of 3 nodes", "label")
    visible_tables = pyatspi.findAllDescendants(desktop, lambda c:
                      c.getRoleName() == "table" and c.getState().contains(pyatspi.STATE_SHOWING))
    assert len(visible_tables) == 1
    table = member_table()
    assert [table.getColumnHeader(c).name for c in range(table.nColumns)] == [
        "Node", "Status", "Role", "Directory", "Last transport", "Hosted by", "Node ID"]
    signed = json.loads(cli("--json", "nodes").stdout)
    assert table.nRows == len(signed) == 3
    for member in signed:
        cells = row(member["id"])
        role = "Owner" if member["is_owner"] else "Admin" if member["can_configure"] else "Member"
        assert cells[:3] == [member["name"], member["status"], role], cells
    assert row(hosted["id"])[3:] == ["—", "—", parent["name"], hosted["id"]]
    assert row(parent["id"])[1] == "local"
    check_member_tooltip(get(hosted["name"], "table cell"))
    select_row(parent["id"])
    for title in ("Remove node…", "Change role…"):
        assert not get(title).getState().contains(pyatspi.STATE_SENSITIVE)
    check_node_action_row(remote["id"])
    tab("Chats")
    get("Fixture conversation", "table cell")
    tab("Dashboard")
    xid = subprocess.check_output(["xdotool", "getactivewindow"], text=True).strip()
    geometry = GdkX11.X11Window.foreign_new_for_display(Gdk.Display.get_default(), int(xid)).get_geometry()
    try:
        # Fit each SVG (including its axes and legend) into the Xvfb viewport for pixel sampling.
        subprocess.run(["xdotool", "windowsize", "--sync", xid, "485", "690"], check=True)
        exercise_dashboard(fixture, agent, cli, xid)
    finally:
        subprocess.run(["xdotool", "windowsize", xid, str(geometry.width), str(geometry.height)], check=True)
    tab("Settings")
    toggle = get("Automatically update Gent", "check box")
    assert toggle.getState().contains(pyatspi.STATE_CHECKED)
    toggle.queryAction().doAction(0)
    wait_for(lambda: json.loads(cli("update", "status", "--json").stdout)["enabled"] is False,
             "persisted auto-update opt-out")
    channel = get("Cluster release channel", "combo box")
    for index, expected in ((1, "beta"), (0, "stable")):
        wait_for(lambda: channel.getState().contains(pyatspi.STATE_SENSITIVE), "writable cluster channel")
        assert channel.querySelection().selectChild(index)
        wait_for(lambda: json.loads(cli("--json", "cluster", "channel", "get").stdout)["channel"] == expected,
                 "accepted cluster channel " + expected)
        assert not json.loads(cli("--json", "update", "status").stdout)["enabled"]
    click("Edit full configuration…")
    editor = wait_for(lambda: pyatspi.findDescendant(desktop, lambda c: c.getRoleName() == "text"
                      and c.getState().contains(pyatspi.STATE_SHOWING)
                      and "[node]" in c.queryText().getText(0, -1)), "private TOML editor")
    original = editor.queryText().getText(0, -1)
    editor.queryEditableText().setTextContents("bad = [")
    click("Save locally")
    get("configuration has invalid TOML or field types")
    assert editor.queryText().getText(0, -1) == "bad = ["
    editor.queryEditableText().setTextContents(original + "\n# desktop fixture saved\n")
    click("Save locally")
    get("Saved locally")
    click("Edit full configuration…")
    editor = wait_for(lambda: pyatspi.findDescendant(desktop, lambda c: c.getRoleName() == "text"
                      and c.getState().contains(pyatspi.STATE_SHOWING)
                      and "# desktop fixture saved" in c.queryText().getText(0, -1)), "saved configuration reopened")
    original = editor.queryText().getText(0, -1)
    # Edit only the cluster name, then check the daemon's signed view after explicit publication.
    changed, count = re.subn(r'(\[cluster\][^\[]*?\nname = )"desktop-test"', r'\1"desktop-published"', original)
    assert count == 1
    editor.queryEditableText().setTextContents(changed)
    click("Save and publish…")
    click("Save and publish")
    wait_for(lambda: json.loads(cli("daemon", "status", "--json").stdout)["cluster"]["name"] == "desktop-published",
             "published cluster name")
    tab("About")
    get("Check for updates")
    get("https://gent.link")
    wait_for(lambda: pyatspi.findDescendant(desktop, lambda c: c.getRoleName() == "label" and
             "Version " in c.name and "Copyright" in c.name), "build version and copyright")
    tab("Status")
    assert get("Account", "toggle button").queryAction().doAction(0)
    get("Gent account: Signed out")
    get("Sign in with GitHub")
    assert get("Account", "toggle button").queryAction().doAction(0)
    tab("Permissions")
    click("Edit permission…")
    get("Apply rule")
    click("Cancel")
    click("Edit permission…")
    click("Apply rule")
    wait_for(lambda: any(r["effect"] == "deny" and r["permission"] == "send" for r in
                         json.loads(cli("--json", "config").stdout)["policy"]["rules"]), "changed signed send rule")
    tab("Chats")
    table = get("Gent Desktop", "table cell").parent.queryTable()
    names = [table.getAccessibleAt(i, 0).name for i in range(table.nRows)]
    # The dashboard callback above sent a Gent message between these two chats.
    assert names.index("Fixture conversation") < names.index("A quiet chat"), names
    assert names.index("Gent Desktop") < names.index("A quiet chat"), names
    def fixture_revoked():
        return next(a["revoked"] for a in json.loads(cli("--json", "agents").stdout) if a["id"] == agent["id"])
    def open_unregister():
        select_row(agent["id"])
        click("Unregister chat…")
        get(agent["name"] + "\n" + agent["id"], "label")
    open_unregister()
    click("Cancel")
    wait_for(lambda: not find("Unregister chat", "dialog"), "unregistration dialog dismissed")
    assert not fixture_revoked()
    open_unregister()
    click("Unregister chat")
    wait_for(fixture_revoked, "confirmed unregistration")
    tab("Status")
    click("Add node…")
    get("New node name", "label")
    click("Cancel")
    exercise_node_rename(cli, remote, hosted, parent)
