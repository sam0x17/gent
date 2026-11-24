"""Drive the real tab widgets via AT-SPI in the smoke test's private graphical session."""
import json
from pathlib import Path
import re
import subprocess
import time

import gi
import pyatspi

gi.require_version("Gdk", "3.0")
gi.require_version("GdkX11", "3.0")
from gi.repository import Gdk, GdkPixbuf, GdkX11

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


def assert_default_cluster():
    item = get("Status", "page tab")
    assert [page.name for page in item.parent] == ["Status", "Dashboard", "Chats", "Settings", "Permissions", "About"]
    assert item.getState().contains(pyatspi.STATE_SELECTED)


def exercise_setup():
    assert_default_cluster()
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


def exercise_dashboard(fixture, agent, cli):
    instruction = "Report the synthetic job status."
    url = "https://example.test/report"
    updated_url = "http://localhost:8042/done"
    board = {"title": "Fixture job", "widgets": [
        {"id": "inspect", "kind": "button", "label": "Inspect job", "value": instruction},
        {"id": "report", "kind": "link", "label": "Job report", "value": url},
        {"id": "status", "kind": "text", "label": "Job status", "value": "Job queued"},
        {"id": "rate", "kind": "metric", "label": "Throughput:", "value": 12.5, "unit": "jobs/s"},
        {"id": "log", "kind": "events", "label": "Recent events", "value": ["Queued", "Started"]},
        {"id": "work", "kind": "progress", "label": "Work completed", "value": 15, "min": 10, "max": 30},
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
        shapes = {}
        for widget in chart_widgets():
            name, kind = widget["label"], widget["kind"]
            item = reveal(name, pyatspi.ROLE_IMAGE)
            detail = "ms" if kind in ("graph", "scatter") else kind
            assert name in item.description and detail in item.description, item.description

            def series():
                snap = dashboard_pixels(item)
                scaled = snap.scale_simple(160, 100, GdkPixbuf.InterpType.BILINEAR)
                pixels, stride, channels = scaled.get_pixels(), scaled.get_rowstride(), scaled.get_n_channels()
                colored = set()
                warm = 0
                pale_blue = 0
                for y in range(10, 86):
                    for x in range(6, 154):
                        k = y * stride + x * channels
                        r, g, b = pixels[k:k + 3]
                        warm += r > b + 45
                        pale_blue += 205 < r < 235 and b > r + 10
                        if max(r, g, b) - min(r, g, b) > 45:
                            colored.add((x, y))
                # Both cartesian fixtures reverse their middle sample on update.
                if kind in ("graph", "scatter") and not any(
                    85 <= x <= 96 and ((y >= 50) if updated else (y < 40)) for x, y in colored
                ):
                    return None
                if kind == "bar" and not all(
                    any(sum((x, y) in colored for x in range(18, 140)) >= 9 for y in band)
                    for band in (range(26, 35), range(49, 58), range(72, 81))
                ):
                    return None
                if (kind == "pie" and warm < 100) or (kind == "radar" and pale_blue < 50):
                    return None
                if kind == "scatter" and any(57 < x < 82 for x, y in colored):
                    return None
                return colored if len(colored) >= 12 else None
            shapes[kind] = wait_for(series, "painted " + kind + " series")

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
        return shapes

    def call(tool, **args):
        return fixture.call("gent_dashboard_" + tool, args)[0]

    empty = "No chats have published a dashboard."
    get(empty, "label")
    assert call("get") == {"revision": 0, "board": None}
    assert call("define", expected_revision=0, board=board)["revision"] == 1
    # Dashboard stays selected throughout. Allow two of the GTK timer's 15 s ticks.
    get(board["title"], "label", timeout=35)
    get(agent["name"], "label")
    open_report([url])
    for name in ("Job queued", "Throughput: 12.5 jobs/s", "Queued\nStarted", "15", "6 jobs"):
        get(name, "label")
    assert get(None, "progress bar").queryValue().currentValue == 0.25
    assert get(None, "level bar").queryValue().currentValue == 0.75
    initial = chart_pixels(updated=False)
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
                "work": 30, "load": 2, "log": ["Finished"], "report": updated_url, "rate": 18,
                "preview": image_uri("JPEG", reverse=True), "runs": [[1, 8], [2, 1], [3, 9]],
                **{key: [{"label": label, "value": n} for label, n in [("Build", 9), ("Test", 1), ("Ship", 5)]]
                   for key in ("counts", "share", "profile")}})["revision"] == 2
    get("Job done", "label", timeout=35)
    open_report([url, updated_url])
    for name in ("Throughput: 18 jobs/s", "30", "2 jobs", "Finished"):
        get(name, "label")
    assert get(None, "progress bar").queryValue().currentValue == 1
    assert get(None, "level bar").queryValue().currentValue == 0.25
    changed = chart_pixels(updated=True)
    for kind in initial:
        assert len(initial[kind] ^ changed[kind]) > 12, kind
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

    assert_default_cluster()
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
        exercise_dashboard(fixture, agent, cli)
    finally:
        subprocess.run(["xdotool", "windowsize", xid, str(geometry.width), str(geometry.height)], check=True)
    tab("Settings")
    toggle = get("Automatically update Gent", "check box")
    assert toggle.getState().contains(pyatspi.STATE_CHECKED)
    toggle.queryAction().doAction(0)
    wait_for(lambda: json.loads(cli("update", "status", "--json").stdout)["enabled"] is False,
             "persisted auto-update opt-out")
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
    get("Gent Desktop", "table cell")
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
