"""Drive the real tab widgets via AT-SPI in the smoke test's private graphical session."""
from collections import Counter
import json
import re
import subprocess
import time

import gi
import pyatspi

gi.require_version("Gdk", "3.0")
gi.require_version("GdkX11", "3.0")
from gi.repository import Gdk, GdkX11


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


def assert_default_cluster():
    item = get("Cluster", "page tab")
    assert [page.name for page in item.parent] == ["Cluster", "Dashboard", "Chats", "Settings", "Permissions", "About"]
    assert item.getState().contains(pyatspi.STATE_SELECTED)


def exercise_setup():
    assert_default_cluster()
    get("Set up this node")
    get("Gent account: Signed out", "label")
    for title in ("Sign in with GitHub", "Create cluster…", "Join with invitation…"):
        get(title)
    assert not find("Members") and not find(None, "table") and not find("Known chats")
    click("Join with invitation…")
    get("Invitation code", "label")
    click("Cancel")


def exercise_enrolled_without_daemon(node):
    click("Refresh status")
    get("desktop-test", "label")
    get("Local node · " + node["name"], "label")
    get("Start daemon")
    get("Members", "label")
    assert get("Account", "toggle button").queryAction().doAction(0)
    get("Install or repair daemon…")
    assert not find("Create cluster…") and not find("Join with invitation…")


def exercise_dashboard(fixture, agent, cli):
    instruction = "Report the synthetic job status."
    board = {"title": "Fixture job", "widgets": [
        {"id": "inspect", "kind": "button", "label": "Inspect job", "value": instruction},
        {"id": "status", "kind": "text", "label": "Job status", "value": "Job queued"},
        {"id": "trend", "kind": "graph", "label": "Sample history", "value": [1, 8, 3], "unit": "ms"},
        {"id": "log", "kind": "events", "label": "Recent events", "value": ["Queued", "Started"]},
        {"id": "work", "kind": "progress", "label": "Work completed", "value": 15, "min": 10, "max": 30},
        {"id": "load", "kind": "gauge", "label": "Queue depth", "value": 6, "max": 8, "unit": "jobs"},
    ]}

    def graph_line_in_half(upper):
        plot = get(None, "drawing area")
        x, y, width, height = plot.queryComponent().getExtents(pyatspi.DESKTOP_COORDS)
        # At 40% of the plot width the first series rises and the updated series dips.
        # Sample one vertical strip of the Xvfb framebuffer, independent of theme colors.
        assert width > 8 and height > 8
        strip = Gdk.pixbuf_get_from_window(Gdk.get_default_root_window(), x + width*2//5, y + 2, 1, height - 4)
        pixels, stride, channels = strip.get_pixels(), strip.get_rowstride(), strip.get_n_channels()
        colors = [pixels[r*stride:r*stride + channels] for r in range(strip.get_height())]
        background = Counter(colors).most_common(1)[0][0]
        ink = [r for r, color in enumerate(colors) if color != background]
        return bool(ink) and all((r < len(colors)/2) == upper for r in ink)

    def call(tool, **args):
        return fixture.call("gent_dashboard_" + tool, args)[0]

    empty = "No chats have published a dashboard."
    get(empty, "label")
    assert call("get") == {"revision": 0, "board": None}
    assert call("define", expected_revision=0, board=board)["revision"] == 1
    # Dashboard stays selected throughout. Allow two of the GTK timer's 15 s ticks.
    get(board["title"], "label", timeout=35)
    get(agent["name"], "label")
    for name in ("Job queued", "3 ms", "Queued\nStarted", "15", "6 jobs"):
        get(name, "label")
    assert get(None, "progress bar").queryValue().currentValue == 0.25
    assert get(None, "level bar").queryValue().currentValue == 0.75
    wait_for(lambda: graph_line_in_half(upper=True), "initial graph pixels")

    assert fixture.call("gent_inbox")[0] == []
    click("Inspect job")
    message, = wait_for(lambda: fixture.call("gent_inbox")[0], "dashboard callback in publisher inbox")
    sender, = [a for a in json.loads(cli("--json", "agents").stdout) if a["provider"] == "desktop"]
    assert sender["name"] == "Gent Desktop" and message["sender"] == sender["id"]
    assert message["recipient"] == agent["id"]
    assert message["text"] == f"Dashboard action Inspect job (inspect) selected in Gent Desktop:\n{instruction}"
    fixture.call("gent_ack", {"message_id": message["id"]})

    assert call("update", expected_revision=1, values={"status": "Job done", "trend": [8, 1, 9],
                "work": 30, "load": 2, "log": ["Finished"]})["revision"] == 2
    get("Job done", "label", timeout=35)
    for name in ("9 ms", "30", "2 jobs", "Finished"):
        get(name, "label")
    assert get(None, "progress bar").queryValue().currentValue == 1
    assert get(None, "level bar").queryValue().currentValue == 0.25
    wait_for(lambda: graph_line_in_half(upper=False), "updated graph pixels")

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

    search = get("Filter members")
    search.queryEditableText().setTextContents(hosted["id"])
    get("1 of 3 members", "label")
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
            get("1 of 3 members", "label")
            search.queryEditableText().setTextContents("")
            get("3 of 3 members", "label")
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
    get("3 of 3 members", "label")
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
    tab("Chats")
    get("Fixture conversation", "table cell")
    tab("Dashboard")
    exercise_dashboard(fixture, agent, cli)
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
    tab("Cluster")
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
    tab("Cluster")
    click("Add node…")
    get("New node name", "label")
    click("Cancel")
    exercise_node_rename(cli, remote, hosted, parent)
