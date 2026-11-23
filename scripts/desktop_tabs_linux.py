"""Drive the real tab widgets via AT-SPI in the smoke test's private graphical session."""
from collections import Counter
import json
import re

import gi
import pyatspi

gi.require_version("Gdk", "3.0")
from gi.repository import Gdk


def exercise_dashboard(wait_for, find, get, click, fixture, agent, cli):
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


def exercise_tabs(wait_for, cli, fixture, agent, hosted, parent):
    desktop = pyatspi.Registry.getDesktop(0)

    def find(name, role=None):
        def match(child):
            return child.getState().contains(pyatspi.STATE_SHOWING) and (name is None or child.name == name) and (role is None or child.getRoleName() == role)
        return pyatspi.findDescendant(desktop, match)

    def get(name, role=None, timeout=12):
        return wait_for(lambda: find(name, role), name or role, timeout)

    def tab(name):
        item = get(name, "page tab")
        assert item.parent.querySelection().selectChild(item.getIndexInParent())

    def click(name):
        button = wait_for(lambda: pyatspi.findDescendant(desktop, lambda c:
                           c.name == name and c.getRole() == pyatspi.ROLE_PUSH_BUTTON
                           and c.getState().contains(pyatspi.STATE_SHOWING)
                           and c.getState().contains(pyatspi.STATE_SENSITIVE)), name)
        assert button.queryAction().doAction(0), name

    def row(name):
        cell = get(name, "table cell")
        table = cell.parent.queryTable()
        index = table.getRowAtIndex(cell.getIndexInParent())
        return [table.getAccessibleAt(index, col).name for col in range(table.nColumns)]

    notebook = get("Status", "page tab").parent
    assert [page.name for page in notebook][:2] == ["Status", "Dashboard"]
    tab("Status")
    assert row(hosted["name"]) == [hosted["name"], "Hosted", "Hosted by " + parent["name"]]
    tab("Chats")
    get("Fixture conversation", "table cell")
    tab("Nodes")
    get("local", "table cell")
    member, = [n for n in json.loads(cli("--json", "nodes").stdout) if n["id"] == hosted["id"]]
    assert member["hosted_by"] == parent["id"] and member["status"] == "hosted"
    role = "Admin" if member["can_configure"] else "Member"
    details = row(hosted["name"])
    assert details == [hosted["name"], "hosted", role, parent["name"], hosted["id"]], details
    tab("Dashboard")
    exercise_dashboard(wait_for, find, get, click, fixture, agent, cli)
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
    get("Gent account: Signed out")
    get("Sign in with GitHub")
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
        chat = get(agent["name"], "table cell")
        table = chat.parent.queryTable()
        index = table.getRowAtIndex(chat.getIndexInParent())
        if not table.isRowSelected(index):
            assert table.addRowSelection(index)
        click("Unregister chat…")
        get(agent["name"] + "\n" + agent["id"], "label")
    open_unregister()
    click("Cancel")
    wait_for(lambda: not find("Unregister chat", "dialog"), "unregistration dialog dismissed")
    assert not fixture_revoked()
    open_unregister()
    click("Unregister chat")
    wait_for(fixture_revoked, "confirmed unregistration")
    tab("Nodes")
    click("Add node…")
    get("New node name", "label")
    click("Cancel")
    tab("Status")
