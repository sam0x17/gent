"""Drive the real tab widgets via AT-SPI in the smoke test's private graphical session."""
import json
import re

import pyatspi


def exercise_tabs(wait_for, cli):
    desktop = pyatspi.Registry.getDesktop(0)

    def find(name, role=None):
        def match(child):
            return child.getState().contains(pyatspi.STATE_SHOWING) and (name is None or child.name == name) and (role is None or child.getRoleName() == role)
        return pyatspi.findDescendant(desktop, match)

    def get(name, role=None):
        return wait_for(lambda: find(name, role), name or role)

    def tab(name):
        item = get(name, "page tab")
        assert item.parent.querySelection().selectChild(item.getIndexInParent())

    def click(name):
        button = wait_for(lambda: pyatspi.findDescendant(desktop, lambda c:
                           c.name == name and c.getRole() == pyatspi.ROLE_PUSH_BUTTON
                           and c.getState().contains(pyatspi.STATE_SHOWING)), name)
        return button.queryAction().doAction(0)

    tab("Chats")
    get("Fixture conversation", "table cell")
    tab("Nodes")
    get("local", "table cell")
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
    chat = get("Fixture conversation", "table cell")
    assert chat.parent.queryTable().addRowSelection(0)
    click("Unregister chat…")
    click("Cancel")
    assert not json.loads(cli("--json", "agents").stdout)[0]["revoked"]
    click("Unregister chat…")
    click("Unregister chat")
    wait_for(lambda: json.loads(cli("--json", "agents").stdout)[0]["revoked"], "confirmed unregistration")
    tab("Nodes")
    click("Add node…")
    get("New node name", "label")
    click("Cancel")
    tab("Status")
