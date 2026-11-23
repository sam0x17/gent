// Compile alongside the production AppKit delegate in a logged-in Aqua session.
import AppKit

func require(_ condition: Bool, _ name: String) {
    if !condition {
        FileHandle.standardError.write(Data(("FAIL: " + name + "\n").utf8))
        exit(1)
    }
}

func cell(_ table: NSTableView, _ key: String, row: Int) -> String? {
    let index = table.column(withIdentifier: NSUserInterfaceItemIdentifier(key))
    guard index >= 0, row < table.numberOfRows else { return nil }
    return (table.view(atColumn: index, row: row, makeIfNecessary: true) as? NSTextField)?.stringValue
}

func descendants<T: NSView>(_ view: NSView, of type: T.Type) -> [T] {
    view.subviews.compactMap { $0 as? T } + view.subviews.flatMap { descendants($0, of: type) }
}

func requests(during action: () -> Void) -> [NSDictionary] {
    let pipe = Pipe()
    let output = dup(STDOUT_FILENO)
    require(output >= 0 && dup2(pipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO) >= 0, "capture supervisor requests")
    action()
    require(dup2(output, STDOUT_FILENO) >= 0, "restore fixture output")
    close(output)
    pipe.fileHandleForWriting.closeFile()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    require(data.isEmpty || data.last == 10, "newline-delimited requests")
    return data.split(separator: 10).map { try! JSONSerialization.jsonObject(with: Data($0)) as! NSDictionary }
}

func checkNodeRename(_ desktop: Desktop) {
    let nodes = desktop.nodes
    let ids = (0..<3).map { _ in UUID().uuidString.lowercased() }
    let action: [String: Any] = ["kind": "rename_node", "title": "Rename node…", "submit": "Rename", "row": true,
                                 "fields": [["key": "name", "title": "New node name"]]]
    var rows = [
        ["name": "Studio", "state": "local", "role": "Owner", "id": ids[0]],
        ["name": "Remote", "state": "offline", "role": "Admin", "id": ids[1]],
        ["name": "claude-web", "state": "hosted", "role": "Member", "host": "Studio", "id": ids[2]],
    ]
    func receiveRows() { desktop.receive(["page": "nodes", "rows": rows, "actions": [action]]) }
    desktop.tabs.selectTabViewItem(withIdentifier: "Nodes")
    receiveRows()
    require(cell(nodes.table, "name", row: 2) == "claude-web" && cell(nodes.table, "host", row: 2) == "Studio",
            "hosted member and carrier rendered")
    func renameDialog() -> NSWindow? {
        // AppKit can present an alert in a panel instead of attaching it as a sheet.
        NSApp.windows.first { window in
            guard window.isVisible, window !== desktop.window, let content = window.contentView else { return false }
            return descendants(content, of: NSButton.self).contains { $0.title == "Rename" }
        }
    }
    func waitFor(_ description: String, _ condition: () -> Bool) {
        let deadline = Date(timeIntervalSinceNow: 3)
        while !condition() && Date() < deadline { RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.01)) }
        require(condition(), description)
    }
    func edit(_ index: Int, _ name: String, cancel: Bool = false) -> [NSDictionary] {
        let rename = nodes.actions.view.arrangedSubviews[0] as! NSButton
        nodes.table.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
        require(rename.isEnabled, "selected node can be renamed")
        rename.performClick(nil)
        waitFor("rename dialog is visible") { renameDialog() != nil }
        guard let dialog = renameDialog(), let content = dialog.contentView,
              let button = descendants(content, of: NSButton.self).first(where: { $0.title == (cancel ? "Cancel" : "Rename") }),
              let input = descendants(content, of: NSTextField.self).first(where: { $0.isEditable }) else {
            require(false, "editable rename dialog")
            return []
        }
        require(input.stringValue == rows[index]["name"], "current name prefilled")
        require(descendants(content, of: NSTextField.self).contains { $0.stringValue.contains(ids[index]) },
                "dialog identifies selected member")
        input.stringValue = name
        return requests {
            button.performClick(nil)
            waitFor("rename dialog dismissed") { !dialog.isVisible && (cancel || !rename.isEnabled) }
        }
    }
    func expectSubmit(_ index: Int, _ name: String) {
        let sent = edit(index, name)
        require(sent.count == 1 && sent[0].isEqual(to: ["op": "manage",
                "action": ["kind": "rename_node", "id": ids[index], "name": name]]),
                "rename submitted once for selected node UUID")
    }
    require(!(nodes.actions.view.arrangedSubviews[0] as! NSButton).isEnabled, "rename requires a selection")
    require(edit(2, "Cancelled", cancel: true).isEmpty, "cancel sends no request")
    expectSubmit(2, "Rejected edit")
    let failure = requests { desktop.receive(["page": "nodes", "operation": true, "error": "Permission denied"]) }
    require(failure.isEmpty && nodes.actions.notice.stringValue == "Permission denied"
            && cell(nodes.table, "name", row: 2) == "claude-web", "error shown with original row")
    for (index, name) in [(2, "Renamed web"), (1, "Renamed remote"), (0, "Renamed owner")] {
        expectSubmit(index, name)
        let refresh = requests { desktop.receive(["page": "nodes", "operation": true, "notice": "Configuration change: applied"]) }
        require(refresh.count == 1 && refresh[0].isEqual(to: ["op": "nodes"]), "refresh directory after rename")
        rows[index]["name"] = name
        if index == 0 { rows[2]["host"] = name }
        receiveRows()
        require(cell(nodes.table, "name", row: index) == name && cell(nodes.table, "id", row: index) == ids[index],
                "renamed row retains its ID")
    }
}

func checkDashboard(_ desktop: Desktop) {
    desktop.tabs.selectTabViewItem(withIdentifier: "Dashboard")
    let rows: [[String: Any]] = (1...3).map { i in
        let button = ["kind": "button", "id": "retry", "label": "Retry", "value": "Retry the fixture job"]
        return ["agent": "agent-\(i)", "chat": "Chat \(i)", "revision": 10 + i,
                "board": ["title": "Board \(i)", "widgets": [button]]]
    }
    desktop.receive(["page": "dashboard", "rows": rows])
    let view = desktop.dashboard.view
    guard let scroll = descendants(view, of: NSScrollView.self).first else {
        require(false, "Dashboard scroll view")
        return
    }

    func layout(width: CGFloat, columns: Int) -> CGFloat {
        desktop.window.setContentSize(NSSize(width: width, height: 605))
        desktop.window.contentView?.layoutSubtreeIfNeeded()
        let cards = descendants(view, of: NSBox.self).sorted { $0.title < $1.title }
        require(cards.map { $0.title } == ["Board 1", "Board 2", "Board 3"], "all Dashboard cards rendered")
        let clip = scroll.contentView
        let frames = cards.map { $0.convert($0.bounds, to: clip) }
        let first = frames[0]
        let lastInRow = frames[columns - 1]
        require(abs(first.minY - clip.bounds.minY) <= 1, "first Dashboard row at top of viewport")
        require(first.width > 0 && first.height > 0 && abs(first.minX - clip.bounds.minX) <= 1
                && abs(lastInRow.maxX - clip.bounds.maxX) <= 1, "Dashboard row fills viewport at \(width)")
        require(frames.allSatisfy { abs($0.width - first.width) <= 1 }, "equal widths on partial row")
        if columns == 2 {
            require(first.maxX < frames[1].minX && abs(first.midY - frames[1].midY) <= 1,
                    "two cards side by side")
        }
        require(abs(first.minX - frames[columns].minX) <= 1 && !first.intersects(frames[columns]),
                "next Dashboard row wraps at \(width)")
        return first.width
    }

    let wide = layout(width: 810, columns: 2)
    require(layout(width: 735, columns: 2) < wide - 1, "two-column cards shrink within the breakpoint")
    let narrow = layout(width: 510, columns: 1)
    require(layout(width: 550, columns: 1) > narrow + 1, "single-column cards grow within the breakpoint")

    guard let card = descendants(view, of: NSBox.self).first(where: { $0.title == "Board 2" }),
          let button = descendants(card, of: NSButton.self).first(where: { $0.title == "Retry" }) else {
        require(false, "published Dashboard button")
        return
    }
    // Exercise the AppKit target/action and inspect the supervisor's actual wire request.
    let sent = requests { button.performClick(nil) }
    require(sent.count == 1 && sent[0].isEqual(to: ["op": "dashboard_click", "agent": "agent-2",
                                                    "revision": 12, "widget": "retry"]),
            "one newline-delimited click for the displayed chat, revision and widget")
    desktop.window.setContentSize(NSSize(width: 850, height: 605))
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let desktop = Desktop(iconPath: CommandLine.arguments[1], openAtLaunch: false)
if CommandLine.arguments.dropFirst(2).contains("--nodes") {
    desktop.makeWindow()
    desktop.window.orderFront(nil)
    checkNodeRename(desktop)
    print("PASS: AppKit local, remote and hosted Nodes rename, selected UUID, cancel, error and directory refresh")
    exit(0)
}
app.delegate = desktop
// The pipe stays open so the UI has the same lifetime as a normal Gent child.
let lifetime = Pipe()
dup2(lifetime.fileHandleForReading.fileDescriptor, STDIN_FILENO)
DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
    require(desktop.statusItem.isVisible && desktop.statusItem.button?.image != nil, "visible menu-bar item and image")
    require(!desktop.window.isVisible, "starts in tray")
    let menu = desktop.statusItem.menu!
    guard let open = menu.item(withTitle: "Open Gent Desktop"), let action = open.action else {
        require(false, "Open menu item")
        return
    }
    require(app.sendAction(action, to: open.target, from: open), "open through actual menu target")
    require(desktop.window.isVisible && desktop.window.windowNumber > 0, "ordered AppKit window")
    desktop.receive(["node":"desktop-test", "cluster":"Local fixture", "running":true,
                     "state":"Running", "sync":"idle", "queue":0, "chats":2,
                     "can_stop":true, "peers":[["name":"fixture-peer","state":"matched","route":"Direct QUIC"],
                                               ["name":"claude-web","state":"connected","route":"Hosted by Studio"]]])
    require(desktop.node.stringValue == "desktop-test" && desktop.table.numberOfRows == 2, "model displayed")
    require(cell(desktop.table, "name", row: 1) == "claude-web" && cell(desktop.table, "route", row: 1) == "Hosted by Studio",
            "Status identifies the hosted claude-web peer and its carrier")
    require(desktop.toggle.title == "Stop daemon" && desktop.toggle.isEnabled, "service controls")
    require(desktop.trayState.title == "Daemon running", "tray status")
    require(desktop.tabs.tabViewItems.map { $0.label } == ["Status","Dashboard","Chats","Nodes","Settings","Cluster","Permissions","About"], "native tabs")
    checkDashboard(desktop)
    desktop.tabs.selectTabViewItem(withIdentifier: "Chats")
    desktop.receive(["page":"chats","rows":[["name":"Remote chat","node":"Other node","provider":"codex","state":"Registered","id":"c"]]])
    require(desktop.chats.table.numberOfRows == 1, "cluster chat rendered")
    checkNodeRename(desktop)
    desktop.tabs.selectTabViewItem(withIdentifier: "Settings")
    desktop.receive(["page":"settings","values":["updates":true, "discovery":false]])
    desktop.settings.openEditor()
    desktop.receive(["page":"settings","document":"fixture = true"])
    require(!desktop.settings.text.isHiddenOrHasHiddenAncestor && desktop.settings.text.string == "fixture = true", "editable configuration")
    desktop.settings.text.string = "fixture = false"
    desktop.settings.saveLocal()
    desktop.receive(["page":"settings","error":"concurrent edit"])
    require(desktop.settings.text.string == "fixture = false" && desktop.settings.text.isEditable, "failed save preserves draft")
    desktop.settings.saveLocal()
    desktop.receive(["page":"settings","saved":true,"values":["updates":true]])
    require(desktop.settings.text.isHiddenOrHasHiddenAncestor, "successful save returns to settings")
    desktop.tabs.selectTabViewItem(withIdentifier: "Cluster")
    desktop.receive(["page":"cluster","title":"Studio · disposable","detail":"Gent account: Signed in · @fixture",
                     "actions":[["title":"Sign out","kind":"sign_out","confirm":"Sign out?"]]])
    require(desktop.clusterPage.detail.string.contains("@fixture"), "account displayed")
    let signOut = desktop.clusterPage.actions.view.arrangedSubviews[0] as! NSButton
    signOut.performClick(nil)
    require(desktop.window.attachedSheet != nil, "sign-out confirmation sheet")
    if let sheet = desktop.window.attachedSheet { desktop.window.endSheet(sheet, returnCode: .alertFirstButtonReturn) }
    desktop.tabs.selectTabViewItem(withIdentifier: "Permissions")
    desktop.receive(["page":"permissions","title":"Cluster permissions","detail":"Allow Send","actions":[]])
    require(desktop.permissions.detail.string == "Allow Send", "permission rules displayed")
    desktop.tabs.selectTabViewItem(withIdentifier: "About")
    desktop.receive(["page":"about","title":"Gent","detail":"Version 0.1.0 · fixture","actions":[["title":"Check for updates","kind":"check_update"]]])
    require(desktop.about.detail.string.contains("0.1.0"), "version displayed")
    desktop.window.contentView?.layoutSubtreeIfNeeded()
    let row = desktop.about.view.subviews.compactMap { $0 as? NSStackView }.first
    let logo = row?.arrangedSubviews.compactMap { $0 as? NSImageView }.first
    require(logo?.image != nil && (logo?.bounds.width ?? 0) >= 512 && (logo?.bounds.height ?? 0) >= 512, "room for the full 512px logo")
    let check = desktop.about.actions.view.arrangedSubviews[0] as! NSButton
    check.performClick(nil)
    require(!check.isEnabled, "one update check in flight")
    desktop.receive(["page":"about","operation":true,"notice":"Current"])
    require(desktop.about.actions.notice.stringValue == "Current", "update check result displayed")
    desktop.window.performClose(nil)
    require(!desktop.window.isVisible && desktop.statusItem.isVisible, "closes to tray")
    require(app.sendAction(action, to: open.target, from: open) && desktop.window.isVisible, "menu reopens window")
    guard let quit = menu.item(withTitle: "Quit Gent Desktop"), let stop = quit.action else {
        require(false, "Quit menu item")
        return
    }
    FileHandle.standardError.write(Data("PASS: AppKit menu bar, hosted Status, local/remote/hosted Nodes rename, cancel and error, Dashboard resizing and button dispatch, directories, editable settings, account confirmation, permissions, about, update check, close, reopen and quit\n".utf8))
    _ = app.sendAction(stop, to: quit.target, from: quit)
}
app.run()
