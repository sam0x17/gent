// Compile alongside the production AppKit delegate in a logged-in Aqua session.
import AppKit

func require(_ condition: Bool, _ name: String) {
    if !condition {
        FileHandle.standardError.write(Data(("FAIL: " + name + "\n").utf8))
        exit(1)
    }
}

func cellField(_ table: NSTableView, _ key: String, row: Int) -> NSTextField? {
    let index = table.column(withIdentifier: NSUserInterfaceItemIdentifier(key))
    guard index >= 0, row < table.numberOfRows else { return nil }
    return table.view(atColumn: index, row: row, makeIfNecessary: true) as? NSTextField
}

func cell(_ table: NSTableView, _ key: String, row: Int) -> String? {
    cellField(table, key, row: row)?.stringValue
}

func descendants<T: NSView>(_ view: NSView, of type: T.Type) -> [T] {
    view.subviews.compactMap { $0 as? T } + view.subviews.flatMap { descendants($0, of: type) }
}

enum Request: Equatable {
    case command(String)
    case json(NSDictionary)
}

let accountRead = Request.json(["op": "cluster"])
let snapshotRead = Request.command("refresh")

func requests(during action: () -> Void) -> [Request] {
    let pipe = Pipe()
    let output = dup(STDOUT_FILENO)
    require(output >= 0 && dup2(pipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO) >= 0, "capture supervisor requests")
    action()
    require(dup2(output, STDOUT_FILENO) >= 0, "restore fixture output")
    close(output)
    pipe.fileHandleForWriting.closeFile()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    require(data.isEmpty || data.last == 10, "newline-delimited requests")
    return data.split(separator: 10).map { line in
        if line.starts(with: "{".utf8) {
            return .json(try! JSONSerialization.jsonObject(with: Data(line)) as! NSDictionary)
        }
        return .command(String(decoding: line, as: UTF8.self))
    }
}

func actionButton(_ bar: ActionBar, _ title: String) -> NSButton {
    guard let button = descendants(bar.view, of: NSButton.self).first(where: { $0.title == title }) else {
        fatalError("Missing action button " + title)
    }
    return button
}

func checkCluster(_ desktop: Desktop, open: () -> Void) {
    require(desktop.tabs.tabViewItems.map { $0.label } == ["Cluster", "Dashboard", "Chats", "Settings", "Permissions", "About"]
            && desktop.tabs.selectedTabViewItem?.label == "Cluster", "Cluster is the first and selected tab")
    require(requests(during: open) == [snapshotRead, accountRead], "opening Cluster reads snapshot and account once")
    let stopped: [String: Any] = ["enrolled": true, "node": "Studio", "cluster": "Local fixture", "state": "Stopped",
                                  "can_start": true, "nodes": ["rows": [], "actions": []]]
    checkSetup(desktop, stopped: stopped)
    checkMembers(desktop, stopped: stopped)
}

func resizeCluster(_ desktop: Desktop, height: CGFloat) {
    let size = NSSize(width: 510, height: height)
    desktop.window.setContentSize(size)
    // A screenless SSH session constrains the window frame. Size its native content view directly there.
    if desktop.window.screen == nil { desktop.tabs.setFrameSize(size) }
    desktop.tabs.layoutSubtreeIfNeeded()
}

func checkSetup(_ desktop: Desktop, stopped: [String: Any]) {
    let account = desktop.account
    let setup: [String: Any] = ["page": "cluster", "title": "Set up this node", "detail": "Gent account: Signed out",
        "actions": [["kind": "sign_in", "title": "Sign in with GitHub"], ["kind": "create", "title": "Create cluster…"],
                    ["kind": "join", "title": "Join with invitation…"], ["kind": "join", "title": "Resume pending join"]]]
    desktop.receive(setup)
    require(account.title.stringValue == "Set up this node" && !account.view.isHiddenOrHasHiddenAncestor
            && actionButton(account.actions, "Create cluster…").isEnabled, "setup actions before status arrives")
    resizeCluster(desktop, height: 400)
    let scroll = desktop.tabs.selectedTabViewItem!.view as! NSScrollView
    let clip = scroll.contentView
    for button in descendants(account.actions.view, of: NSButton.self) {
        require(clip.bounds.contains(button.convert(button.bounds, to: clip)), "setup action visible: " + button.title)
    }
    let firstRun: [String: Any] = ["enrolled": false, "state": "Unavailable", "nodes": ["rows": [], "actions": []]]
    desktop.receive(firstRun)
    require(desktop.health.isHidden && desktop.nodes.view.isHidden && !account.view.isHiddenOrHasHiddenAncestor,
            "setup takes precedence over empty daemon health and members")
    let document = scroll.documentView!
    let setupTop = account.title.convert(account.title.bounds, to: document).minY - scroll.documentVisibleRect.minY
    resizeCluster(desktop, height: 900)
    let tallSetupTop = account.title.convert(account.title.bounds, to: document).minY - scroll.documentVisibleRect.minY
    require(setupTop < 100 && abs(setupTop - tallSetupTop) <= 1, "setup stays at the top of a tall window")
    resizeCluster(desktop, height: 400)
    require(requests { desktop.poll() } == [snapshotRead], "periodic status read only")
    let signIn = actionButton(account.actions, "Sign in with GitHub")
    require(requests { signIn.performClick(nil) } == [.json(["op": "manage", "action": ["kind": "sign_in"]])],
            "sign-in works while status is pending")
    desktop.receive(firstRun)
    require(!signIn.isEnabled && account.actions.notice.stringValue.contains("Waiting for sign-in"),
            "polling preserves pending account action")
    require(requests { desktop.receive(["page": "cluster", "operation": true, "error": "Sign-in failed"]) } == [accountRead],
            "failed account operation rereads account")
    desktop.receive(setup)
    require(account.actions.notice.stringValue == "Sign-in failed", "account read preserves error notice")

    require(requests { desktop.refresh.performClick(nil) } == [snapshotRead, accountRead], "manual refresh reads both")
    desktop.receive(firstRun)
    desktop.receive(setup)
    desktop.tabs.selectTabViewItem(withIdentifier: "Chats")
    require(requests { desktop.tabs.selectTabViewItem(withIdentifier: "Cluster") } == [snapshotRead, accountRead],
            "selecting Cluster reads both")
    desktop.receive(firstRun)
    require(requests { actionButton(account.actions, "Sign in with GitHub").performClick(nil) }
            == [.json(["op": "manage", "action": ["kind": "sign_in"]])], "sign-in can be retried")
    require(requests { desktop.receive(["page": "cluster", "operation": true, "notice": "Signed in"]) } == [snapshotRead],
            "account operation refreshes snapshot while an earlier account read is pending")
    require(requests { desktop.receive(setup) } == [accountRead], "fresh account read after the older account reply")
    desktop.receive(["page": "cluster", "title": "Account", "detail": "Gent account: Signed in · @fixture",
        "actions": [["kind": "sign_out", "title": "Sign out", "confirm": "Sign out?"],
                    ["kind": "finish_setup", "title": "Install or repair daemon…", "confirm": "Install and start?"]]])
    desktop.receive(stopped)
    require(!desktop.health.isHidden && !desktop.nodes.view.isHidden && account.title.stringValue == "Account"
            && actionButton(account.actions, "Install or repair daemon…").isEnabled && account.actions.notice.stringValue == "Signed in",
            "enrolled stopped node shows health and repair")
    require(desktop.toggle.title == "Start daemon" && !desktop.restart.isEnabled
            && requests { desktop.toggle.performClick(nil) } == [.command("start")], "stopped daemon can be started")
}

func checkMembers(_ desktop: Desktop, stopped: [String: Any]) {
    let nodes = desktop.nodes
    let ids = (0..<3).map { _ in UUID().uuidString.lowercased() }
    let renameSpec: [String: Any] = ["kind": "rename_node", "title": "Rename node…", "submit": "Rename", "row": true,
                                    "fields": [["key": "name", "title": "New node name"]]]
    let actions: [[String: Any]] = [renameSpec, ["kind": "invite", "title": "Add node…"],
        ["kind": "node_role", "title": "Change role…", "row": true],
        ["kind": "remove_node", "title": "Remove node…", "row": true, "confirm": "Remove?"]]
    let presence = "Waiting for a fresh encrypted round trip"
    var rows = [
        ["name": "Studio", "state": "local", "role": "Owner", "id": ids[0]],
        ["name": "Remote", "state": "offline", "status_detail": presence, "role": "Admin", "id": ids[1], "directory": "matched", "route": "Direct QUIC"],
        ["name": "claude-web", "state": "hosted", "role": "Member", "host": "Studio", "id": ids[2]],
    ]
    let connection = "Notifications connected · Retrying streams: 1"
    func receiveRows(directoryError: String? = nil, extraMembers: [[String: String]] = []) {
        var directory: [String: Any] = ["rows": rows + extraMembers, "actions": actions]
        directory["error"] = directoryError
        desktop.receive(["enrolled": true, "node": rows[0]["name"]!, "cluster": "Local fixture", "state": "Running",
                         "running": true, "can_stop": true, "queue": 0, "chats": 2, "sync": "idle", "connection": connection,
                         "nodes": directory])
    }
    require(requests { receiveRows() }.isEmpty, "ordinary snapshot renders without follow-up requests")
    require(!nodes.view.isHidden && nodes.table.numberOfRows == 3 && nodes.table.tableColumns.map { $0.title }
            == ["Node", "Status", "Role", "Directory", "Last transport", "Hosted by", "Node ID"], "signed members in one table")
    require(cell(nodes.table, "state", row: 0) == "local" && cell(nodes.table, "role", row: 0) == "Owner"
            && cell(nodes.table, "state", row: 1) == "offline" && cell(nodes.table, "directory", row: 1) == "matched"
            && cell(nodes.table, "route", row: 1) == "Direct QUIC" && cell(nodes.table, "name", row: 2) == "claude-web"
            && cell(nodes.table, "route", row: 2) == "—" && cell(nodes.table, "host", row: 2) == "Studio",
            "local, offline and hosted rows have distinct status, observed transport and carrier")
    require(cellField(nodes.table, "state", row: 1)?.toolTip == presence
            && cellField(nodes.table, "state", row: 0)?.toolTip == "local", "presence evidence in Status tooltip when supplied")
    require(desktop.cluster.stringValue == "Local fixture" && desktop.node.stringValue.contains("Studio")
            && desktop.metrics["queue"]?.stringValue == "0" && desktop.metrics["chats"]?.stringValue == "2"
            && desktop.metrics["sync"]?.stringValue == "Idle" && desktop.connection.stringValue == connection
            && desktop.trayState.title == "Daemon running", "identity, health, notifications and retry state")
    require(desktop.toggle.title == "Stop daemon" && requests { desktop.toggle.performClick(nil) } == [.command("stop")],
            "managed daemon can be stopped")
    desktop.receive(stopped)
    receiveRows()
    require(requests { desktop.restart.performClick(nil) } == [.command("restart")], "restart daemon")
    receiveRows()

    receiveRows(extraMembers: (1...50).map { ["id": UUID().uuidString, "name": "Member \($0)", "state": "offline", "role": "Member"] })
    desktop.window.contentView?.layoutSubtreeIfNeeded()
    let scroll = desktop.tabs.selectedTabViewItem!.view as! NSScrollView
    let clip = scroll.contentView
    let memberScroll = nodes.table.enclosingScrollView!
    require(abs(memberScroll.bounds.width - (clip.bounds.width - 32)) <= 1 && memberScroll.hasHorizontalScroller
            && nodes.table.rect(ofColumn: 6).maxX > memberScroll.contentSize.width, "member columns scroll within the page")
    require(scroll.documentView!.bounds.height > clip.bounds.height && abs(scroll.documentView!.bounds.width - clip.bounds.width) <= 1,
            "Cluster fits the narrow viewport and scrolls vertically")
    for button in descendants(nodes.actions.view, of: NSButton.self) + descendants(desktop.account.actions.view, of: NSButton.self) {
        let rect = button.convert(button.bounds, to: clip)
        require(rect.width > 0 && rect.minX >= clip.bounds.minX && rect.maxX <= clip.bounds.maxX,
                "action fits narrow window: " + button.title)
    }
    let shortTableHeight = memberScroll.bounds.height
    let shortDocumentHeight = scroll.documentView!.bounds.height
    let shortVisibleRows = nodes.table.rows(in: nodes.table.visibleRect).length
    require(abs(shortTableHeight - 160) <= 1, "short window preserves the member table minimum")
    resizeCluster(desktop, height: 900)
    let extraHeight = clip.bounds.height - shortDocumentHeight
    require(extraHeight > nodes.table.rowHeight && abs(scroll.documentView!.bounds.height - clip.bounds.height) <= 1
            && abs(memberScroll.bounds.height - shortTableHeight - extraHeight) <= 1
            && nodes.table.rows(in: nodes.table.visibleRect).length > shortVisibleRows,
            "narrow tall window gives spare height to visible member rows")
    resizeCluster(desktop, height: 400)
    require(abs(memberScroll.bounds.height - shortTableHeight) <= 1 && scroll.documentView!.bounds.height > clip.bounds.height,
            "shrinking the window restores outer scrolling")
    receiveRows()
    desktop.window.setContentSize(NSSize(width: 850, height: 605))
    let remove = actionButton(nodes.actions, "Remove node…")
    let role = actionButton(nodes.actions, "Change role…")
    nodes.table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
    require(!remove.isEnabled && !role.isEnabled, "owner protected from removal and role changes")
    rows[0]["role"] = "Admin"
    receiveRows()
    require(!remove.isEnabled && !role.isEnabled, "local non-owner protected")
    rows[0]["role"] = "Owner"
    receiveRows()
    func search(_ query: String) {
        nodes.search.stringValue = query
        nodes.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification, object: nodes.search))
    }
    search("o")
    nodes.table.selectRowIndexes(IndexSet(integer: 2), byExtendingSelection: false)
    rows.swapAt(1, 2)
    receiveRows()
    require(nodes.search.stringValue == "o" && nodes.table.selectedRow == 1 && cell(nodes.table, "id", row: 1) == ids[2]
            && remove.isEnabled && role.isEnabled, "filtered selection follows UUID through reordered snapshot")
    search("direct quic")
    require(nodes.table.numberOfRows == 1 && nodes.table.selectedRow == -1 && !remove.isEnabled, "transport searchable, stale selection cleared")
    receiveRows(directoryError: "Directory unavailable")
    require(nodes.status.stringValue == "Directory unavailable" && desktop.errorMessage.isHidden,
            "directory error displayed independently of daemon health")
    search(ids[2])
    require(nodes.status.stringValue == "Directory unavailable", "search preserves directory error")
    receiveRows()
    require(nodes.table.numberOfRows == 1 && cell(nodes.table, "name", row: 0) == "claude-web", "stable ID searchable")
    search("")
    rows.swapAt(1, 2)
    receiveRows()
    func expectSubmit(_ index: Int, _ name: String) {
        let sent = editMember(desktop, at: index, member: rows[index], name: name)
        require(sent == [.json(["op": "manage",
                "action": ["kind": "rename_node", "id": ids[index], "name": name]])],
                "rename submitted once for selected node UUID")
    }
    require(!actionButton(nodes.actions, "Rename node…").isEnabled, "rename requires a selection")
    require(editMember(desktop, at: 2, member: rows[2], name: "Cancelled", cancel: true).isEmpty, "cancel sends no request")
    expectSubmit(2, "Rejected edit")
    receiveRows()
    require(!actionButton(nodes.actions, "Rename node…").isEnabled && nodes.actions.notice.stringValue == "Working…",
            "snapshot preserves pending member operation")
    let failure = requests { desktop.receive(["page": "nodes", "operation": true, "error": "Permission denied"]) }
    require(failure.isEmpty && nodes.actions.notice.stringValue == "Permission denied"
            && cell(nodes.table, "name", row: 2) == "claude-web", "error shown with original row")
    for (index, name) in [(2, "Renamed web"), (1, "Renamed remote"), (0, "Renamed owner")] {
        expectSubmit(index, name)
        if index == 1 { require(requests { desktop.poll() } == [snapshotRead], "poll pending at rename completion") }
        let refresh = requests { desktop.receive(["page": "nodes", "operation": true, "notice": "Configuration change: applied"]) }
        if index == 1 {
            require(refresh.isEmpty && requests { receiveRows() } == [snapshotRead], "refresh after the older snapshot arrives")
        } else {
            require(refresh == [snapshotRead], "one ordinary refresh after rename")
        }
        rows[index]["name"] = name
        if index == 0 { rows[2]["host"] = name }
        receiveRows()
        require(nodes.actions.notice.stringValue == "Configuration change: applied" && nodes.table.selectedRow == index
                && cell(nodes.table, "name", row: index) == name && cell(nodes.table, "id", row: index) == ids[index],
                "renamed row retains its ID")
    }
}

func editMember(_ desktop: Desktop, at index: Int, member: [String: String], name: String, cancel: Bool = false) -> [Request] {
    let nodes = desktop.nodes
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

    let rename = actionButton(nodes.actions, "Rename node…")
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
    require(input.stringValue == member["name"], "current name prefilled")
    require(descendants(content, of: NSTextField.self).contains { $0.stringValue.contains(member["id"]!) },
            "dialog identifies selected member")
    input.stringValue = name
    return requests {
        button.performClick(nil)
        waitFor("rename dialog dismissed") { !dialog.isVisible && (cancel || !rename.isEnabled) }
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
    require(sent == [.json(["op": "dashboard_click", "agent": "agent-2",
                                "revision": 12, "widget": "retry"])],
            "one newline-delimited click for the displayed chat, revision and widget")
    desktop.window.setContentSize(NSSize(width: 850, height: 605))
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let desktop = Desktop(iconPath: CommandLine.arguments[1], openAtLaunch: false)
if CommandLine.arguments.dropFirst(2).contains(where: { ["--cluster", "--nodes"].contains($0) }) {
    desktop.makeWindow()
    checkCluster(desktop) { desktop.show() }
    print("PASS: native Cluster setup, status, member search, guarded actions, rename dialogs and refresh requests")
    exit(0)
}
app.delegate = desktop
// The pipe stays open so the UI has the same lifetime as a normal Gent child.
let lifetime = Pipe()
dup2(lifetime.fileHandleForReading.fileDescriptor, STDIN_FILENO)
DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
    require(desktop.statusItem?.isVisible == true && desktop.statusItem?.button?.image != nil,
            "visible menu-bar item and image in a logged-in Aqua session")
    require(!desktop.window.isVisible, "starts in tray")
    let menu = desktop.statusItem.menu!
    guard let open = menu.item(withTitle: "Open Gent Desktop"), let action = open.action else {
        require(false, "Open menu item")
        return
    }
    desktop.receive(["enrolled": false, "state": "Unavailable"])
    checkCluster(desktop) {
        require(app.sendAction(action, to: open.target, from: open), "open through actual menu target")
        require(desktop.window.isVisible && desktop.window.windowNumber > 0, "ordered AppKit window")
    }
    checkDashboard(desktop)
    desktop.tabs.selectTabViewItem(withIdentifier: "Chats")
    desktop.receive(["page":"chats","rows":[["name":"Remote chat","node":"Other node","provider":"codex","state":"Registered","id":"c"]]])
    require(desktop.chats.table.numberOfRows == 1, "cluster chat rendered")
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
    desktop.receive(["page":"cluster","title":"Account","detail":"Gent account: Signed in · @fixture",
                     "actions":[["title":"Sign out","kind":"sign_out","confirm":"Sign out?"]]])
    require(desktop.account.detail.stringValue.contains("@fixture"), "account displayed")
    let signOut = actionButton(desktop.account.actions, "Sign out")
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
    FileHandle.standardError.write(Data("PASS: AppKit menu bar, consolidated Cluster setup, daemon controls, member search and actions, Dashboard resizing and button dispatch, directories, editable settings, account confirmation, permissions, about, update check, close, reopen and quit\n".utf8))
    _ = app.sendAction(stop, to: quit.target, from: quit)
}
app.run()
