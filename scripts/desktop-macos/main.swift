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

func checkOrdinaryRecovery() {
    let pane = SettingsTab()
    let buttons = descendants(pane.view, of: NSButton.self)
    require(descendants(pane.view, of: NSTextField.self).contains { $0.stringValue.contains("eligible Codex chats") },
            "ordinary recovery identifies the supported host")
    let ordinary = buttons.first { $0.title == "Continue ordinary chats after provider errors" }!
    let goal = buttons.first { $0.title == "Resume goals after provider failures" }!
    func show(paid: Bool, goals: Bool, chats: Bool) {
        pane.receive(["values": ["paid": paid, "babysitter": goals, "ordinary_babysitter": chats]])
    }
    pane.receive(["error": "node configuration is missing"])
    require(!goal.isEnabled && !ordinary.isEnabled, "recovery controls require a configured node")
    for paid in [false, true] {
        show(paid: paid, goals: true, chats: false)
        require(goal.isEnabled && ordinary.isEnabled && goal.state == .on && ordinary.state == .off,
                "both recovery preferences are editable with independent defaults")
        require(requests { ordinary.performClick(nil) } == [.json(["op":"set","key":"ordinary_babysitter","enabled":true])],
                "enable ordinary recovery")
        show(paid: paid, goals: true, chats: true)
        require(goal.state == .on && ordinary.state == .on, "ordinary recovery preserves goal recovery")
        require(requests { goal.performClick(nil) } == [.json(["op":"set","key":"babysitter","enabled":false])],
                "disable goal recovery")
        show(paid: paid, goals: false, chats: true)
        require(goal.state == .off && ordinary.state == .on, "goal opt-out preserves ordinary recovery")
        require(requests { ordinary.performClick(nil) } == [.json(["op":"set","key":"ordinary_babysitter","enabled":false])],
                "disable ordinary recovery")
        show(paid: paid, goals: false, chats: false)
        require(requests { goal.performClick(nil) } == [.json(["op":"set","key":"babysitter","enabled":true])],
                "restore goal recovery")
    }
}

let accountRead = Request.json(["op": "cluster"])
let snapshotRead = Request.command("refresh")

@discardableResult
func waitInMainRunLoop(until ready: () -> Bool) -> Bool {
    let deadline = ProcessInfo.processInfo.systemUptime + 3
    while !ready() && ProcessInfo.processInfo.systemUptime < deadline {
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
    }
    return ready()
}

func requests(waitForOutput: Bool = false, during action: () -> Void) -> [Request] {
    let pipe = Pipe()
    let output = dup(STDOUT_FILENO)
    require(output >= 0 && dup2(pipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO) >= 0, "capture supervisor requests")
    action()
    if waitForOutput {
        var reader = pollfd(fd: pipe.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
        waitInMainRunLoop { poll(&reader, 1, 0) == 1 }
    }
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

func checkReleaseChannel(_ desktop: Desktop) {
    let settings = desktop.settings
    let row = settings.channel
    require(descendants(row.view, of: NSTextField.self).contains { $0.stringValue.contains("one update per node") },
            "channel change explains one-time updates on paused nodes")
    let reads = requests { desktop.showSettings() }
    require(reads.contains(.json(["op": "release_channel"])) && reads.contains(.json(["op": "settings"])),
            "Settings independently loads local preferences and the signed channel")
    desktop.receive(["page": "settings", "values": ["updates": false, "discovery": true]])
    func receive(_ fields: [String: Any]) {
        var reply = fields
        reply["page"] = "release_channel"
        desktop.receive(reply)
    }
    receive(["current": "stable", "can_set": true])
    require(row.choice.isEnabled && row.choice.titleOfSelectedItem == "Stable", "last accepted channel selected")
    row.choice.selectItem(withTitle: "Beta")
    require(requests { _ = NSApp.sendAction(row.choice.action!, to: row.choice.target, from: row.choice) }
            == [.json(["op": "set_release_channel", "channel": "beta"])], "choose Beta through the popup")
    require(!row.choice.isEnabled && row.choice.titleOfSelectedItem == "Stable" && row.detail.stringValue.contains("Beta"),
            "requesting Beta preserves verified Stable")
    receive(["current": "stable", "pending": true, "notice": "Beta queued"])
    require(requests { settings.pollChannel() } == [.json(["op": "release_channel"])], "queued edit polls by reading")
    receive(["current": "stable", "pending": true, "retry": true, "notice": "Unconfirmed"])
    require(!row.retry.isHidden && requests { row.retry.performClick(nil) } == [.json(["op": "retry_release_channel"])],
            "explicit retry uses the supervisor's saved intent")
    settings.openEditor()
    desktop.receive(["page": "settings", "document": "draft"])
    receive(["current": "beta", "can_set": true, "notice": "Cluster accepted beta"])
    require(settings.text.string == "draft" && !settings.text.isHiddenOrHasHiddenAncestor && row.choice.titleOfSelectedItem == "Beta",
            "channel reply preserves an open draft")
    settings.discard()
    desktop.receive(["page": "settings"])
    let checks = descendants(settings.view, of: NSButton.self)
    require(checks.first { $0.title == "Automatically update Gent" }?.state == .off &&
            checks.first { $0.title == "Discover and publish native chats" }?.state == .on, "node preferences survive channel replies")
    receive(["current": "beta", "can_set": false])
    require(!row.choice.isEnabled && row.choice.titleOfSelectedItem == "Beta", "member can see the signed channel")
    receive(["notice": "Unavailable"])
    require(!row.choice.isEnabled && row.choice.indexOfSelectedItem == -1, "unknown channel remains unselected")
}

func checkCluster(_ desktop: Desktop, open: () -> Void) {
    require(desktop.tabs.tabViewItems.map { $0.label } == ["Status", "Dashboard", "Chats", "Settings", "Permissions", "About"]
            && desktop.tabs.selectedTabViewItem?.label == "Status", "Status is the first and selected tab")
    require(requests(during: open) == [snapshotRead, accountRead], "opening Status reads snapshot and account once")
    let stopped: [String: Any] = ["enrolled": true, "node": "Studio", "cluster": "Local fixture", "state": "Stopped",
                                  "can_start": true, "nodes": ["rows": [], "actions": []]]
    checkSetup(desktop, stopped: stopped)
    checkMembers(desktop, stopped: stopped)
}

func resizeDesktop(_ desktop: Desktop, width: CGFloat = 510, height: CGFloat) {
    let size = NSSize(width: width, height: height)
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
    resizeDesktop(desktop, height: 400)
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
    resizeDesktop(desktop, height: 900)
    let tallSetupTop = account.title.convert(account.title.bounds, to: document).minY - scroll.documentVisibleRect.minY
    require(setupTop < 100 && abs(setupTop - tallSetupTop) <= 1, "setup stays at the top of a tall window")
    resizeDesktop(desktop, height: 400)
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
    require(requests { desktop.tabs.selectTabViewItem(withIdentifier: "Status") } == [snapshotRead, accountRead],
            "selecting Status reads both")
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

func checkNodeActionRow(_ desktop: Desktop, width: CGFloat, height: CGFloat) {
    resizeDesktop(desktop, width: width, height: height)
    let row = desktop.nodes.actions.view
    let scroll = row.enclosingScrollView!
    let titles = ["Add node…", "Rename node…", "Change role…", "Remove node…"]
    let buttons = row.arrangedSubviews.compactMap { $0 as? NSButton }
    require(buttons.map { $0.title } == titles, "four node action labels in supervisor order")
    let table = desktop.nodes.table.enclosingScrollView!
    let page = scroll.enclosingScrollView!.documentView!
    require(scroll.convert(scroll.bounds, to: page).minY >= table.convert(table.bounds, to: page).maxY,
            "node actions below the table")
    let frames = buttons.map { $0.convert($0.bounds, to: row) }
    for (index, button) in buttons.enumerated() {
        require(button.image == nil && !button.isHiddenOrHasHiddenAncestor
                && button.bounds.width >= button.intrinsicContentSize.width - 1
                && abs(frames[index].midY - frames[0].midY) <= 1
                && (index == 0 || frames[index].minX >= frames[index - 1].maxX),
                "full text button on one row at width \(width): " + button.title)
    }
    if width == 850 {
        require(frames.allSatisfy { scroll.documentVisibleRect.contains($0) }
                && abs(scroll.bounds.height - scroll.contentSize.height) <= 1
                && abs(scroll.bounds.height - row.fittingSize.height) <= 1,
                "default width fits all node buttons without scrollbar height")
    }
    let trailing = frames.last!
    row.scrollToVisible(trailing)
    let center = row.convert(NSPoint(x: trailing.midX, y: trailing.midY), to: scroll)
    require(scroll.documentVisibleRect.contains(trailing) && scroll.contentView.hitTest(center) === buttons.last,
            "trailing Remove node button reachable at width \(width)")
}

func checkMembers(_ desktop: Desktop, stopped: [String: Any]) {
    let nodes = desktop.nodes
    let ids = (0..<3).map { _ in UUID().uuidString.lowercased() }
    let renameSpec: [String: Any] = ["kind": "rename_node", "title": "Rename node…", "submit": "Rename", "row": true,
                                    "fields": [["key": "name", "title": "New node name"]]]
    let actions: [[String: Any]] = [["kind": "invite", "title": "Add node…"], renameSpec,
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
    require(nodes.search.placeholderString == "Filter nodes" && nodes.status.stringValue == "3 of 3 nodes",
            "node search and count labels")
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
    let actionScroll = nodes.actions.view.enclosingScrollView!
    let originalStyle = actionScroll.scrollerStyle
    let minimum = desktop.window.contentRect(forFrameRect: NSRect(origin: .zero, size: desktop.window.minSize)).size
    for style in [NSScroller.Style.legacy, .overlay] {
        actionScroll.scrollerStyle = style
        checkNodeActionRow(desktop, width: 850, height: 605)
        checkNodeActionRow(desktop, width: minimum.width, height: minimum.height)
    }
    actionScroll.scrollerStyle = originalStyle
    desktop.tabs.layoutSubtreeIfNeeded()
    let scroll = desktop.tabs.selectedTabViewItem!.view as! NSScrollView
    let clip = scroll.contentView
    let memberScroll = nodes.table.enclosingScrollView!
    require(abs(memberScroll.bounds.width - (clip.bounds.width - 32)) <= 1 && memberScroll.hasHorizontalScroller
            && nodes.table.rect(ofColumn: 6).maxX > memberScroll.contentSize.width, "member columns scroll within the page")
    require(scroll.documentView!.bounds.height > clip.bounds.height && abs(scroll.documentView!.bounds.width - clip.bounds.width) <= 1,
            "Status fits the narrow viewport and scrolls vertically")
    for button in descendants(desktop.account.actions.view, of: NSButton.self) {
        let rect = button.convert(button.bounds, to: clip)
        require(rect.width > 0 && rect.minX >= clip.bounds.minX && rect.maxX <= clip.bounds.maxX,
                "action fits narrow window: " + button.title)
    }
    let shortTableHeight = memberScroll.bounds.height
    let shortDocumentHeight = scroll.documentView!.bounds.height
    let shortVisibleRows = nodes.table.rows(in: nodes.table.visibleRect).length
    require(abs(shortTableHeight - 160) <= 1, "short window preserves the member table minimum")
    resizeDesktop(desktop, height: 900)
    let extraHeight = clip.bounds.height - shortDocumentHeight
    require(extraHeight > nodes.table.rowHeight && abs(scroll.documentView!.bounds.height - clip.bounds.height) <= 1
            && abs(memberScroll.bounds.height - shortTableHeight - extraHeight) <= 1
            && nodes.table.rows(in: nodes.table.visibleRect).length > shortVisibleRows,
            "narrow tall window gives spare height to visible member rows")
    resizeDesktop(desktop, height: 400)
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

func fixtureRaster(_ format: NSBitmapImageRep.FileType, width: Int, height: Int) -> Data {
    let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height,
                                  bitsPerSample: 8, samplesPerPixel: 3, hasAlpha: false, isPlanar: false,
                                  colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    memset(bitmap.bitmapData!, 128, bitmap.bytesPerRow * height)
    return bitmap.representation(using: format, properties: [:])!
}

// Use AppKit's native backing for the first capture. A bitmap with two pixels per
// point also exercises the 2× drawing path on a screenless SSH host.
func chartCapture(_ view: NSImageView, at2x: Bool) -> NSBitmapImageRep {
    let bitmap: NSBitmapImageRep
    if at2x {
        let size = view.bounds.size
        bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(ceil(size.width * 2)),
                                  pixelsHigh: Int(ceil(size.height * 2)), bitsPerSample: 8,
                                  samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                  colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        bitmap.size = size
        NSGraphicsContext.saveGraphicsState()
        let context = NSGraphicsContext(bitmapImageRep: bitmap)!
        NSGraphicsContext.current = context
        view.cell!.draw(withFrame: view.bounds, in: view)
        NSGraphicsContext.restoreGraphicsState()
    } else {
        bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds)!
        view.cacheDisplay(in: view.bounds, to: bitmap)
    }
    return bitmap
}

func rasterizedAtSourceSize(_ vector: NSImage) -> NSImage {
    let size = vector.size
    let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width), pixelsHigh: Int(size.height),
                                  bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                  colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)!
    vector.draw(in: NSRect(origin: .zero, size: size))
    NSGraphicsContext.restoreGraphicsState()
    let image = NSImage(size: size)
    image.addRepresentation(bitmap)
    return image
}

func checkChartPixels(_ bitmap: NSBitmapImageRep, kind: String, expectSharp: Bool) {
    let width = Double(bitmap.pixelsWide)
    func pixel(_ x: Int, _ y: Int) -> NSColor {
        bitmap.colorAt(x: x, y: y)!.usingColorSpace(.sRGB)!
    }
    func midline(_ x: Double) -> NSColor { pixel(Int(x / 60 * width), bitmap.pixelsHigh / 2) }
    let mark = midline(6)
    require(mark.blueComponent > 0.9 && mark.redComponent < 0.3, "native SVG draws the " + kind + " mark")
    if expectSharp {
        let xs = stride(from: bitmap.pixelsWide / 3, to: bitmap.pixelsWide * 9 / 10, by: 4)
        let ys = stride(from: 0, to: bitmap.pixelsHigh, by: 4)
        let hasText = xs.contains { x in
            ys.contains { y in
                let color = pixel(x, y)
                return color.alphaComponent > 0.95 && color.redComponent < 0.3
            }
        }
        require(hasText, "native SVG draws chart text for " + kind)
    }

    // The screen color profile affects even fully covered red pixels. Sample both
    // endpoints of the contrast scale from broad, solid fills in this same capture.
    let red = midline(16.5)
    let paper = midline(19)
    let contrast = paper.greenComponent - red.greenComponent
    require(red.alphaComponent > 0.98 && red.redComponent - red.greenComponent > 0.45
            && paper.greenComponent > 0.9 && contrast > 0.5, "red and white SVG reference fills")
    func matches(_ color: NSColor, _ reference: NSColor) -> Bool {
        max(abs(color.redComponent - reference.redComponent),
            abs(color.greenComponent - reference.greenComponent),
            abs(color.blueComponent - reference.blueComponent)) <= contrast * 0.05 && color.alphaComponent > 0.98
    }
    let left = 12.25 / 60 * width
    let right = 12.75 / 60 * width
    let scan = (Int(floor(left)) - 3)...(Int(ceil(right)) + 3)
    let core = scan.filter { matches(pixel($0, bitmap.pixelsHigh / 2), red) }
    var sharp = false
    if let first = core.first, let last = core.last {
        // Allow antialiasing on each edge; require a solid contiguous interior
        // of the projected width and white paper immediately outside both edges.
        sharp = core.count == last - first + 1 && core.count >= max(1, Int(floor(right - left)) - 2)
            && abs(Double(first) - left) <= 2 && abs(Double(last + 1) - right) <= 2
            && matches(pixel(scan.lowerBound, bitmap.pixelsHigh / 2), paper)
            && matches(pixel(scan.upperBound, bitmap.pixelsHigh / 2), paper)
    }
    require(sharp == expectSharp,
            "\(kind) stripe in \(bitmap.pixelsWide)×\(bitmap.pixelsHigh) capture, expected sharp=\(expectSharp), " +
            "edges=\(left)...\(right), solid pixels=\(core), reference=\(red), center=\(midline(12.5))")
}

let chartCategories = [["label": "A", "value": 1], ["label": "B", "value": 2], ["label": "C", "value": 3]]
let fixtureCharts: [(kind: String, value: Any)] = [
    ("graph", [0.5, 1.5]), ("bar", chartCategories), ("pie", chartCategories),
    ("radar", chartCategories), ("scatter", [[1, 2], [2, 3]]),
]

func checkDashboardMedia(_ desktop: Desktop, scroll: NSScrollView) {
    let marks = [
        #"<path d="M1 8 C4 5 8 11 11 8" fill="none" stroke="blue" stroke-width="2"/>"#,
        #"<rect x="4" y="2" width="4" height="8" fill="blue"/>"#,
        #"<path d="M3 4 A7 7 0 0 1 10 11 L3 11 Z" fill="blue"/>"#,
        #"<polygon points="2,10 6,3 10,10" fill="blue"/>"#,
        #"<circle cx="6" cy="8" r="2" fill="blue"/>"#,
    ]
    var widgets: [[String: Any]] = fixtureCharts.enumerated().map { i, chart in
        let kind = chart.kind
        // The half-unit stripe must remain solid red when AppKit enlarges the vector.
        let height = 16 + i * 2
        let svg = """
        <svg xmlns="http://www.w3.org/2000/svg" width="60" height="\(height)" viewBox="0 0 60 \(height)">
        <rect width="60" height="\(height)" fill="white"/><rect x="12.25" width=".5" height="\(height)" fill="red"/>
        <rect x="15" width="3" height="\(height)" fill="red"/>
        <g transform="translate(0 \(i))">\(marks[i])</g>
        <text x="20" y="12" font-size="7">\(kind)</text></svg>
        """
        return ["kind": kind, "label": kind, "id": kind, "unit": "ms", "value": chart.value,
                "chart_svg": svg, "chart_description": "Summary of " + kind]
    }
    widgets.append(["kind": "metric", "id": "duration", "label": "Latency", "value": 21.5, "unit": "ms"])
    widgets.append(["kind": "metric", "id": "count", "label": "Count:  ", "value": 0])
    let png = fixtureRaster(.png, width: 1024, height: 256)
    let jpeg = fixtureRaster(.jpeg, width: 90, height: 600)
    let pngPrefix = "data:image/png;base64,"
    let jpegPrefix = "data:image/jpeg;base64,"
    // A legal 24 KiB JPEG comment takes this small picture over the encoded byte limit.
    let paddedJPEG = jpeg.prefix(2) + Data([0xff, 0xfe, 0x60, 0x02]) + Data(count: 24 * 1024) + jpeg.dropFirst(2)
    let sources = [
        ("Wide PNG", pngPrefix + png.base64EncodedString()), ("Tall JPEG", jpegPrefix + jpeg.base64EncodedString()),
        ("Remote", "https://example.invalid/image.png"), ("Broken", pngPrefix + "!!"),
        ("PNG declared as JPEG", jpegPrefix + png.base64EncodedString()),
        ("JPEG declared as PNG", pngPrefix + jpeg.base64EncodedString()),
        ("Inline SVG", "data:image/svg+xml;base64," + Data("<svg/>".utf8).base64EncodedString()),
        ("Truncated PNG", pngPrefix + png.dropLast(12).base64EncodedString()),
        ("Truncated JPEG", jpegPrefix + jpeg.dropLast(2).base64EncodedString()),
        ("Oversized", jpegPrefix + paddedJPEG.base64EncodedString()),
        ("Too wide", pngPrefix + fixtureRaster(.png, width: 2049, height: 1).base64EncodedString()),
        ("Too many pixels", pngPrefix + fixtureRaster(.png, width: 1025, height: 1024).base64EncodedString()),
    ]
    for (i, source) in sources.enumerated() {
        widgets.append(["kind": "image", "id": "image-\(i)", "label": source.0, "value": source.1])
    }
    widgets.append(["kind": "bar", "id": "missing", "label": "Missing chart", "value": chartCategories,
                    "chart_description": "Bar summary without a drawing"])
    let view = desktop.dashboard.view
    let board: [String: Any] = ["agent": "charts", "chat": "Chart fixture", "revision": 1,
                                "board": ["title": "Telemetry", "widgets": widgets]]
    func reply(_ fields: [String: Any]) {
        require(requests { desktop.receive(fields.merging(["page": "dashboard"]) { _, new in new }) }.isEmpty,
                "media and unchanged replies generate no supervisor requests")
        desktop.tabs.layoutSubtreeIfNeeded()
    }
    reply(["rows": [board]])
    let card = descendants(view, of: NSBox.self).first!
    let images = descendants(card, of: NSImageView.self)
    require(images.count == fixtureCharts.count + 2, "only charts and valid inline rasters produce images")
    func image(_ label: String) -> NSImageView {
        guard let image = images.first(where: { $0.accessibilityLabel() == label }) else {
            fatalError("Missing accessible image " + label)
        }
        require(image.isAccessibilityElement() && image.accessibilityRole() == .image && image.toolTip == label,
                "accessible image description for " + label)
        return image
    }
    let fields = descendants(card, of: NSTextField.self)
    require(fields.contains { $0.stringValue == "1.5 ms" } && fields.contains { $0.stringValue == "Bar summary without a drawing" },
            "latest graph value and fallback chart description")
    for (label, number) in [("Latency:", "21.5 ms"), ("Count:", "0")] {
        guard let caption = fields.first(where: { $0.stringValue == label }),
              let line = caption.superview as? NSStackView,
              let reading = line.arrangedSubviews.last as? NSTextField else { fatalError("Missing metric row") }
        require(line.accessibilityLabel() == label + " " + number && reading.stringValue == number
                && caption.font!.fontDescriptor.symbolicTraits.contains(.bold)
                && !reading.font!.fontDescriptor.symbolicTraits.contains(.bold)
                && reading.alignment == .right && abs(reading.alignmentRect(forFrame: reading.frame).maxX - line.bounds.maxX) <= 1,
                "metric label and single colon bold, reading and unit regular and right aligned")
    }
    require(fields.filter { $0.stringValue == "Image unavailable" }.count == sources.count - 2,
            "invalid, remote and oversized images show placeholders")

    for width: CGFloat in [850, 510] {
        resizeDesktop(desktop, width: width, height: 605)
        let contentWidth = card.contentView!.bounds.width
        for (i, example) in fixtureCharts.enumerated() {
            let kind = example.kind
            let chart = image("Summary of " + kind)
            let size = chart.bounds.size
            require(abs(size.width - contentWidth) <= 1 && abs(size.height - size.width * CGFloat(16 + i * 2) / 60) <= 1,
                    "full-width proportional SVG at \(width) for " + kind)
            chart.scrollToVisible(chart.bounds)
            for at2x in [false, true] {
                checkChartPixels(chartCapture(chart, at2x: at2x), kind: kind, expectSharp: true)
            }
            if kind == "graph" {
                // The same mark and reference patch survive an upscale from
                // 60×16 pixels. The half-unit stripe must fail the sharpness check.
                let vector = chart.image!
                chart.image = rasterizedAtSourceSize(vector)
                for at2x in [false, true] {
                    checkChartPixels(chartCapture(chart, at2x: at2x), kind: kind, expectSharp: false)
                }
                chart.image = vector
            }
        }
        let landscape = image("Wide PNG").bounds
        let portrait = image("Tall JPEG").bounds
        require(abs(landscape.width - contentWidth) <= 1 && abs(landscape.height - landscape.width / 4) < 1
                && portrait.height > 0 && portrait.height <= 360 && abs(portrait.width - portrait.height * 0.15) <= 1,
                "PNG and JPEG fit at their aspect ratios at \(width), content \(contentWidth), " +
                "landscape \(landscape.size), portrait \(portrait.size)")
    }

    let clip = scroll.contentView
    require(scroll.documentView!.bounds.height > clip.bounds.height, "media board scrolls")
    let last = fields.first { $0.stringValue == "Bar summary without a drawing" }!
    last.scrollToVisible(last.bounds)
    require(clip.bounds.contains(last.convert(last.bounds, to: clip)), "last widget below charts and rasters is reachable")
    clip.scroll(to: NSPoint(x: 0, y: 200))
    reply(["error": "Transient dashboard error"])
    let notice = descendants(view, of: NSTextField.self).first { $0.stringValue == "Transient dashboard error" }!
    require(!notice.isHiddenOrHasHiddenAncestor, "dashboard shows transient errors")
    let position = scroll.documentVisibleRect.origin
    reply(["unchanged": true])
    require(notice.isHiddenOrHasHiddenAncestor && position.y > 0 && position == scroll.documentVisibleRect.origin
            && descendants(view, of: NSBox.self).first === card && descendants(card, of: NSImageView.self).first === images.first,
            "unchanged populated reply clears error and preserves cards, media and scroll position")
    var replacement = board
    replacement["board"] = ["title": "Telemetry", "widgets": [
        ["kind": "metric", "id": "duration", "label": "Latency:", "value": 42, "unit": "ms"]
    ]]
    reply(["rows": [replacement]])
    require(descendants(view, of: NSImageView.self).isEmpty
            && descendants(view, of: NSStackView.self).contains { $0.accessibilityLabel() == "Latency: 42 ms" },
            "a differing full snapshot replaces stale media and values")
    reply(["rows": []])
    reply(["notice": "Waiting for refresh"])
    reply(["unchanged": true])
    require(!notice.isHiddenOrHasHiddenAncestor && notice.stringValue == "No chats have published a dashboard.",
            "unchanged empty reply restores empty state")
}

// Model the private supervisor reply: the last row uses the width for its own card count.
func checkNegotiatedChartSizes(_ desktop: Desktop, widths: [Int], boards: Int) {
    let rows: [[String: Any]] = (0..<boards).map { index in
        let count = min(widths.count, boards - (index / widths.count) * widths.count)
        let width = widths[count - 1]
        let svg = """
        <svg xmlns="http://www.w3.org/2000/svg" width="\(width)" height="90" viewBox="0 0 \(width) 90">
        <path d="M4 60 H\(width - 4)" stroke="blue" stroke-width="2"/><text x="4" y="80" font-size="12">Sample</text></svg>
        """
        let examples = boards == 1 ? fixtureCharts : [fixtureCharts[index % fixtureCharts.count]]
        let widgets: [[String: Any]] = examples.map { chart in
            ["kind": chart.kind, "id": chart.kind, "label": chart.kind, "value": chart.value,
             "chart_svg": svg, "chart_description": "Series \(index) \(chart.kind)"]
        }
        return ["agent": "agent-\(index)", "chat": "Chat \(index)", "revision": 1,
                "board": ["title": "Series \(index)", "widgets": widgets]]
    }
    desktop.receive(["page": "dashboard", "layout_only": true, "rows": rows])
    desktop.tabs.layoutSubtreeIfNeeded()
    let cards = descendants(desktop.dashboard.view, of: NSBox.self).sorted { $0.title < $1.title }
    require(cards.count == boards, "render every board in the cached reply")
    for (index, card) in cards.enumerated() {
        let charts = descendants(card, of: NSImageView.self)
        require(charts.count == (boards == 1 ? fixtureCharts.count : 1), "render every negotiated SVG")
        let count = min(widths.count, boards - (index / widths.count) * widths.count)
        let width = CGFloat(widths[count - 1])
        for chart in charts {
            require(chart.image!.size.width == width && abs(chart.bounds.width - card.contentView!.bounds.width) <= 1
                    && abs(chart.bounds.width - width) <= 4.5 && abs(chart.bounds.height - 90) <= 2,
                    "SVG at logical card width (\(count) across, negotiated \(width), native \(chart.bounds.size))")
        }
    }
}

func checkDashboardAppearance(_ desktop: Desktop, scroll: NSScrollView) {
    let window = desktop.window!
    let dashboard = desktop.dashboard
    let oldAppearance = window.appearance
    let oldAccent = dashboard.accentColor
    let wasVisible = window.isVisible
    let initialAppearance = window.effectiveAppearance.name.rawValue
    defer {
        window.orderOut(nil)
        dashboard.accentColor = oldAccent
        window.appearance = oldAppearance
        if wasVisible { window.orderFront(nil) }
    }
    func state(_ stage: String) -> String {
        let mode = CommandLine.arguments.contains("--dashboard") ? "--dashboard" : "full"
        return "\(stage) [\(mode), initial=\(initialAppearance), window=\(window.effectiveAppearance.name.rawValue), " +
            "dashboard=\(dashboard.view.effectiveAppearance.name.rawValue), tab=\(desktop.tabs.selectedTabViewItem?.label ?? "none"), " +
            "grid=\(scroll.documentView?.effectiveAppearance.name.rawValue ?? "none"), visible=\(window.isVisible), " +
            "attached=\(dashboard.view.window === window), hidden=\(dashboard.view.isHiddenOrHasHiddenAncestor)]"
    }
    func settle(_ stage: String, _ expected: NSAppearance.Name) {
        desktop.tabs.layoutSubtreeIfNeeded()
        window.displayIfNeeded()
        let selected = window.isVisible && desktop.tabs.selectedTabViewItem?.label == "Dashboard"
        let modes: [NSAppearance.Name] = [.aqua, .darkAqua]
        require(waitInMainRunLoop {
            window.effectiveAppearance.bestMatch(from: modes) == expected &&
                (!selected || (dashboard.view.window === window && dashboard.view.effectiveAppearance.bestMatch(from: modes) == expected))
        }, state(stage) + " did not adopt " + expected.rawValue)
        var drained = false
        DispatchQueue.main.async { drained = true }
        require(waitInMainRunLoop { drained }, state(stage) + " could not drain the main dispatch queue")
    }
    typealias Layout = (palette: [String: [Int]], widths: [Int])
    func readLayout(_ stage: String, _ expected: NSAppearance.Name, op: String, during action: () -> Void) -> Layout {
        let sent = requests(waitForOutput: true) { action(); settle(stage, expected) }
        guard sent.count == 1, case .json(let message) = sent[0], message.count == 3,
              message["op"] as? String == op, let palette = message["palette"] as? [String: [Int]],
              let widths = message["chart_widths"] as? [Int] else {
            fatalError(state(stage) + " expected one \(op) with a palette and chart widths, received \(sent)")
        }
        require(Set(palette.keys) == ["surface", "text", "secondary", "accent"] && palette.values.allSatisfy {
            $0.count == 3 && $0.allSatisfy { (0...255).contains($0) }
        }, state(stage) + " expected four local sRGB palette triples")
        require(widths.count == max(1, min(4, Int(scroll.contentSize.width / 280)))
                && widths.allSatisfy { (160...16384).contains($0) && $0.isMultiple(of: 8) },
                state(stage) + " unexpected logical chart widths \(widths)")
        return (palette, widths)
    }
    func expectNoRead(_ stage: String, _ expected: NSAppearance.Name, during action: () -> Void) {
        let sent = requests { action(); settle(stage, expected) }
        require(sent.isEmpty, state(stage) + " expected no reads, received \(sent)")
    }
    func publish(_ layout: Layout, cached: Bool = false) {
        let (palette, width) = (layout.palette, layout.widths[0])
        func rgb(_ role: String) -> String { "rgb(" + palette[role]!.map(String.init).joined(separator: ",") + ")" }
        let svg = """
        <svg xmlns="http://www.w3.org/2000/svg" width="\(width)" height="100" viewBox="0 0 \(width) 100">
        <rect x="8" width="4" height="100" fill="\(rgb("surface"))"/>
        <path d="M32 10 V78 H\(width - 10)" stroke="\(rgb("secondary"))" fill="none"/>
        <g font-family="sans-serif" font-size="8" fill="\(rgb("text"))">
        <text x="30" y="15" text-anchor="end">1.0</text><text x="30" y="77" text-anchor="end">0</text>
        <text x="32" y="91">1</text><text x="\(width - 14)" y="91">3</text></g>
        <path d="M32 17 C80 24 110 54 142 55 S210 60 \(width - 10) 66" stroke="\(rgb("accent"))" stroke-width="2" fill="none"/></svg>
        """
        let widgets: [[String: Any]] = [
            ["id": "job", "kind": "text", "label": "Status", "value": "Training"],
            ["id": "epochs", "kind": "progress", "label": "Epochs completed", "value": 72, "unit": "%"],
            ["id": "loss", "kind": "graph", "label": "Validation loss", "value": [0.9, 0.44, 0.18],
             "chart_svg": svg, "chart_description": "Validation loss decreased to 0.18"],
            ["id": "history", "kind": "events", "label": "History", "value": (1...20).map { "Epoch \($0) completed" }],
        ]
        let board: [String: Any] = ["agent": "trainer", "chat": "Research chat", "revision": 8,
                                    "board": ["title": "Training run", "widgets": widgets]]
        require(requests { desktop.receive(["page": "dashboard", "rows": [board], "layout_only": cached]) }.isEmpty,
                "repainting a snapshot performs no reads or actions")
        desktop.tabs.layoutSubtreeIfNeeded()
    }
    func inspect(_ layout: Layout, accent: NSColor) {
        let (palette, width) = (layout.palette, layout.widths[0])
        let card = descendants(dashboard.view, of: NSBox.self).first!
        let fields = descendants(card, of: NSTextField.self)
        func field(_ value: String) -> NSTextField { fields.first { $0.stringValue == value }! }
        let title = field("Training run"), publisher = field("Research chat")
        let titleRect = title.convert(title.bounds, to: card)
        require(card.titlePosition == .noTitle && card.cornerRadius >= 8 && card.borderWidth > 0
                && title.font!.pointSize == 18 && titleRect.minX >= 13 && card.bounds.maxY - titleRect.maxY >= 12
                && publisher.font!.pointSize < title.font!.pointSize && publisher.textColor == .secondaryLabelColor
                && NSFontManager.shared.weight(of: title.font!) > NSFontManager.shared.weight(of: publisher.font!)
                && NSFontManager.shared.weight(of: field("Status").font!) > NSFontManager.shared.weight(of: field("Training").font!),
                "board title and subdued publisher sit inside the rounded, padded card")
        card.effectiveAppearance.performAsCurrentDrawingAppearance {
            let surface = card.fillColor.usingColorSpace(.sRGB)!
            for (key, color) in [("surface", card.fillColor), ("text", title.textColor!),
                                 ("secondary", publisher.textColor!), ("accent", accent)] {
                let ink = color.usingColorSpace(.sRGB)!
                let channels = zip([ink.redComponent, ink.greenComponent, ink.blueComponent],
                                   [surface.redComponent, surface.greenComponent, surface.blueComponent])
                let expected = channels.map { Int((255 * ($1 + ink.alphaComponent * ($0 - $1))).rounded()) }
                require(palette[key] == expected, "sent \(key) matches native ink on the visible card surface")
            }
        }
        for (label, value) in [("Epochs completed", "72%"), ("Validation loss", "0.18")] {
            let name = field(label), reading = field(value)
            require(name.superview === reading.superview && abs(name.frame.midY - reading.frame.midY) <= 1
                    && name.frame.maxX <= reading.frame.minX && reading.alignment == .right,
                    "inline reading beside " + label)
        }
        let progress = descendants(card, of: NSProgressIndicator.self).first!
        require(!progress.isIndeterminate && progress.accessibilityLabel() == "Epochs completed"
                && progress.controlSize == .small && progress.bounds.height <= 12 && progress.doubleValue == 72,
                "compact native determinate progress")
        let chart = descendants(card, of: NSImageView.self).first!
        require(abs(chart.bounds.width - card.contentView!.bounds.width) <= 1
                && abs(chart.bounds.width - CGFloat(width)) <= 4.5
                && abs(chart.bounds.height - chart.bounds.width * 100 / CGFloat(width)) <= 1,
                "responsive chart at the negotiated width inside the card inset")
        // Rust paints on transparency. A patch of the negotiated surface should
        // disappear against the actual box, through the same display profile.
        let chartRect = chart.convert(chart.bounds, to: card)
        let pixels = card.bitmapImageRepForCachingDisplay(in: chartRect)!
        card.cacheDisplay(in: chartRect, to: pixels)
        func chartColor(_ x: Int) -> NSColor {
            pixels.colorAt(x: x * pixels.pixelsWide / width, y: pixels.pixelsHigh / 2)!.usingColorSpace(.sRGB)!
        }
        let patch = chartColor(10), background = chartColor(16)
        require((30...34).contains { abs(chartColor($0).greenComponent - background.greenComponent) > 0.15 },
                "axis visible on chart surface")
        require(patch.alphaComponent > 0.98 && background.alphaComponent > 0.98
                && max(abs(patch.redComponent - background.redComponent), abs(patch.greenComponent - background.greenComponent),
                       abs(patch.blueComponent - background.blueComponent)) < 0.025,
                "transparent chart matches negotiated surface, patch=\(patch), background=\(background)")
        let events = fields.first { $0.stringValue.hasPrefix("Epoch 1 completed") }!
        let style = events.attributedStringValue.attribute(.paragraphStyle, at: 0, effectiveRange: nil) as! NSParagraphStyle
        require(style.paragraphSpacing > 0 && style.paragraphSpacing <= 4, "compact selectable event entries")
    }

    // Establish Aqua off the Dashboard so launch appearance and pending color notifications
    // cannot turn the baseline into a second read. Selection issues the normal first request.
    _ = requests { desktop.tabs.selectTabViewItem(withIdentifier: "Chats") }
    expectNoRead("establish Aqua on Chats", .aqua) {
        window.appearance = NSAppearance(named: .aqua)!
        window.orderFront(nil)
        resizeDesktop(desktop, width: 766, height: 604)
    }
    let light = readLayout("select Dashboard in Aqua", .aqua, op: "dashboard") {
        desktop.tabs.selectTabViewItem(withIdentifier: "Dashboard")
    }
    publish(light)
    inspect(light, accent: .controlAccentColor)
    scroll.contentView.scroll(to: NSPoint(x: 0, y: 100))
    let position = scroll.documentVisibleRect.origin
    desktop.receive(["page": "dashboard", "error": "Dashboard refresh failed"])
    let notice = descendants(dashboard.view, of: NSTextField.self).first { $0.stringValue == "Dashboard refresh failed" }!
    let dark = readLayout("visible Aqua to Dark Aqua", .darkAqua, op: "dashboard_layout") {
        window.appearance = NSAppearance(named: .darkAqua)!
    }
    require(dark.palette["surface"] != light.palette["surface"] && dark.palette["text"] != light.palette["text"], "effective appearance changes palette")
    require(dark.widths == light.widths, "appearance change retains width buckets")
    publish(dark, cached: true)
    require(notice.stringValue == "Dashboard refresh failed" && !notice.isHiddenOrHasHiddenAncestor,
            "cached redraw preserves a refresh error")
    desktop.receive(["page": "dashboard", "notice": "Action sent"])
    desktop.receive(["page": "dashboard", "unchanged": true, "layout_only": true])
    require(notice.stringValue == "Action sent" && !notice.isHiddenOrHasHiddenAncestor,
            "unchanged cached layout preserves an action notice")
    desktop.receive(["page": "dashboard", "unchanged": true])
    require(notice.isHiddenOrHasHiddenAncestor, "successful data read clears the transient notice")
    inspect(dark, accent: .controlAccentColor)
    require(position.y > 0 && scroll.documentVisibleRect.origin == position, "chart recolor preserves scroll position")

    // Deliver the native system-color notification with a different accent in this fixture only.
    func notifyColors() { NotificationCenter.default.post(name: NSColor.systemColorsDidChangeNotification, object: nil) }
    let alternate = dark.palette["accent"] == [255, 0, 255]
        ? NSColor(srgbRed: 0, green: 1, blue: 0, alpha: 1) : NSColor(srgbRed: 1, green: 0, blue: 1, alpha: 1)
    dashboard.accentColor = { alternate }
    let recolored = readLayout("accent change in Dark Aqua", .darkAqua, op: "dashboard_layout") { notifyColors(); notifyColors() }
    require(recolored.palette["accent"] != dark.palette["accent"] && recolored.palette["surface"] == dark.palette["surface"], "accent-only change")
    publish(recolored, cached: true)
    inspect(recolored, accent: alternate)
    expectNoRead("unchanged accent in Dark Aqua", .darkAqua) { notifyColors() }
    let compact = readLayout("compact single column", .darkAqua, op: "dashboard_layout") {
        resizeDesktop(desktop, width: 510, height: 604)
    }
    checkNegotiatedChartSizes(desktop, widths: compact.widths, boards: 1)
    let compactResize = readLayout("coalesced single-column resize", .darkAqua, op: "dashboard_layout") {
        for width: CGFloat in [522, 536, 550] {
            resizeDesktop(desktop, width: width, height: 604)
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
        }
    }
    require(compactResize.widths.count == 1 && compactResize.widths[0] > compact.widths[0],
            "resize inside the compact breakpoint updates the SVG width")
    checkNegotiatedChartSizes(desktop, widths: compactResize.widths, boards: 1)
    expectNoRead("one-point resize within a width bucket", .darkAqua) {
        let chart = descendants(dashboard.view, of: NSImageView.self).first!
        let before = chart.bounds.width
        let step: CGFloat = before > CGFloat(compactResize.widths[0]) ? -1 : 1
        resizeDesktop(desktop, width: 550 + step, height: 604)
        require(abs(chart.bounds.width - before - step) < 0.5, "native chart follows the one-point resize")
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.2))
    }
    let large = readLayout("large single board", .darkAqua, op: "dashboard_layout") {
        resizeDesktop(desktop, width: 1192, height: 604)
    }
    checkNegotiatedChartSizes(desktop, widths: large.widths, boards: 1)
    let wider = readLayout("resize within four-column capacity", .darkAqua, op: "dashboard_layout") {
        resizeDesktop(desktop, width: 1240, height: 604)
    }
    require(wider.widths.count == 4 && large.widths.count == 4 && wider.widths[0] > large.widths[0]
            && wider.palette == compactResize.palette, "same-capacity resize changes only logical widths")
    expectNoRead("cached chart rows and height-only resize", .darkAqua) {
        for count in [1, 5, 6, 7] { checkNegotiatedChartSizes(desktop, widths: wider.widths, boards: count) }
        resizeDesktop(desktop, width: 1240, height: 620)
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.2))
    }
    _ = requests { desktop.tabs.selectTabViewItem(withIdentifier: "Chats") }
    expectNoRead("resize and change theme on Chats", .aqua) {
        resizeDesktop(desktop, width: 766, height: 604)
        window.appearance = NSAppearance(named: .aqua)!
        notifyColors()
    }
    let reselected = readLayout("reselect Dashboard in Aqua", .aqua, op: "dashboard") {
        desktop.tabs.selectTabViewItem(withIdentifier: "Dashboard")
    }
    require(reselected.palette["surface"] == light.palette["surface"] && reselected.palette["accent"] == recolored.palette["accent"]
            && reselected.widths == light.widths,
            state("reselect Dashboard in Aqua") + " did not send the current surface and accent")
    window.orderOut(nil)
    expectNoRead("hidden Aqua to Dark Aqua", .darkAqua) {
        window.appearance = NSAppearance(named: .darkAqua)!
        notifyColors()
    }
}

func checkDashboardVisibility(_ desktop: Desktop) {
    let view = desktop.dashboard.view
    let review = ["agent": "reviewer", "title": "Build", "chat": "Review"]
    let first = ["agent": "runner-1", "title": "Build", "chat": "Runner"]
    let second = ["agent": "runner-2", "title": "Build", "chat": "Runner"]
    func row(_ board: [String: String]) -> [String: Any] {
        ["agent": board["agent"]!, "chat": board["chat"]!, "revision": 8, "board": ["title": board["title"]!]]
    }
    func reply(_ fields: [String: Any]) {
        require(requests { desktop.receive(fields.merging(["page": "dashboard"]) { _, new in new }) }.isEmpty,
                "applying dashboard visibility sends no requests")
        desktop.tabs.layoutSubtreeIfNeeded()
    }
    func cards() -> [NSBox] { descendants(view, of: NSBox.self) }
    func restoreLink() -> NSButton? {
        descendants(view, of: NSButton.self).first { $0.title == "Restore hidden dashboards" && !$0.isHiddenOrHasHiddenAncestor }
    }
    func shows(_ message: String) -> Bool {
        descendants(view, of: NSTextField.self).contains { $0.stringValue == message && !$0.isHiddenOrHasHiddenAncestor }
    }
    let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
    let spec = repo.appendingPathComponent("crates/gent-link/src/desktop/dashboard-example.json")
    let example = try! JSONSerialization.jsonObject(with: Data(contentsOf: spec)) as! [String: Any]
    let empty: [String: Any] = ["rows": [], "hidden": [], "example": example]
    let free = empty.merging(["pro_required": true]) { _, new in new }
    resizeDesktop(desktop, width: 510, height: 400)
    reply(free)
    let sample = cards().first!
    require(cards().count == 1 && shows("Test run") && shows("Example dashboard") && shows("18 of 24")
            && descendants(sample, of: NSButton.self).isEmpty, "Free displays one labeled, read-only example")
    require(shows("Each registered chat on a Pro cluster can publish one dashboard. When the chat posts new results, Gent Desktop shows them across the cluster."), "example explains who publishes results and where updates appear")
    let progress = descendants(sample, of: NSProgressIndicator.self).first!
    require(progress.accessibilityLabel() == "Tests passed" && progress.doubleValue == 18 && progress.maxValue == 24,
            "example progress identifies the completed tests")
    let pricing = descendants(view, of: NSButton.self).first { $0.title == "View Gent plans" }!
    require(!pricing.isHiddenOrHasHiddenAncestor && shows("Dashboards require an active Gent Pro plan for this cluster."),
            "Free keeps the upgrade link and plan notice")
    let pasteboard = NSPasteboard.withUniqueName()
    defer { pasteboard.releaseGlobally() }
    let hasPasteboard = pasteboard.setString("fixture", forType: .string)
    require(desktop.window.screen == nil || hasPasteboard, "pasteboard available for windowed copy test")
    for prompt in ["Make a Gent dashboard for this test run. Show how many tests have passed and list any failures.",
                   "Update my dashboard after each test batch."] {
        let field = descendants(sample, of: NSTextField.self).first { $0.stringValue == prompt }!
        field.scrollToVisible(field.bounds)
        let clip = field.enclosingScrollView!.contentView
        let fitting = field.cell!.cellSize(forBounds: NSRect(x: 0, y: 0, width: field.bounds.width, height: 1000))
        require(field.isSelectable && !field.isEditable && field.bounds.height >= fitting.height - 1
                && clip.bounds.insetBy(dx: -1, dy: -1).contains(field.convert(field.bounds, to: clip)),
                "prompt wraps and scrolls into view at minimum window width")
        field.selectText(nil)
        guard let editor = field.currentEditor() as? NSTextView else { fatalError("Missing prompt selection") }
        editor.selectAll(nil)
        let selected = (editor.string as NSString).substring(with: editor.selectedRange())
        require(selected == prompt, "field editor selects the entire prompt")
        if hasPasteboard {
            // NSTextField's field editor advertises the legacy name for plain text.
            let nativeStringType = NSPasteboard.PasteboardType(rawValue: "NSStringPboardType")
            pasteboard.declareTypes([nativeStringType], owner: nil)
            require(editor.writeSelection(to: pasteboard, type: nativeStringType) && pasteboard.string(forType: .string) == prompt,
                    "selected prompt copies as plain text")
        }
        reply(free)
        require(cards().first === sample && field.currentEditor() === editor, "Free refresh preserves selection")
    }
    reply(empty)
    require(pricing.isHidden && cards().first === sample && shows("No chats have published a dashboard."),
            "empty Pro shows the same example without upgrade controls")
    reply(["error": "Daemon offline", "hidden": []])
    reply(["layout_only": true, "unchanged": true])
    require(cards().isEmpty && shows("Daemon offline"), "offline error survives resize and clears the example")
    reply(empty)
    require(cards().count == 1 && shows("Test run"), "a successful empty refresh restores the example")
    reply(["rows": [row(review)], "hidden": []])
    // Negotiate the current viewport before performClick services queued resize work.
    _ = requests { desktop.dashboard.load() }
    require(cards().count == 1 && !shows("Test run") && restoreLink() == nil, "published board replaces example")
    let card = cards()[0]
    guard let title = descendants(card, of: NSTextField.self).first(where: { $0.stringValue == "Build" }),
          let hide = descendants(card, of: NSButton.self).first(where: { $0.title == "×" }) else {
        fatalError("Missing dashboard header controls")
    }
    require(hide.toolTip == "Hide dashboard" && hide.accessibilityLabel() == "Hide dashboard" && hide.isEnabled
            && title.superview === hide.superview && title.frame.maxX <= hide.frame.minX
            && (16...28).contains(hide.bounds.width) && (16...28).contains(hide.bounds.height),
            "compact labeled hide action sits beside the card title")
    let hideRequests = requests { hide.performClick(nil) }
    require(hideRequests == [.json(["op": "dashboard_hide", "agent": "reviewer"])],
            "hide sends only the displayed agent, received \(hideRequests)")
    require(cards().first === card, "the displayed card waits for supervisor data after hide")
    reply(["rows": [], "hidden": [review]])
    require(cards().isEmpty && shows("All dashboards are hidden."), "hiding the last card shows the all-hidden state")
    guard let restore = restoreLink() else { fatalError("Missing restore link with all dashboards hidden") }
    require(restore.controlSize == .small && restore.accessibilityRole() == .link && restore.action != nil && restore.isEnabled
            && restore.menu?.items.map({ $0.title }) == ["Build — Review"], "even one hidden board is a named choice")

    reply(["layout_only": true, "rows": [], "hidden": []])
    require(restoreLink() == nil && shows("No chats have published a dashboard."), "cached data updates the empty state")
    reply(["unchanged": true, "hidden": [review, first, second]])
    guard let menu = restore.menu else { fatalError("Missing hidden dashboard choices") }
    let labels = menu.items.map { $0.title }
    require(Set(labels) == ["Build — Review", "Build — Runner (runner-1)", "Build — Runner (runner-2)"]
            && labels.count == 3, "restore choices distinguish identical titles and chat names")
    let intermediate: [[String: Any]] = [
        ["notice": "Action sent"], ["unchanged": true, "layout_only": true], ["error": "Refresh failed"],
        ["rows": [], "layout_only": true], ["rows": []], ["unchanged": true],
    ]
    for fields in intermediate {
        reply(fields)
        require(restoreLink()?.menu?.items.map({ $0.title }) == labels, "omitting hidden preserves restore choices")
    }
    require(shows("All dashboards are hidden."), "ordinary refresh restores the all-hidden notice")
    let selection = menu.indexOfItem(withTitle: "Build — Runner (runner-2)")
    let restoreRequests = requests { menu.performActionForItem(at: selection) }
    require(restoreRequests == [.json(["op": "dashboard_restore", "agent": "runner-2"])],
            "restore sends only the selected duplicate's agent, received \(restoreRequests)")
    require(cards().isEmpty, "restoring a card waits for supervisor data")
    reply(["rows": [row(second)], "hidden": [review, first]])
    require(cards().count == 1 && shows("Runner") && !shows("All dashboards are hidden.")
            && restoreLink()?.menu?.items.map({ $0.title }) == ["Build — Review", "Build — Runner"],
            "restored card returns and the menu lists the remaining publishers")
    reply(["unchanged": true, "hidden": []])
    require(cards().count == 1 && restoreLink() == nil, "an explicit empty hidden list removes the link")
    reply(["rows": [row(second)], "hidden": [first]])
    reply(["pro_required": true])
    require(cards().isEmpty && restoreLink() == nil && restore.menu == nil
            && shows("Dashboards require an active Gent Pro plan for this cluster."), "lock clears cards and restore choices")
    reply(["rows": []])
    require(restoreLink() == nil && shows("No chats have published a dashboard."), "unlock starts with an empty hidden list")
}

func checkDashboard(_ desktop: Desktop) {
    let initial = requests { DashboardTab().load() }
    guard case .json(let initialPage)? = initial.first else { fatalError("Missing initial dashboard read") }
    require(initial.count == 1 && initialPage["op"] as? String == "dashboard"
            && initialPage["chart_widths"] as? [Int] == [260], "unallocated dashboard requests the fallback width")
    desktop.tabs.selectTabViewItem(withIdentifier: "Dashboard")
    let view = desktop.dashboard.view
    guard let scroll = descendants(view, of: NSScrollView.self).first else {
        fatalError("Missing Dashboard scroll view")
    }
    var opened: [String] = []
    desktop.dashboard.openURL = { opened.append($0.absoluteString) }
    let targets = ["HtTp://localhost:8080/build?run=42#log", "HTTPS://192.168.1.1:8443/status?q=a%20b#result"]
    let retry = ["kind": "button", "id": "retry", "label": "Retry", "value": "Retry the fixture job"]

    func link(_ target: String, title: String, id: String = "link") -> [String: String] {
        ["kind": "link", "id": id, "label": title, "value": target]
    }
    func row(_ index: Int, widgets: [[String: Any]]) -> [String: Any] {
        ["agent": "agent-\(index)", "chat": "Chat \(index)", "revision": 10 + index,
         "board": ["title": "Board \(index)", "widgets": widgets]]
    }
    func publish(_ rows: [[String: Any]]) {
        require(requests { desktop.receive(["page": "dashboard", "rows": rows]) }.isEmpty,
                "rendering a dashboard sends no supervisor request")
        desktop.tabs.layoutSubtreeIfNeeded()
    }
    func cards() -> [NSBox] { descendants(view, of: NSBox.self).sorted { $0.title < $1.title } }
    let clip = scroll.contentView

    // Measure native frames through the production tab and its actual scroll viewport.
    @discardableResult
    func layout(_ width: CGFloat, _ height: CGFloat, rows: [Int], overflow: Bool = false, equalAreas: Bool = true) -> NSSize {
        resizeDesktop(desktop, width: width, height: height)
        let frames = cards().map { $0.convert($0.bounds, to: clip) }
        require(frames.count == rows.reduce(0, +), "all cards at \(width) × \(height)")
        var start = 0
        for count in rows {
            let line = frames[start..<start + count]
            let first = line.first!
            require(abs(first.minX - clip.bounds.minX) <= 1 && abs(line.last!.maxX - clip.bounds.maxX) <= 1,
                    "each row fills the available width at \(width)")
            require(line.allSatisfy { abs($0.width - first.width) <= 1 && abs($0.minY - first.minY) <= 1 && abs($0.height - first.height) <= 1 }
                    && zip(line, line.dropFirst()).allSatisfy { $0.maxX < $1.minX },
                    "cards share row width at \(width)")
            require(start == 0 || frames[start - 1].maxY < first.minY, "rows stack vertically")
            start += count
        }
        require(frames.allSatisfy { $0.height >= 159 }, "all cards preserve their minimum height")
        if equalAreas {
            let area = frames[0].width * frames[0].height
            require(frames.allSatisfy { abs($0.width * $0.height - area) <= area * 0.03 },
                    "cards share area within spacing and rounding at \(width) × \(height), rows \(rows)")
        }
        let document = scroll.documentView!
        let bounds = document.convert(document.bounds, to: clip)
        require(abs(frames[0].minY - bounds.minY) <= 1 && abs(frames.last!.maxY - bounds.maxY) <= 1,
                "cards fill the document vertically")
        require(overflow ? document.bounds.height > clip.bounds.height : abs(document.bounds.height - clip.bounds.height) <= 1,
                "document height at \(width) × \(height), overflow expected: \(overflow)")
        return frames[0].size
    }

    let rows = (1...6).map { row($0, widgets: [retry, link(targets[($0 - 1) % 2], title: "Build log")]) }
    publish([rows[0]])
    let single = layout(850, 605, rows: [1])
    let smaller = layout(510, 400, rows: [1])
    require(smaller.width < single.width && smaller.height < single.height, "single board follows both dimensions")
    publish(Array(rows.prefix(3)))
    layout(766, 604, rows: [2, 1])
    let wide = layout(810, 605, rows: [2, 1])
    require(layout(735, 605, rows: [2, 1]).width < wide.width, "cards resize within the same breakpoint")
    layout(810, 440, rows: [2, 1], equalAreas: false)
    layout(510, 400, rows: [1, 1, 1], overflow: true)
    layout(550, 720, rows: [1, 1, 1])
    publish(rows)
    layout(1000, 605, rows: [3, 3])
    layout(1240, 605, rows: [4, 2])
    publish(Array(rows.prefix(3)))
    layout(850, 605, rows: [2, 1])
    // The ordinary poll supersedes pending resize work before exercising clicks.
    let needsSnapshot = !desktop.pending
    let polled = requests {
        desktop.poll()
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.2))
    }
    // AppKit can give the first card an extra pixel to split an odd-width row.
    let nativeWidths = cards().map { $0.contentView!.bounds.width }
    let measured = [nativeWidths[2], (nativeWidths[0] + nativeWidths[1]) / 2].map { Int(($0 / 8).rounded()) * 8 }
    guard case .json(let page)? = polled.first else { fatalError("Missing dashboard poll") }
    require(page["op"] as? String == "dashboard" && page["palette"] is [String: [Int]]
            && page["chart_widths"] as? [Int] == measured && Array(polled.dropFirst()) == (needsSnapshot ? [snapshotRead] : []),
            "ordinary poll at clip \(scroll.contentView.bounds.size), expected measured widths \(measured) " +
            "and snapshot=\(needsSnapshot), received \(polled)")
    if needsSnapshot { desktop.receive(["enrolled": false, "state": "Unavailable"]) }
    require(opened.isEmpty, "render, refresh and resize never open links")

    for (card, target) in zip(cards(), targets) {
        guard let link = descendants(card, of: NSButton.self).first(where: { $0.title == "Build log" }) else {
            fatalError("Missing published link")
        }
        require(link.toolTip == target && link.isEnabled && link.accessibilityRole() == .link,
                "accessible link shows its destination")
        require(requests { link.performClick(nil) }.isEmpty, "link click sends no chat callback")
    }
    require(opened == targets, "each click opens its exact HTTP or HTTPS destination once")

    guard let button = descendants(cards()[1], of: NSButton.self).first(where: { $0.title == "Retry" }) else {
        fatalError("Missing published Dashboard button")
    }
    require(requests { button.performClick(nil) } == [.json(["op": "dashboard_click", "agent": "agent-2",
                                                              "revision": 12, "widget": "retry"])],
            "ordinary button sends one callback for the displayed chat, revision and widget")
    let invalid = ["file:///tmp/report", "javascript:alert(1)", "mailto:user@example.org", "/relative", "//host/path",
                   "https:host", "http:///path", "https://:80", "https://", "https://host/a b", "http://host/\t",
                   "https://[::1", "https://host:65536", "http://host:18446744073709552030",
                   "https://host/\u{7f}", "https://host/\u{a0}", "https://host\\path"]
    publish([row(1, widgets: invalid.enumerated().map { link($0.element, title: "Invalid \($0.offset)", id: "bad-\($0.offset)") })])
    require(descendants(cards()[0], of: NSButton.self).map { $0.title } == ["×"], "invalid links expose no launch action")

    let entries = (1...40).map { "Event \($0)" }
    let events: [String: Any] = ["kind": "events", "id": "events", "label": "History", "value": entries]
    publish([row(1, widgets: [events, link(targets[0], title: "Last link")])])
    layout(510, 400, rows: [1], overflow: true)
    let card = cards()[0]
    let field = descendants(card, of: NSTextField.self).first { $0.stringValue == entries.joined(separator: "\n") }!
    require(field.bounds.height >= CGFloat(entries.count) * (field.font?.pointSize ?? 13), "tall contents stay readable")
    let last = descendants(card, of: NSButton.self).first { $0.title == "Last link" }!
    require(!clip.bounds.contains(last.convert(last.bounds, to: clip)), "last link starts below viewport")
    last.scrollToVisible(last.bounds)
    require(clip.bounds.contains(last.convert(last.bounds, to: clip)), "last link reachable by vertical scrolling")
    let message = String(repeating: "A dashboard message with wrapping text. ", count: 49)
    let paragraph = ["kind": "text", "id": "message", "label": "Message", "value": message]
    publish([rows[0], rows[1], row(3, widgets: [paragraph])])
    layout(810, 400, rows: [2, 1], overflow: true, equalAreas: false)
    let wrapped = descendants(cards()[2], of: NSTextField.self).first { $0.stringValue == message }!
    let fitting = wrapped.cell!.cellSize(forBounds: NSRect(x: 0, y: 0, width: wrapped.bounds.width,
                                                            height: CGFloat.greatestFiniteMagnitude))
    require(fitting.height > 160 && wrapped.bounds.height >= fitting.height - 1,
            "wrapped text gets its natural height in a partial row")
    checkDashboardMedia(desktop, scroll: scroll)
    checkDashboardVisibility(desktop)
    checkDashboardAppearance(desktop, scroll: scroll)
    require(opened == targets, "button, malformed links, media and scrolling leave opener idle")
    resizeDesktop(desktop, width: 850, height: 605)
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let desktop = Desktop(iconPath: CommandLine.arguments[1], openAtLaunch: false)
if CommandLine.arguments.dropFirst(2).contains("--settings") {
    desktop.makeWindow()
    checkReleaseChannel(desktop)
    print("PASS: native release channel settings")
    exit(0)
}
if CommandLine.arguments.dropFirst(2).contains(where: { ["--cluster", "--nodes"].contains($0) }) {
    desktop.makeWindow()
    checkCluster(desktop) { desktop.show() }
    print("PASS: native Status tab, setup, node search, guarded actions, rename dialogs and refresh requests")
    exit(0)
}
var permissionChecks = 0
desktop.prepareNotifications = { permissionChecks += 1 }
let dashboardOnly = CommandLine.arguments.dropFirst(2).contains("--dashboard")
checkOrdinaryRecovery()
if CommandLine.arguments.dropFirst(2).contains("--ordinary-recovery") {
    print("PASS: independent ordinary chat and goal recovery preferences")
    exit(0)
}
let lifetime = Pipe()
if dashboardOnly {
    // A screenless SSH session can construct the native window without a tray.
    desktop.makeWindow()
} else {
    app.delegate = desktop
    // The pipe stays open so the UI has the same lifetime as a normal Gent child.
    dup2(lifetime.fileHandleForReading.fileDescriptor, STDIN_FILENO)
}
// Run from an AppKit run-loop timer. A nested run loop inside DispatchQueue.main
// cannot service the dashboard's coalesced refresh on that same serial queue.
Timer.scheduledTimer(withTimeInterval: 0.8, repeats: false) { _ in
    if dashboardOnly {
        desktop.window.orderFront(nil)
        checkDashboard(desktop)
        print("PASS: native Dashboard layout, scrolling, hide and restore, web links, button dispatch, SVG charts, metrics, inline images, negotiated widths, appearance palettes and cached redraws")
        exit(0)
    }
    require(desktop.statusItem?.isVisible == true && desktop.statusItem?.button?.image != nil,
            "visible menu-bar item and image in a logged-in Aqua session")
    require(!desktop.window.isVisible, "starts in tray")
    require(permissionChecks == 1, "tray launch checks notification permission before any notice")
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
    let chats = desktop.chats
    let ranked = [("z", "Zulu"), ("m", "Mike"), ("a", "Alpha")].map { id, name in
        ["id": id, "name": name, "node": id == "m" ? "Other" : "West",
         "provider": "codex", "state": "Registered"]
    }
    desktop.receive(["page": "chats", "rows": ranked])
    require((0..<3).map { cell(chats.table, "id", row: $0) } == ["z", "m", "a"],
            "Chats preserves the supervisor's nonalphabetical message order")
    chats.table.selectRowIndexes(IndexSet(integer: 2), byExtendingSelection: false)
    chats.search.stringValue = "West"
    chats.controlTextDidChange(Notification(name: NSControl.textDidChangeNotification))
    require(chats.table.numberOfRows == 2 && cell(chats.table, "id", row: 0) == "z" &&
            cell(chats.table, "id", row: 1) == "a" && chats.table.selectedRow == 1,
            "filtered Chats keeps the original order and selection")
    desktop.receive(["page": "chats", "rows": Array(ranked.reversed())])
    require(cell(chats.table, "id", row: 0) == "a" && chats.table.selectedRow == 0,
            "selected chat follows its ID after recent-message order changes")
    checkReleaseChannel(desktop)
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
    desktop.tabs.selectTabViewItem(withIdentifier: "Status")
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
    FileHandle.standardError.write(Data("PASS: AppKit menu bar, Status tab, setup, daemon controls, node search and actions, Dashboard layout, scrolling, web links and button dispatch, directories, editable settings, account confirmation, permissions, about, update check, close, reopen and quit\n".utf8))
    _ = app.sendAction(stop, to: quit.target, from: quit)
}
app.run()
