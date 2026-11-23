import AppKit

// Keep all AppKit updates on the main thread. Gent writes a JSON object per line.
final class Desktop: NSObject, NSApplicationDelegate, NSWindowDelegate, NSTabViewDelegate, NSTableViewDataSource, NSTableViewDelegate {
    let tabs = NSTabView()
    let chats = DirectoryTab(page: "chats")
    let nodes = DirectoryTab(page: "nodes")
    let settings = SettingsTab()
    let clusterPage = ManagementTab(page: "cluster")
    let permissions = ManagementTab(page: "permissions")
    lazy var about = ManagementTab(page: "about", icon: icon)
    let setupAtLaunch: Bool
    let icon: NSImage?
    let openAtLaunch: Bool
    var statusItem: NSStatusItem!
    let trayState = NSMenuItem(title: "Checking daemon…", action: nil, keyEquivalent: "")
    var lastRead = Date.distantPast
    var window: NSWindow!
    let node = NSTextField(labelWithString: "Gent")
    let cluster = NSTextField(labelWithString: "")
    let state = NSTextField(labelWithString: "Connecting…")
    let empty = NSTextField(labelWithString: "Waiting for daemon status…")
    let connection = NSTextField(labelWithString: "")
    let errorMessage = NSTextField(wrappingLabelWithString: "")
    let table = NSTableView()
    let scroll = NSScrollView()
    let refresh = NSButton(title: "Refresh", target: nil, action: nil)
    let toggle = NSButton(title: "Start daemon", target: nil, action: nil)
    let restart = NSButton(title: "Restart", target: nil, action: nil)
    var metrics: [String: NSTextField] = [:]
    var peers: [[String: Any]] = []
    var running = false
    var canStart = false
    var canStop = false
    var pending = false

    init(iconPath: String, openAtLaunch: Bool, setup: Bool = false) {
        self.icon = NSImage(contentsOfFile: iconPath)
        self.openAtLaunch = openAtLaunch
        self.setupAtLaunch = setup
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let image = icon?.copy() as? NSImage {
            image.size = NSSize(width: 20, height: 20)
            statusItem.button?.image = image
        } else {
            statusItem.button?.title = "G"
        }
        statusItem.button?.toolTip = "Gent Desktop"
        let menu = NSMenu()
        menu.addItem(trayState)
        menu.addItem(.separator())
        menu.addItem(withTitle: "Open Gent Desktop", action: #selector(show), keyEquivalent: "").target = self
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit Gent Desktop", action: #selector(quit), keyEquivalent: "q").target = self
        menu.insertItem(withTitle: "Settings…", action: #selector(showSettings), keyEquivalent: ",", at: 3).target = self
        statusItem.menu = menu
        let main = NSMenu()
        let edit = NSMenu(title: "Edit")
        for (title, action, key) in [("Undo","undo:","z"), ("Cut","cut:","x"), ("Copy","copy:","c"),
                                     ("Paste","paste:","v"), ("Select All","selectAll:","a")] {
            edit.addItem(withTitle: title, action: Selector(action), keyEquivalent: key)
        }
        let application = NSMenu(title: "Gent Desktop")
        application.addItem(withTitle: "Settings…", action: #selector(showSettings), keyEquivalent: ",").target = self
        application.addItem(withTitle: "Quit Gent Desktop", action: #selector(quit), keyEquivalent: "q").target = self
        for submenu in [application, edit] {
            let item = NSMenuItem()
            main.addItem(item)
            item.submenu = submenu
        }
        NSApp.mainMenu = main
        makeWindow()
        if setupAtLaunch { tabs.selectTabViewItem(withIdentifier: "Cluster") }
        if openAtLaunch { show() } else { request("refresh") }

        Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            if let self = self, self.window.isVisible || Date().timeIntervalSince(self.lastRead) >= 60 { self.request("refresh") }
        }
        DispatchQueue.global(qos: .userInitiated).async {
            while let line = readLine() {
                guard let data = line.data(using: .utf8),
                      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
                DispatchQueue.main.async { self.receive(object) }
            }
            DispatchQueue.main.async { self.quit() }
        }
    }

    @objc func show() {
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        loadTab(tabs.selectedTabViewItem)
    }

    func loadTab(_ item: NSTabViewItem?) {
        switch item?.identifier as? String {
        case "Cluster": clusterPage.load()
        case "Permissions": permissions.load()
        case "About": about.load()
        case "Chats": chats.load()
        case "Nodes": nodes.load()
        case "Settings": settings.load()
        default: request("refresh")
        }
    }

    func tabView(_ tabView: NSTabView, didSelect tabViewItem: NSTabViewItem?) {
        loadTab(tabViewItem)
    }

    @objc func showSettings() {
        tabs.selectTabViewItem(withIdentifier: "Settings")
        show()
    }

    @objc func quit() { NSApp.terminate(nil) }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    func stack(_ views: [NSView], vertical: Bool = false, spacing: CGFloat = 8) -> NSStackView {
        let result = NSStackView(views: views)
        result.orientation = vertical ? .vertical : .horizontal
        result.alignment = vertical ? .leading : .centerY
        result.spacing = spacing
        return result
    }

    func makeWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 850, height: 605),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Gent Desktop"
        window.minSize = NSSize(width: 510, height: 400)
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.center()
        let content = NSView()
        for (title, child) in [("Status", content), ("Chats", chats.view), ("Nodes", nodes.view), ("Settings", settings.view), ("Cluster", clusterPage.view), ("Permissions", permissions.view), ("About", about.view)] {
            let tab = NSTabViewItem(identifier: title)
            tab.label = title
            tab.view = child
            tabs.addTabViewItem(tab)
        }
        tabs.delegate = self
        window.contentView = tabs
        let image = NSImageView()
        image.image = icon
        image.imageScaling = .scaleProportionallyUpOrDown
        image.widthAnchor.constraint(equalToConstant: 46).isActive = true
        image.heightAnchor.constraint(equalToConstant: 46).isActive = true
        node.font = .systemFont(ofSize: 23, weight: .semibold)
        cluster.textColor = .secondaryLabelColor
        state.font = .systemFont(ofSize: 13, weight: .semibold)
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let identity = stack([image, stack([node, cluster], vertical: true, spacing: 2), spacer, state])
        let divider = NSBox()
        divider.boxType = .separator
        var columns: [NSView] = []
        for (key, name) in [("sync", "Sync"), ("queue", "Queued"), ("chats", "Known chats")] {
            let title = NSTextField(labelWithString: name)
            title.textColor = .secondaryLabelColor
            let value = NSTextField(labelWithString: "—")
            value.font = .systemFont(ofSize: 19, weight: .semibold)
            metrics[key] = value
            columns.append(stack([title, value], vertical: true, spacing: 2))
        }
        let stats = stack(columns)
        stats.distribution = .fillEqually
        for (key, title, width) in [("name", "Peer", 180), ("state", "Directory", 110), ("route", "Last transport", 145)] {
            let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(key))
            col.title = title
            col.width = CGFloat(width)
            table.addTableColumn(col)
        }
        table.dataSource = self
        table.delegate = self
        table.usesAlternatingRowBackgroundColors = true
        table.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.borderType = .bezelBorder
        empty.textColor = .secondaryLabelColor
        let area = NSView()
        for view in [scroll, empty] as [NSView] {
            area.addSubview(view)
            view.translatesAutoresizingMaskIntoConstraints = false
        }
        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: area.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: area.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: area.topAnchor), scroll.bottomAnchor.constraint(equalTo: area.bottomAnchor),
            empty.centerXAnchor.constraint(equalTo: area.centerXAnchor), empty.centerYAnchor.constraint(equalTo: area.centerYAnchor),
        ])
        scroll.isHidden = true
        errorMessage.textColor = .systemRed
        errorMessage.isHidden = true
        let actions = stack([toggle, restart, NSView(), refresh])
        for b in [refresh, toggle, restart] { b.target = self; b.action = #selector(clicked(_:)); b.bezelStyle = .rounded }
        connection.textColor = .secondaryLabelColor
        let body = stack([identity, divider, stats, area, connection, errorMessage, actions], vertical: true, spacing: 14)
        content.addSubview(body)
        body.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            body.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            body.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            body.topAnchor.constraint(equalTo: content.topAnchor, constant: 18),
            body.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -18),
        ])
        for view in [identity, divider, stats, area, connection, errorMessage, actions] as [NSView] {
            view.widthAnchor.constraint(equalTo: body.widthAnchor).isActive = true
        }
        area.setContentHuggingPriority(.defaultLow, for: .vertical)
        buttons()
    }

    func numberOfRows(in tableView: NSTableView) -> Int { peers.count }
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let col = tableColumn else { return nil }
        let cell = tableView.makeView(withIdentifier: col.identifier, owner: nil) as? NSTextField ?? NSTextField(labelWithString: "")
        cell.identifier = col.identifier
        let key = col.identifier.rawValue
        let text = peers[row][key] as? String ?? "—"
        cell.stringValue = key == "state" ? text.capitalized : text
        cell.lineBreakMode = .byTruncatingTail
        return cell
    }

    @objc func clicked(_ sender: NSButton) {
        if sender === toggle { request(canStop ? "stop" : "start") }
        else if sender === restart { request("restart") }
        else { request("refresh") }
    }

    func buttons() {
        refresh.isEnabled = !pending
        toggle.isEnabled = !pending && (canStart || canStop)
        toggle.title = (running || canStop) ? "Stop daemon" : "Start daemon"
        restart.isEnabled = !pending && canStop
    }

    func request(_ action: String) {
        guard !pending else { return }
        pending = true
        buttons()
        FileHandle.standardOutput.write(Data((action + "\n").utf8))
    }

    func receive(_ m: [String: Any]) {
        switch m["page"] as? String {
        case "cluster": clusterPage.receive(m); return
        case "permissions": permissions.receive(m); return
        case "about": about.receive(m); return
        case "chats": chats.receive(m); return
        case "nodes": nodes.receive(m); return
        case "settings": settings.receive(m); return
        default: break
        }
        if m["show"] as? Bool == true { show(); return }
        if m["quit"] as? Bool == true { quit(); return }
        pending = false
        lastRead = Date()
        errorMessage.stringValue = m["error"] as? String ?? ""
        errorMessage.isHidden = errorMessage.stringValue.isEmpty
        if errorMessage.isHidden {
            node.stringValue = m["node"] as? String ?? "Gent"
            cluster.stringValue = m["cluster"] as? String ?? "Local daemon"
            state.stringValue = m["state"] as? String ?? "Unavailable"
            trayState.title = "Daemon " + state.stringValue.lowercased()
            for (key, field) in metrics {
                if let n = m[key] as? NSNumber { field.stringValue = n.stringValue }
                else { field.stringValue = (m[key] as? String)?.capitalized ?? "—" }
            }
            connection.stringValue = m["connection"] as? String ?? ""
            peers = m["peers"] as? [[String: Any]] ?? []
            table.reloadData()
            scroll.isHidden = peers.isEmpty
            empty.isHidden = !peers.isEmpty
            empty.stringValue = m["running"] as? Bool == true ? "No peers in the directory." :
                (state.stringValue == "Stopped" ? "The daemon is stopped." : "Daemon status is unavailable.")
            running = m["running"] as? Bool ?? false
            canStart = m["can_start"] as? Bool ?? false
            canStop = m["can_stop"] as? Bool ?? false
        }
        buttons()
    }
}
