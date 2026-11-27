import AppKit

final class FlippedDocument: NSView {
    override var isFlipped: Bool { true }
}

// Keep all AppKit updates on the main thread. Gent writes a JSON object per line.
final class Desktop: NSObject, NSApplicationDelegate, NSWindowDelegate, NSTabViewDelegate {
    let tabs = NSTabView()
    let chats = DirectoryTab(page: "chats")
    let nodes = DirectoryTab(page: "nodes")
    let settings = SettingsTab()
    let dashboard = DashboardTab()
    let account = AccountSection()
    let permissions = ManagementTab(page: "permissions")
    lazy var about = ManagementTab(page: "about", icon: aboutLogo)
    let aboutLogo: NSImage?
    let trayIcon: NSImage?
    var prepareNotifications: (() -> Void)?
    var deliverNotification: (([String: Any]) -> Void)?
    let openAtLaunch: Bool
    let setupAtLaunch: Bool
    var statusItem: NSStatusItem!
    let trayState = NSMenuItem(title: "Checking daemon…", action: nil, keyEquivalent: "")
    var lastRead = Date.distantPast
    var window: NSWindow!
    private var enrolledViewportHeight: NSLayoutConstraint?
    private let identity = NSStackView()
    let node = NSTextField(labelWithString: "Gent")
    let cluster = NSTextField(labelWithString: "")
    let state = NSTextField(labelWithString: "Connecting…")
    let health = NSView()
    let connection = NSTextField(wrappingLabelWithString: "")
    let errorMessage = NSTextField(wrappingLabelWithString: "")
    let refresh = NSButton(title: "Refresh", target: nil, action: nil)
    let toggle = NSButton(title: "Start daemon", target: nil, action: nil)
    let restart = NSButton(title: "Restart", target: nil, action: nil)
    var metrics: [String: NSTextField] = [:]
    var running = false
    var canStart = false
    var canStop = false
    var pending = false
    private var refreshAfterPending = false

    init(iconPath: String, openAtLaunch: Bool, setupAtLaunch: Bool = false) {
        self.aboutLogo = NSImage(contentsOf: URL(fileURLWithPath: iconPath)
            .deletingLastPathComponent().appendingPathComponent("inkling.svg"))
        self.aboutLogo?.cacheMode = .never
        self.trayIcon = NSImage(contentsOf: URL(fileURLWithPath: iconPath)
            .deletingLastPathComponent().appendingPathComponent("inkling-tray-128.png"))
        self.openAtLaunch = openAtLaunch
        self.setupAtLaunch = setupAtLaunch
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let image = trayIcon {
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
        if openAtLaunch { present(destination: setupAtLaunch ? "Status" : nil) } else { request("refresh") }
        prepareNotifications?()

        Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            self?.poll()
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

    func poll() {
        if window.isVisible && tabs.selectedTabViewItem?.label == "Settings" { settings.pollChannel() }
        if window.isVisible && tabs.selectedTabViewItem?.label == "Dashboard" { dashboard.load() }
        if window.isVisible || Date().timeIntervalSince(lastRead) >= 60 { request("refresh") }
    }

    @objc func show() { present(destination: nil) }

    func present(destination: String?) {
        let target = destination ?? (window.isVisible && !NSApp.isHidden ? nil : "Dashboard")
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        if let target = target, tabs.selectedTabViewItem?.label != target {
            tabs.selectTabViewItem(withIdentifier: target)
        } else {
            loadTab(tabs.selectedTabViewItem)
        }
        request("refresh")
    }

    func loadTab(_ item: NSTabViewItem?) {
        switch item?.identifier as? String {
        case "Dashboard": dashboard.load()
        case "Status": refreshCluster()
        case "Permissions": permissions.load()
        case "About": about.load()
        case "Chats": chats.loadChats()
        case "Settings": settings.load()
        default: request("refresh")
        }
    }

    func tabView(_ tabView: NSTabView, didSelect tabViewItem: NSTabViewItem?) {
        loadTab(tabViewItem)
    }

    @objc func showSettings() {
        present(destination: "Settings")
    }

    @objc func quit() { NSApp.terminate(nil) }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        reopen()
        return false
    }

    private func reopen() {
        guard let window else { return }
        if window.isMiniaturized { window.deminiaturize(nil) }
        show()
        if NSApp.isHidden { NSApp.unhide(nil) }
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
        let content = NSScrollView()
        for (title, child) in [("Dashboard", dashboard.view), ("Status", content), ("Chats", chats.view), ("Settings", settings.view), ("Permissions", permissions.view), ("About", about.view)] {
            let tab = NSTabViewItem(identifier: title)
            tab.label = title
            tab.view = child
            tabs.addTabViewItem(tab)
        }
        tabs.delegate = self
        window.contentView = tabs
        let document = FlippedDocument()
        content.hasVerticalScroller = true
        content.drawsBackground = false
        content.documentView = document
        document.translatesAutoresizingMaskIntoConstraints = false
        let clip = content.contentView
        let viewportHeight = document.heightAnchor.constraint(equalTo: clip.heightAnchor)
        // Let the window keep its requested size before stretching the member table.
        viewportHeight.priority = NSLayoutConstraint.Priority(490)
        enrolledViewportHeight = viewportHeight
        NSLayoutConstraint.activate([
            document.leadingAnchor.constraint(equalTo: clip.leadingAnchor),
            document.topAnchor.constraint(equalTo: clip.topAnchor),
            document.widthAnchor.constraint(equalTo: clip.widthAnchor),
        ])

        cluster.font = .systemFont(ofSize: 21, weight: .semibold)
        node.textColor = .secondaryLabelColor
        state.font = .boldSystemFont(ofSize: NSFont.systemFontSize)
        identity.addArrangedSubview(cluster)
        identity.addArrangedSubview(node)
        identity.orientation = .vertical
        identity.alignment = .leading
        let controls = NSStackView(views: [state, NSView(), toggle, restart])
        for button in [refresh, toggle, restart] {
            button.target = self
            button.action = #selector(clicked(_:))
            button.bezelStyle = .rounded
        }
        let stats = NSStackView()
        stats.distribution = .fillEqually
        for (key, name) in [("sync", "Sync"), ("queue", "Queued"), ("chats", "Known chats")] {
            let caption = NSTextField(labelWithString: name)
            caption.textColor = .secondaryLabelColor
            let value = NSTextField(labelWithString: "—")
            value.font = .systemFont(ofSize: 16, weight: .medium)
            metrics[key] = value
            let metric = column([caption, value])
            metric.spacing = 2
            stats.addArrangedSubview(metric)
        }
        connection.textColor = .secondaryLabelColor
        pin(column([controls, stats, connection]), in: health)

        let header = NSStackView(views: [identity, NSView(), refresh])
        identity.spacing = 2
        identity.isHidden = true
        health.isHidden = true
        nodes.view.isHidden = true
        errorMessage.textColor = .systemRed
        errorMessage.isHidden = true
        let body = column([header, errorMessage, health, nodes.view, account.view])
        body.distribution = .fill
        body.spacing = 14
        pin(body, in: document, inset: 16)
        buttons()
    }

    @objc func clicked(_ sender: NSButton) {
        if sender === toggle { request(canStop ? "stop" : "start") }
        else if sender === restart { request("restart") }
        else { refreshCluster() }
    }

    private func refreshCluster() {
        request("refresh")
        account.load()
    }

    private func refreshAfterOperation() {
        // An in-flight status or daemon command may have sampled the directory before the edit.
        if pending { refreshAfterPending = true }
        else { request("refresh") }
    }

    func buttons() {
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
        if let banner = m["notification"] as? [String: Any] {
            deliverNotification?(banner)
            return
        }
        switch m["page"] as? String {
        case "cluster":
            account.receive(m)
            if m["operation"] as? Bool == true && m["error"] == nil { refreshAfterOperation() }
            return
        case "permissions": permissions.receive(m); return
        case "dashboard": dashboard.receive(m); return
        case "about": about.receive(m); return
        case "chats": chats.receive(m); return
        case "nodes":
            if m["operation"] as? Bool == true {
                nodes.actions.completed(m)
                if m["error"] == nil { refreshAfterOperation() }
            }
            return
        case "settings": settings.receive(m); return
        case "release_channel": settings.channel.receive(m); return
        default: break
        }
        if m["show"] as? Bool == true { reopen(); return }
        if m["quit"] as? Bool == true { quit(); return }
        pending = false
        lastRead = Date()
        errorMessage.stringValue = m["error"] as? String ?? ""
        errorMessage.isHidden = errorMessage.stringValue.isEmpty
        if errorMessage.isHidden {
            let enrolled = m["enrolled"] as? Bool == true
            identity.isHidden = !enrolled
            health.isHidden = !enrolled
            nodes.view.isHidden = !enrolled
            enrolledViewportHeight?.isActive = enrolled
            node.stringValue = "Local node: " + (m["node"] as? String ?? "—")
            cluster.stringValue = m["cluster"] as? String ?? "Cluster"
            let daemonState = m["state"] as? String ?? "Unavailable"
            state.stringValue = "Daemon " + daemonState.lowercased()
            trayState.title = state.stringValue
            for (key, field) in metrics {
                if let n = m[key] as? NSNumber { field.stringValue = n.stringValue }
                else { field.stringValue = (m[key] as? String)?.capitalized ?? "—" }
            }
            connection.stringValue = m["connection"] as? String ?? ""
            connection.isHidden = connection.stringValue.isEmpty
            nodes.display(m["nodes"] as? [String: Any] ?? [:])
            running = m["running"] as? Bool ?? false
            canStart = m["can_start"] as? Bool ?? false
            canStop = m["can_stop"] as? Bool ?? false
        }
        if refreshAfterPending {
            refreshAfterPending = false
            request("refresh")
        } else {
            buttons()
        }
    }
}
