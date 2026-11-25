import AppKit

// The supervisor handles these requests locally. Configuration text travels only over stdin/stdout.
func sendPage(_ op: String, _ fields: [String: Any] = [:]) {
    var object = fields
    object["op"] = op
    guard var bytes = try? JSONSerialization.data(withJSONObject: object) else { return }
    bytes.append(10)
    FileHandle.standardOutput.write(bytes)
}

func pin(_ child: NSView, in parent: NSView, inset: CGFloat = 0) {
    parent.addSubview(child)
    child.translatesAutoresizingMaskIntoConstraints = false
    NSLayoutConstraint.activate([
        child.topAnchor.constraint(equalTo: parent.topAnchor, constant: inset),
        child.bottomAnchor.constraint(equalTo: parent.bottomAnchor, constant: -inset),
        child.leadingAnchor.constraint(equalTo: parent.leadingAnchor, constant: inset),
        child.trailingAnchor.constraint(equalTo: parent.trailingAnchor, constant: -inset),
    ])
}

func column(_ children: [NSView]) -> NSStackView {
    let stack = NSStackView(views: children)
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 9
    for child in children {
        child.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
    }
    return stack
}

private final class NodeActionScrollView: NSScrollView {
    private var rowHeight: NSLayoutConstraint?

    init(row: NSStackView) {
        super.init(frame: .zero)
        drawsBackground = false
        hasHorizontalScroller = true
        autohidesScrollers = true
        documentView = row
        row.translatesAutoresizingMaskIntoConstraints = false
        rowHeight = heightAnchor.constraint(equalTo: row.heightAnchor)
        rowHeight?.isActive = true
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            row.topAnchor.constraint(equalTo: contentView.topAnchor),
        ])
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func layout() {
        super.layout()
        guard let row = documentView, let rowHeight = rowHeight else { return }
        let overflow = row.fittingSize.width > bounds.width
        let gutter = NSScrollView.frameSize(forContentSize: .zero,
                                            horizontalScrollerClass: overflow ? NSScroller.self : nil,
                                            verticalScrollerClass: nil, borderType: .noBorder,
                                            controlSize: .regular, scrollerStyle: scrollerStyle).height
        if rowHeight.constant != gutter { rowHeight.constant = gutter }
    }
}

final class DirectoryTab: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate {
    let view = NSView()
    let table = NSTableView()
    let search = NSSearchField()
    let status = NSTextField(labelWithString: "")
    let actions = ActionBar()
    let page: String
    let columns: [(String, String, CGFloat)]
    var rows: [[String: Any]] = []
    private var filtered: [[String: Any]] = []
    private var readError: String?
    private var loading = false

    init(page: String) {
        self.page = page
        let members = page == "nodes"
        columns = page == "chats"
            ? [("name", "Chat", 185), ("node", "Node", 120), ("provider", "Provider", 95),
               ("state", "Registration", 100), ("id", "Chat ID", 270)]
            : [("name", "Node", 150), ("state", "Status", 100), ("role", "Role", 70),
               ("directory", "Directory", 110), ("route", "Last transport", 135),
               ("host", "Hosted by", 120), ("id", "Node ID", 270)]
        super.init()
        search.placeholderString = "Filter " + page
        search.delegate = self
        for (key, title, width) in columns {
            let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(key))
            col.title = title
            col.width = width
            table.addTableColumn(col)
        }
        table.dataSource = self
        table.delegate = self
        table.usesAlternatingRowBackgroundColors = true
        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.borderType = .bezelBorder
        let bar: NSStackView
        let actionRow: NSView
        if members {
            let title = NSTextField(labelWithString: "Nodes")
            title.font = .systemFont(ofSize: 18, weight: .semibold)
            bar = NSStackView(views: [title, search])
            table.columnAutoresizingStyle = .noColumnAutoresizing
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 160).isActive = true

            actionRow = NodeActionScrollView(row: actions.view)
        } else {
            let refresh = NSButton(title: "Refresh", target: self, action: #selector(loadChats))
            bar = NSStackView(views: [search, refresh])
            actionRow = actions.view
            actions.reload = { [weak self] in self?.loadChats() }
        }
        status.textColor = .secondaryLabelColor
        actions.selection = { [weak self] in
            guard let self = self, self.filtered.indices.contains(self.table.selectedRow) else { return nil }
            return self.filtered[self.table.selectedRow]
        }
        let body = column([bar, scroll, status, actionRow, actions.notice])
        if members { body.distribution = .fill }
        pin(body, in: view, inset: members ? 0 : 12)
    }

    @objc func loadChats() {
        guard !loading else { return }
        loading = true
        status.stringValue = "Loading…"
        sendPage("chats")
    }

    func receive(_ reply: [String: Any]) {
        if reply["operation"] as? Bool == true { actions.completed(reply); return }
        loading = false
        display(reply)
    }

    func display(_ reply: [String: Any]) {
        actions.configure(reply["actions"] as? [[String: Any]] ?? [])
        rows = reply["rows"] as? [[String: Any]] ?? []
        readError = reply["error"] as? String
        filter()
    }

    func tableViewSelectionDidChange(_ notification: Notification) { actions.update() }

    func controlTextDidChange(_ notification: Notification) { filter() }

    private func filter() {
        let selectedID = actions.selection()?["id"] as? String
        let query = search.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        filtered = query.isEmpty ? rows : rows.filter { row in
            columns.contains { (row[$0.0] as? String)?.localizedCaseInsensitiveContains(query) == true }
        }
        table.deselectAll(nil)
        table.reloadData()
        if let id = selectedID, let index = filtered.firstIndex(where: { $0["id"] as? String == id }) {
            table.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
        }
        actions.update()
        status.stringValue = readError ?? "\(filtered.count) of \(rows.count) \(page)"
    }

    func numberOfRows(in tableView: NSTableView) -> Int { filtered.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let id = tableColumn?.identifier else { return nil }
        let cell = table.makeView(withIdentifier: id, owner: self) as? NSTextField ?? NSTextField(labelWithString: "")
        cell.identifier = id
        cell.stringValue = filtered[row][id.rawValue] as? String ?? "—"
        cell.lineBreakMode = .byTruncatingTail
        if page == "nodes" && id.rawValue == "state", let detail = filtered[row]["status_detail"] as? String {
            cell.toolTip = detail
        } else {
            cell.toolTip = cell.stringValue
        }
        return cell
    }
}

final class StatsTable: NSObject, NSTableViewDelegate, NSTableViewDataSource {
    let table = NSTableView()
    let scroll = NSScrollView()
    private var rows: [[String: String]] = []
    private let numeric = ["messages", "bytes", "ordinary", "goals"]

    init(_ columns: [(String, String, CGFloat)]) {
        super.init()
        for (key, title, width) in columns {
            let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(key))
            col.title = title
            col.width = width
            if numeric.contains(key) { col.headerCell.alignment = .right }
            table.addTableColumn(col)
        }
        table.columnAutoresizingStyle = .noColumnAutoresizing
        table.dataSource = self
        table.delegate = self
        table.usesAlternatingRowBackgroundColors = true
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.borderType = .bezelBorder
    }

    func receive(_ rows: [[String: String]]) {
        self.rows = rows
        table.reloadData()
    }

    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let id = tableColumn?.identifier else { return nil }
        let cell = table.makeView(withIdentifier: id, owner: self) as? NSTextField ?? NSTextField(labelWithString: "")
        cell.identifier = id
        cell.stringValue = rows[row][id.rawValue] ?? ""
        cell.toolTip = cell.stringValue
        cell.lineBreakMode = .byTruncatingTail
        cell.alignment = numeric.contains(id.rawValue) ? .right : .left
        return cell
    }
}

final class StatsTab: NSObject {
    let view = NSView()
    let senders = StatsTable([("name", "Chat", 180), ("messages", "Messages", 90),
                              ("bytes", "Bytes", 105), ("chat_id", "Chat ID", 265)])
    let nodes = StatsTable([("name", "Node", 150), ("status", "Report", 90), ("messages", "Messages", 85),
                            ("bytes", "Bytes", 95), ("ordinary", "Continuations", 110), ("goals", "Goal resumes", 105),
                            ("as_of", "As of (UTC)", 165), ("started", "Tracking since (UTC)", 165),
                            ("backfill", "Earlier activity", 200), ("older_daemon", "Older daemon activity", 180), ("id", "Node ID", 265)])
    let details = NSTabView()
    private let notice = NSTextField(wrappingLabelWithString: "")
    private let coverage = NSTextField(wrappingLabelWithString: "")
    private let outbound = NSTextField(wrappingLabelWithString: "")
    private let babysitter = NSTextField(wrappingLabelWithString: "")
    private let empty = NSTextField(wrappingLabelWithString: "No sending chats in the reported activity.")
    private var loading = false
    private lazy var refresh = NSButton(title: "Refresh", target: self, action: #selector(load))
    private lazy var body = column([coverage, heading("Outbound messages"), outbound,
                                    heading("Babysitter"), babysitter, details])

    private func heading(_ title: String) -> NSTextField {
        let field = NSTextField(labelWithString: title)
        field.font = .boldSystemFont(ofSize: NSFont.systemFontSize)
        return field
    }

    override init() {
        super.init()
        let ranks = NSView()
        pin(senders.scroll, in: ranks)
        empty.translatesAutoresizingMaskIntoConstraints = false
        ranks.addSubview(empty)
        NSLayoutConstraint.activate([empty.leadingAnchor.constraint(equalTo: ranks.leadingAnchor, constant: 8),
                                     empty.topAnchor.constraint(equalTo: ranks.topAnchor, constant: 8)])
        for (title, child) in [("Top 10 sending chats", ranks), ("Node reports", nodes.scroll)] {
            let tab = NSTabViewItem(identifier: title)
            tab.label = title
            tab.view = child
            details.addTabViewItem(tab)
        }
        empty.textColor = .secondaryLabelColor
        [coverage, outbound, babysitter].forEach { $0.isSelectable = true }
        let header = NSStackView(views: [heading("Cluster activity"), NSView(), refresh])
        body.isHidden = true
        notice.isHidden = true
        pin(column([header, notice, body]), in: view, inset: 12)
    }

    @objc func load() {
        guard !loading else { return }
        loading = true
        refresh.isEnabled = false
        body.isHidden = true
        notice.stringValue = "Loading stats…"
        notice.isHidden = false
        sendPage("stats")
    }

    func receive(_ reply: [String: Any]) {
        loading = false
        refresh.isEnabled = true
        let rows = reply["rows"] as? [[String: String]] ?? []
        senders.receive(rows)
        nodes.receive(reply["nodes"] as? [[String: String]] ?? [])
        notice.stringValue = reply["error"] as? String ?? ""
        notice.isHidden = notice.stringValue.isEmpty
        body.isHidden = !notice.isHidden
        coverage.stringValue = reply["coverage"] as? String ?? ""
        outbound.stringValue = reply["outbound"] as? String ?? ""
        babysitter.stringValue = reply["babysitter"] as? String ?? ""
        empty.isHidden = !rows.isEmpty
        senders.scroll.isHidden = rows.isEmpty
    }
}

final class ReleaseChannelRow: NSObject {
    let choice = NSPopUpButton(frame: .zero, pullsDown: false)
    let detail = NSTextField(wrappingLabelWithString: "")
    private let hint = NSTextField(wrappingLabelWithString: "Switching channels requests one update per node, even when automatic updates are paused.")
    let retry = NSButton(title: "Retry request", target: nil, action: nil)
    private let channels = ["stable", "beta"]
    private var current: String?
    private var busy = false
    private(set) var pending = false
    private let title = "Cluster release channel"
    lazy var view = column([NSStackView(views: [NSTextField(labelWithString: title), choice, retry, NSView()]), hint, detail])

    override init() {
        super.init()
        view.spacing = 3
        hint.textColor = .secondaryLabelColor
        detail.isHidden = true
        retry.isHidden = true
        retry.target = self
        retry.action = #selector(retryRequest)
        choice.setAccessibilityLabel(title)
        choice.addItems(withTitles: channels.map { $0.capitalized })
        choice.select(nil)
        choice.isEnabled = false
        choice.target = self
        choice.action = #selector(selectChannel)
    }

    func load() {
        guard !busy else { return }
        busy = true
        choice.isEnabled = false
        retry.isEnabled = false
        sendPage("release_channel")
    }

    @objc private func retryRequest() {
        guard !busy, retry.isEnabled else { return }
        busy = true
        retry.isEnabled = false
        detail.stringValue = "Retrying the same request…"
        sendPage("retry_release_channel")
    }

    private func showCurrent() {
        if let current = current, let index = channels.firstIndex(of: current) {
            choice.selectItem(at: index)
        } else {
            choice.select(nil)
        }
    }

    @objc func selectChannel() {
        let index = choice.indexOfSelectedItem
        showCurrent()
        guard !busy, choice.isEnabled, channels.indices.contains(index), channels[index] != current else { return }
        busy = true
        choice.isEnabled = false
        detail.stringValue = "Requesting \(channels[index].capitalized)…"
        detail.isHidden = false
        sendPage("set_release_channel", ["channel": channels[index]])
    }

    func receive(_ reply: [String: Any]) {
        busy = false
        current = reply["current"] as? String
        pending = reply["pending"] as? Bool == true
        showCurrent()
        choice.isEnabled = choice.indexOfSelectedItem >= 0 && reply["can_set"] as? Bool == true
        retry.isHidden = reply["retry"] as? Bool != true
        retry.isEnabled = !retry.isHidden
        detail.stringValue = reply["notice"] as? String ?? ""
        detail.isHidden = detail.stringValue.isEmpty
    }
}

final class SettingsTab: NSObject {
    let view = NSView()
    let text = NSTextView()
    let status = NSTextField(wrappingLabelWithString: "")
    let channel = ReleaseChannelRow()
    private let form = NSScrollView()
    private let editor = NSView()
    private var checks: [String: NSButton] = [:]
    private var controls: [NSButton] = []
    private var loaded: [String: Bool] = [:]
    private lazy var pricing = NSButton(title: "Babysitter requires Gent Pro · View plans", target: self, action: #selector(openPricing))
    @objc private func openPricing() { NSWorkspace.shared.open(URL(string: "https://gent.link/pricing")!) }
    private var busy = false

    override init() {
        super.init()
        let options = [("login", "Start Gent Desktop at graphical login"), ("updates", "Automatically update Gent"),
                       ("discovery", "Discover and publish native chats"),
                       ("babysitter", "Resume goals after provider failures"),
                       ("ordinary_babysitter", "Continue ordinary chats after provider errors"),
                       ("direct", "Prefer direct connections"),
                       ("udp", "Allow UDP for direct connections"), ("helper", "Offer this node as a transport helper")]
        var fields: [NSView] = []
        let headings = ["login": "General", "babysitter": "Babysitter", "direct": "Network"]
        for (key, title) in options {
            if let section = headings[key] {
                let heading = NSTextField(labelWithString: section)
                heading.font = .boldSystemFont(ofSize: NSFont.systemFontSize)
                fields.append(heading)
            }
            let button = NSButton(checkboxWithTitle: title, target: self, action: #selector(toggle(_:)))
            button.identifier = NSUserInterfaceItemIdentifier(key)
            button.isEnabled = false
            checks[key] = button
            fields.append(button)
            if key == "updates" { fields.append(channel.view) }
            if key == "ordinary_babysitter" {
                let detail = NSTextField(wrappingLabelWithString: "Sends “please continue” in eligible Codex chats on this node.")
                detail.textColor = .secondaryLabelColor
                fields.append(detail)
                pricing.isHidden = true
                fields.append(pricing)
            }
        }
        let hint = NSTextField(labelWithString: "Network changes take effect when the daemon restarts.")
        hint.textColor = .secondaryLabelColor
        fields.append(hint)
        let edit = NSButton(title: "Edit full configuration…", target: self, action: #selector(openEditor))
        fields.append(NSStackView(views: [edit, NSView()]))
        let standard = column(fields)
        let document = FlippedDocument()
        form.documentView = document
        form.hasVerticalScroller = true
        form.drawsBackground = false
        document.translatesAutoresizingMaskIntoConstraints = false
        pin(standard, in: document)
        NSLayoutConstraint.activate([
            document.leadingAnchor.constraint(equalTo: form.contentView.leadingAnchor),
            document.topAnchor.constraint(equalTo: form.contentView.topAnchor),
            document.widthAnchor.constraint(equalTo: form.contentView.widthAnchor),
        ])

        text.isRichText = false
        text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        text.isAutomaticQuoteSubstitutionEnabled = false
        text.isAutomaticDashSubstitutionEnabled = false
        text.isAutomaticTextReplacementEnabled = false
        text.allowsUndo = true
        text.autoresizingMask = [.width]
        text.textContainer?.widthTracksTextView = true
        let scroll = NSScrollView()
        scroll.documentView = text
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        let help = NSTextField(wrappingLabelWithString: "Save locally writes config.toml. Publish also submits node and cluster names and policy to the cluster.")
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(discard))
        let save = NSButton(title: "Save locally", target: self, action: #selector(saveLocal))
        let publish = NSButton(title: "Save and publish…", target: self, action: #selector(saveShared))
        controls = [edit, cancel, save, publish]
        let actions = NSStackView(views: [cancel, NSView(), save, publish])
        pin(column([help, scroll, actions]), in: editor)
        let area = NSView()
        pin(form, in: area)
        pin(editor, in: area)
        editor.isHidden = true
        area.setContentHuggingPriority(.defaultLow, for: .vertical)
        pin(column([area, status]), in: view, inset: 16)
    }

    func load() {
        if editor.isHidden {
            request("settings")
            channel.load()
        }
    }

    func pollChannel() {
        if editor.isHidden && channel.pending { channel.load() }
    }

    private func enableControls() {
        for button in controls { button.isEnabled = !busy }
        for (key, button) in checks {
            let needsPro = key == "babysitter" || (key == "ordinary_babysitter" && loaded[key] != true)
            let available = loaded[key] != nil && (!needsPro || loaded["paid"] == true)
            button.state = available && loaded[key] == true ? .on : .off
            button.isEnabled = !busy && available
        }
        pricing.isHidden = loaded["paid"] != false
        text.isEditable = !busy
    }

    private func request(_ op: String, _ fields: [String: Any] = [:]) {
        guard !busy else { return }
        busy = true
        enableControls()
        status.stringValue = ""
        sendPage(op, fields)
    }

    @objc func toggle(_ button: NSButton) {
        guard let key = button.identifier?.rawValue else { return }
        request("set", ["key": key, "enabled": button.state == .on])
    }
    @objc func openEditor() { request("edit") }
    @objc func discard() { request("discard") }
    @objc func saveLocal() { request("save", ["text": text.string, "publish": false]) }
    @objc func saveShared() {
        let alert = NSAlert()
        alert.messageText = "Publish these shared settings to the cluster?"
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Save and publish")
        if alert.runModal() == .alertSecondButtonReturn {
            request("save", ["text": text.string, "publish": true])
        }
    }

    func receive(_ reply: [String: Any]) {
        busy = false
        if let values = reply["values"] as? [String: Bool] { loaded = values }
        enableControls()
        if let document = reply["document"] as? String {
            text.string = document
            text.undoManager?.removeAllActions()
            form.isHidden = true
            editor.isHidden = false
        } else if reply["error"] == nil {
            text.string = ""
            text.undoManager?.removeAllActions()
            editor.isHidden = true
            form.isHidden = false
        }
        status.stringValue = reply["error"] as? String ?? reply["notice"] as? String ?? ""
    }
}
