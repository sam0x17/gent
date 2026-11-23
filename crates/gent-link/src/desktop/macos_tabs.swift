import AppKit

// The supervisor handles these requests locally. Configuration text travels only over stdin/stdout.
func sendPage(_ op: String, _ fields: [String: Any] = [:]) {
    var object = fields
    object["op"] = op
    guard var bytes = try? JSONSerialization.data(withJSONObject: object) else { return }
    bytes.append(10)
    FileHandle.standardOutput.write(bytes)
}

private func pin(_ child: NSView, in parent: NSView, inset: CGFloat = 0) {
    parent.addSubview(child)
    child.translatesAutoresizingMaskIntoConstraints = false
    NSLayoutConstraint.activate([
        child.topAnchor.constraint(equalTo: parent.topAnchor, constant: inset),
        child.bottomAnchor.constraint(equalTo: parent.bottomAnchor, constant: -inset),
        child.leadingAnchor.constraint(equalTo: parent.leadingAnchor, constant: inset),
        child.trailingAnchor.constraint(equalTo: parent.trailingAnchor, constant: -inset),
    ])
}

private func column(_ children: [NSView]) -> NSStackView {
    let stack = NSStackView(views: children)
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 9
    for child in children {
        child.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
    }
    return stack
}

final class DirectoryTab: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate {
    let view = NSView()
    let table = NSTableView()
    let search = NSSearchField()
    let status = NSTextField(labelWithString: "")
    let page: String
    let columns: [(String, String, CGFloat)]
    var rows: [[String: Any]] = []
    private var filtered: [[String: Any]] = []
    private var loading = false

    init(page: String) {
        self.page = page
        columns = page == "chats"
            ? [("name", "Chat", 185), ("node", "Node", 120), ("provider", "Provider", 95),
               ("state", "Registration", 100), ("id", "Chat ID", 270)]
            : [("name", "Node", 150), ("state", "Status", 100), ("role", "Role", 70),
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
        let refresh = NSButton(title: "Refresh", target: self, action: #selector(load))
        let bar = NSStackView(views: [search, refresh])
        status.textColor = .secondaryLabelColor
        pin(column([bar, scroll, status]), in: view, inset: 12)
    }

    @objc func load() {
        guard !loading else { return }
        loading = true
        status.stringValue = "Loading…"
        sendPage(page)
    }

    func receive(_ reply: [String: Any]) {
        loading = false
        rows = reply["rows"] as? [[String: Any]] ?? []
        filter()
        if let error = reply["error"] as? String { status.stringValue = error }
    }

    func controlTextDidChange(_ notification: Notification) { filter() }

    private func filter() {
        let query = search.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        filtered = query.isEmpty ? rows : rows.filter { row in
            columns.contains { (row[$0.0] as? String)?.localizedCaseInsensitiveContains(query) == true }
        }
        table.reloadData()
        status.stringValue = "\(filtered.count) of \(rows.count) \(page)"
    }

    func numberOfRows(in tableView: NSTableView) -> Int { filtered.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let id = tableColumn?.identifier else { return nil }
        let cell = table.makeView(withIdentifier: id, owner: self) as? NSTextField ?? NSTextField(labelWithString: "")
        cell.identifier = id
        cell.stringValue = filtered[row][id.rawValue] as? String ?? "—"
        cell.lineBreakMode = .byTruncatingTail
        cell.toolTip = cell.stringValue
        return cell
    }
}

final class SettingsTab: NSObject {
    let view = NSView()
    let text = NSTextView()
    let status = NSTextField(wrappingLabelWithString: "")
    private let form = NSView()
    private let editor = NSView()
    private var checks: [String: NSButton] = [:]
    private var controls: [NSButton] = []
    private var loaded: [String: Bool] = [:]
    private var busy = false

    override init() {
        super.init()
        let options = [("login", "Start Gent Desktop at graphical login"), ("updates", "Automatically update Gent"),
                       ("discovery", "Discover and publish native chats"), ("direct", "Prefer direct connections"),
                       ("udp", "Allow UDP for direct connections"), ("helper", "Offer this node as a transport helper")]
        var fields: [NSView] = []
        for (key, title) in options {
            if key == "login" || key == "direct" {
                let heading = NSTextField(labelWithString: key == "login" ? "General" : "Network")
                heading.font = .boldSystemFont(ofSize: NSFont.systemFontSize)
                fields.append(heading)
            }
            let button = NSButton(checkboxWithTitle: title, target: self, action: #selector(toggle(_:)))
            button.identifier = NSUserInterfaceItemIdentifier(key)
            button.isEnabled = false
            checks[key] = button
            fields.append(button)
        }
        let hint = NSTextField(labelWithString: "Network changes take effect when the daemon restarts.")
        hint.textColor = .secondaryLabelColor
        fields.append(hint)
        let edit = NSButton(title: "Edit full configuration…", target: self, action: #selector(openEditor))
        fields.append(NSStackView(views: [edit, NSView()]))
        let standard = column(fields)
        form.addSubview(standard)
        standard.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            standard.leadingAnchor.constraint(equalTo: form.leadingAnchor),
            standard.trailingAnchor.constraint(equalTo: form.trailingAnchor),
            standard.topAnchor.constraint(equalTo: form.topAnchor),
            standard.bottomAnchor.constraint(lessThanOrEqualTo: form.bottomAnchor),
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

    func load() { if editor.isHidden { request("settings") } }

    private func enableControls() {
        for button in controls { button.isEnabled = !busy }
        for (key, button) in checks {
            button.state = loaded[key] == true ? .on : .off
            button.isEnabled = !busy && loaded[key] != nil
        }
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
