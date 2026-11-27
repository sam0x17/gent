import AppKit

// The supervisor supplies labels and choices. Every mutation still has a typed Rust handler.
final class ActionBar: NSObject {
    let view = NSStackView()
    let notice = NSTextField(wrappingLabelWithString: "")
    var selection: () -> [String: Any]? = { nil }
    var reload: () -> Void = {}
    private var specs: [[String: Any]] = []
    private var busy = false
    private let pairedRows: Bool
    private var buttons: [NSButton] = []

    init(pairedRows: Bool = false) {
        self.pairedRows = pairedRows
        super.init()
        if pairedRows {
            view.orientation = .vertical
            view.alignment = .leading
            view.spacing = 4
        }
    }

    func configure(_ specs: [[String: Any]]) {
        guard !NSArray(array: self.specs).isEqual(to: specs) else { update(); return }
        self.specs = specs
        buttons.removeAll()
        for child in view.arrangedSubviews { view.removeArrangedSubview(child); child.removeFromSuperview() }
        var row = view
        for (index, spec) in specs.enumerated() {
            let button = NSButton(title: spec["title"] as? String ?? "", target: self, action: #selector(open(_:)))
            button.tag = index
            if pairedRows && index.isMultiple(of: 2) {
                row = NSStackView()
                view.addArrangedSubview(row)
            }
            row.addArrangedSubview(button)
            buttons.append(button)
        }
        if !pairedRows { view.addArrangedSubview(NSView()) }
        update()
    }

    func update() {
        let row = selection()
        for button in buttons {
            let spec = specs[button.tag]
            var enabled = true
            if spec["row"] as? Bool == true {
                enabled = row != nil && !["Retired", "Revoked"].contains(row?["state"] as? String ?? "")
                if ["remove_node", "node_role"].contains(spec["kind"] as? String ?? "") {
                    enabled = enabled && row?["state"] as? String != "local" && row?["role"] as? String != "Owner"
                }
            }
            button.isEnabled = enabled && !busy
        }
    }

    @objc private func open(_ sender: NSButton) {
        guard !busy, let kind = specs[sender.tag]["kind"] as? String else { return }
        let spec = specs[sender.tag]
        var values = spec["values"] as? [String: Any] ?? [:]
        values["kind"] = kind
        let row = spec["row"] as? Bool == true ? selection() : nil
        if spec["row"] as? Bool == true {
            guard let id = row?["id"] as? String else { return }
            values["id"] = id
        }
        let fields = spec["fields"] as? [[String: Any]] ?? []
        if fields.isEmpty && spec["confirm"] == nil { submit(values); return }
        guard let window = view.window else { return }
        let dialog = NSAlert()
        dialog.messageText = sender.title.trimmingCharacters(in: CharacterSet(charactersIn: "…"))
        var info = [String]()
        if let name = row?["name"] as? String, let id = row?["id"] as? String { info.append("\(name) · \(id)") }
        if let hint = (spec["confirm"] ?? spec["hint"]) as? String { info.append(hint) }
        dialog.informativeText = info.joined(separator: "\n\n")
        dialog.addButton(withTitle: "Cancel")
        dialog.addButton(withTitle: spec["submit"] as? String ?? dialog.messageText)
        var readers: [(String, () -> String)] = []
        let form = NSStackView()
        form.orientation = .vertical
        form.alignment = .leading
        form.spacing = 6
        var first: NSView?
        for field in fields {
            guard let key = field["key"] as? String else { continue }
            form.addArrangedSubview(NSTextField(labelWithString: field["title"] as? String ?? key))
            let control: NSView
            if let choices = field["choices"] as? [[String]] {
                let popup = NSPopUpButton()
                for pair in choices where pair.count == 2 {
                    let item = NSMenuItem(title: pair[1], action: nil, keyEquivalent: "")
                    item.representedObject = pair[0]
                    popup.menu?.addItem(item)
                }
                if key == "role", let role = row?["role"] as? String {
                    popup.selectItem(at: role == "Admin" ? 0 : 1)
                }
                readers.append((key, { popup.selectedItem?.representedObject as? String ?? "" }))
                control = popup
            } else {
                let input: NSTextField = field["secret"] as? Bool == true ? NSSecureTextField() : NSTextField()
                input.stringValue = row?[key] as? String ?? ""
                readers.append((key, { input.stringValue.trimmingCharacters(in: .whitespacesAndNewlines) }))
                control = input
            }
            form.addArrangedSubview(control)
            control.widthAnchor.constraint(equalToConstant: 350).isActive = true
            if first == nil { first = control }
        }
        if !fields.isEmpty {
            form.frame.size = form.fittingSize
            dialog.accessoryView = form
            dialog.window.initialFirstResponder = first
        }
        dialog.beginSheetModal(for: window) { [weak self] answer in
            guard answer == .alertSecondButtonReturn, let self = self else { return }
            for (key, read) in readers {
                let value = read()
                guard !value.isEmpty else { self.notice.stringValue = "Complete all fields and try again."; return }
                values[key] = value
            }
            self.submit(values)
        }
    }

    private func submit(_ values: [String: Any]) {
        guard !busy else { return }
        busy = true
        notice.stringValue = values["kind"] as? String == "sign_in" ? "Waiting for sign-in in your browser…" : "Working…"
        update()
        sendPage("manage", ["action": values])
    }

    func completed(_ reply: [String: Any]) {
        busy = false
        update()
        notice.stringValue = (reply["error"] ?? reply["notice"]) as? String ?? ""
        if let code = reply["private_code"] as? String, let window = view.window {
            let dialog = NSAlert()
            dialog.messageText = reply["notice"] as? String ?? "Invitation"
            dialog.informativeText = "Enter this private code on the new node within 15 minutes."
            let field = NSTextField(labelWithString: code)
            field.isSelectable = true
            field.lineBreakMode = .byCharWrapping
            field.preferredMaxLayoutWidth = 380
            field.frame.size = field.fittingSize
            dialog.accessoryView = field
            dialog.addButton(withTitle: "Done")
            dialog.beginSheetModal(for: window, completionHandler: nil)
        }
        if reply["error"] == nil { reload() }
    }
}

// About receives plain text; links are the only rich-text attributes supplied by the view.
private struct AboutText {
    let text = NSMutableAttributedString()
    var links = Set<URL>()
    let expanded: Bool

    init(_ reply: [String: Any], detail: String) {
        let root = "https://github.com/sam0x17/gent"
        let release = reply["error"] == nil ? reply["latest_release"] as? [String: Any] : nil
        var version = release?["version"] as? String ?? ""
        if version.hasPrefix("v") { version.removeFirst() }
        let notes = release?["notes"] as? String ?? ""
        let hasNotes = !notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        expanded = !version.isEmpty || hasNotes
        let releasePath = "\(root)/releases/tag/v\(version)"
        var releaseURL: URL?
        if version.range(of: #"\A[0-9][0-9A-Za-z.+-]{0,127}\z"#, options: .regularExpression) != nil,
           release?["url"] as? String == releasePath {
            releaseURL = URL(string: releasePath)
        }
        let installed = reply["version"] as? String ?? ""
        let revision = reply["revision"] as? String ?? ""
        let prefix = "Version \(installed) · "
        if !installed.isEmpty && detail.hasPrefix(prefix) {
            append("Version ")
            append(installed, url: installed == version ? releaseURL : nil)
            append(" · ")
            var rest = detail.dropFirst(prefix.count)
            let short = revision.prefix(12)
            if revision.range(of: #"\A[0-9a-f]{40}\z"#, options: .regularExpression) != nil, rest.hasPrefix(short) {
                let target = reply["revision_url"] as? String
                let commit = "\(root)/commit/\(revision)"
                let url = target == commit ? URL(string: commit) : (target == releaseURL?.absoluteString ? releaseURL : nil)
                append(String(short), url: url)
                rest = rest.dropFirst(short.count)
            }
            append(String(rest))
        } else {
            append(detail)
        }
        if expanded {
            if !detail.isEmpty { append("\n\n") }
            append(hasNotes ? "Release notes" : "Latest release", bold: true)
            if !version.isEmpty {
                append(hasNotes ? " for " : " ", bold: true)
                append("v" + version, url: releaseURL, bold: true)
            }
            if hasNotes { append("\n\n" + notes) }
        }
    }

    private mutating func append(_ string: String, url: URL? = nil, bold: Bool = false) {
        var attributes: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: NSFont.systemFontSize, weight: bold ? .semibold : .regular),
            .foregroundColor: NSColor.labelColor,
        ]
        if let url = url {
            attributes[.link] = url
            links.insert(url)
        }
        text.append(NSAttributedString(string: string, attributes: attributes))
    }
}

final class ManagementTab: NSObject, NSTextViewDelegate {
    let view = NSView()
    let title = NSTextField(labelWithString: "")
    let detail = NSTextView()
    let actions = ActionBar()
    let page: String
    private var busy = false
    private var compactConstraints: [NSLayoutConstraint] = []
    private var releaseConstraints: [NSLayoutConstraint] = []
    private var aboutLinks = Set<URL>()
    var openURL: (URL) -> Void = { _ = NSWorkspace.shared.open($0) }

    init(page: String, icon: NSImage? = nil) {
        self.page = page
        super.init()
        title.font = .systemFont(ofSize: 21, weight: .semibold)
        var fields: [NSView] = [title]
        detail.isEditable = false
        detail.isSelectable = true
        detail.drawsBackground = false
        detail.font = .systemFont(ofSize: NSFont.systemFontSize)
        detail.autoresizingMask = [.width]
        detail.textContainer?.widthTracksTextView = true
        let scroll = NSScrollView()
        scroll.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.documentView = detail
        fields.append(scroll)
        if page == "about" {
            let link = NSButton(title: "https://gent.link", target: self, action: #selector(openSite))
            link.bezelStyle = .inline
            fields.append(NSStackView(views: [link, NSView()]))
        }
        fields.append(contentsOf: [actions.view, actions.notice])
        let body = column(fields)
        if page == "about" {
            let image = NSImageView()
            image.image = icon
            image.imageScaling = .scaleProportionallyDown
            image.setAccessibilityLabel("Gent logo")
            image.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            image.setContentCompressionResistancePriority(.defaultLow, for: .vertical)
            let row = NSStackView(views: [image, body])
            row.spacing = 16
            row.alignment = .centerY
            pin(row, in: view, inset: 16)
            detail.delegate = self
            detail.isAutomaticLinkDetectionEnabled = false
            scroll.autohidesScrollers = true
            compactConstraints = [body.widthAnchor.constraint(equalToConstant: 250),
                                  scroll.heightAnchor.constraint(equalToConstant: 64)]
            let width = body.widthAnchor.constraint(equalTo: row.widthAnchor, multiplier: 0.58)
            width.priority = .defaultHigh
            releaseConstraints = [width, body.widthAnchor.constraint(greaterThanOrEqualToConstant: 280),
                                  body.heightAnchor.constraint(equalTo: row.heightAnchor)]
            NSLayoutConstraint.activate(compactConstraints)
            image.heightAnchor.constraint(equalTo: row.heightAnchor).isActive = true
        } else {
            pin(body, in: view, inset: 16)
        }
        actions.reload = { [weak self] in self?.load() }
    }
    func textView(_ textView: NSTextView, clickedOnLink link: Any, at charIndex: Int) -> Bool {
        if let url = link as? URL, aboutLinks.contains(url) { openURL(url) }
        return true
    }

    @objc private func openSite() { openURL(URL(string: "https://gent.link")!) }
    func load() {
        guard !busy else { return }
        busy = true
        sendPage(page)
    }
    func receive(_ reply: [String: Any]) {
        if reply["operation"] as? Bool == true { actions.completed(reply); return }
        busy = false
        title.stringValue = reply["title"] as? String ?? page.capitalized
        let value = (reply["error"] ?? reply["detail"]) as? String ?? ""
        if page == "about" {
            let content = AboutText(reply, detail: value)
            aboutLinks = content.links
            if detail.textStorage?.isEqual(to: content.text) != true {
                detail.textStorage?.setAttributedString(content.text)
                detail.scrollRangeToVisible(NSRange(location: 0, length: 0))
            }
            NSLayoutConstraint.deactivate(content.expanded ? compactConstraints : releaseConstraints)
            NSLayoutConstraint.activate(content.expanded ? releaseConstraints : compactConstraints)
        } else {
            detail.string = value
        }
        actions.configure(reply["actions"] as? [[String: Any]] ?? [])
    }
}

// The account page has its own read cadence. Its sign-in state and setup actions
// can arrive before the first status snapshot or while a daemon command is running.
final class AccountSection {
    let title = NSTextField(labelWithString: "Loading account…")
    let detail = NSTextField(wrappingLabelWithString: "")
    let actions = ActionBar(pairedRows: true)
    let view: NSStackView
    private var loading = false
    private var reloadAfterRead = false

    init() {
        title.font = .systemFont(ofSize: 18, weight: .semibold)
        detail.isSelectable = true
        view = column([title, detail, actions.view, actions.notice])
    }

    func load() {
        guard !loading else { return }
        loading = true
        sendPage("cluster")
    }

    func receive(_ reply: [String: Any]) {
        if reply["operation"] as? Bool == true {
            actions.completed(reply)
            if loading { reloadAfterRead = true }
            else { load() }
            return
        }
        loading = false
        if reloadAfterRead {
            reloadAfterRead = false
            load()
            return
        }
        title.stringValue = reply["title"] as? String ?? "Account"
        detail.stringValue = (reply["error"] ?? reply["detail"]) as? String ?? ""
        actions.configure(reply["actions"] as? [[String: Any]] ?? [])
    }
}
