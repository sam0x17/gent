import AppKit

// The supervisor supplies labels and choices. Every mutation still has a typed Rust handler.
final class ActionBar: NSObject {
    let view = NSStackView()
    let notice = NSTextField(wrappingLabelWithString: "")
    var selection: () -> [String: Any]? = { nil }
    var reload: () -> Void = {}
    private var specs: [[String: Any]] = []
    private var busy = false

    func configure(_ specs: [[String: Any]]) {
        self.specs = specs
        for child in view.arrangedSubviews { view.removeArrangedSubview(child); child.removeFromSuperview() }
        for (index, spec) in specs.enumerated() {
            let button = NSButton(title: spec["title"] as? String ?? "", target: self, action: #selector(open(_:)))
            button.tag = index
            view.addArrangedSubview(button)
        }
        view.addArrangedSubview(NSView())
        update()
    }

    func update() {
        let row = selection()
        for case let button as NSButton in view.arrangedSubviews {
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

final class ManagementTab: NSObject {
    let view = NSView()
    let title = NSTextField(labelWithString: "")
    let detail = NSTextView()
    let actions = ActionBar()
    let page: String
    private var busy = false
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
            scroll.heightAnchor.constraint(equalToConstant: 64).isActive = true
            let row = NSStackView(views: [image, body])
            row.spacing = 16
            row.alignment = .centerY
            pin(row, in: view, inset: 16)
            body.widthAnchor.constraint(equalToConstant: 250).isActive = true
            image.heightAnchor.constraint(equalTo: row.heightAnchor).isActive = true
        } else {
            pin(body, in: view, inset: 16)
        }
        actions.reload = { [weak self] in self?.load() }
    }
    @objc private func openSite() { NSWorkspace.shared.open(URL(string: "https://gent.link")!) }
    func load() {
        guard !busy else { return }
        busy = true
        sendPage(page)
    }
    func receive(_ reply: [String: Any]) {
        if reply["operation"] as? Bool == true { actions.completed(reply); return }
        busy = false
        title.stringValue = reply["title"] as? String ?? page.capitalized
        detail.string = (reply["error"] ?? reply["detail"]) as? String ?? ""
        actions.configure(reply["actions"] as? [[String: Any]] ?? [])
    }
}
