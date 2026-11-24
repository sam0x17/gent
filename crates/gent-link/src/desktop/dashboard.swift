import AppKit

private final class Plot: NSView {
    var samples: [Double] = []
    override func draw(_ rect: NSRect) {
        guard let lo = samples.min(), let hi = samples.max() else { return }
        let line = NSBezierPath()
        for (i, v) in samples.enumerated() {
            let x = 2 + (bounds.width - 4) * CGFloat(i) / CGFloat(max(1, samples.count - 1))
            let y = 2 + (bounds.height - 4) * CGFloat(hi == lo ? 0.5 : (v - lo) / (hi - lo))
            if i == 0 { line.move(to: NSPoint(x: x, y: y)) }
            line.line(to: NSPoint(x: x + 0.1, y: y))
        }
        NSColor.controlAccentColor.setStroke()
        line.lineWidth = 2
        line.stroke()
    }
}

private final class DashboardButton: NSButton {
    var fields: [String: Any] = [:]
    @objc func invoke() { sendPage("dashboard_click", fields) }
}

private final class DashboardLink: NSButton {
    let url: URL

    init(title: String, url: URL) {
        self.url = url
        super.init(frame: .zero)
        isBordered = false
        alignment = .left
        attributedTitle = NSAttributedString(string: title, attributes: [
            .foregroundColor: NSColor.linkColor,
            .underlineStyle: NSUnderlineStyle.single.rawValue,
        ])
        cell?.lineBreakMode = .byTruncatingTail
        toolTip = url.absoluteString
        setAccessibilityRole(.link)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
}

private func dashboardURL(_ value: Any?) -> URL? {
    guard let text = value as? String, text.utf8.count <= 2048,
          !text.unicodeScalars.contains(where: {
              $0.properties.isWhitespace || $0.properties.generalCategory == .control || $0 == "\\"
          }),
          let parts = URLComponents(string: text),
          let scheme = parts.scheme?.lowercased(), scheme == "http" || scheme == "https",
          let host = parts.host, !host.isEmpty else { return nil }
    if let range = parts.rangeOfPort, !range.isEmpty {
        guard let port = parts.port, UInt16(exactly: port) != nil else { return nil }
    }
    return parts.url
}

private final class DashboardGrid: NSStackView {
    override var isFlipped: Bool { true }
}

final class DashboardTab: NSObject {
    let view = NSStackView()
    private let grid = DashboardGrid()
    private let scroll = NSScrollView()
    private let notice = NSTextField(wrappingLabelWithString: "")
    var openURL: (URL) -> Void = { url in _ = NSWorkspace.shared.open(url) }
    private var rows: [[String: Any]] = []
    private var columns = 0
    private var viewportColumns: Int { max(1, min(4, Int(scroll.contentSize.width / 280))) }

    override init() {
        super.init()
        view.orientation = .vertical
        view.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        view.distribution = .fill
        notice.isHidden = true
        grid.distribution = .fill
        grid.orientation = .vertical
        grid.alignment = .leading
        scroll.hasVerticalScroller = true
        scroll.documentView = grid
        grid.translatesAutoresizingMaskIntoConstraints = false
        let clip = scroll.contentView
        let viewportHeight = grid.heightAnchor.constraint(equalTo: clip.heightAnchor)
        // Keep the user's window size first, fit the viewport next, then balance card areas.
        viewportHeight.priority = NSLayoutConstraint.Priority(490)
        NSLayoutConstraint.activate([
            viewportHeight,
            grid.heightAnchor.constraint(greaterThanOrEqualTo: clip.heightAnchor),
            grid.leadingAnchor.constraint(equalTo: clip.leadingAnchor),
            grid.topAnchor.constraint(equalTo: clip.topAnchor),
            grid.widthAnchor.constraint(equalTo: clip.widthAnchor),
        ])
        view.addArrangedSubview(scroll)
        view.addArrangedSubview(notice)
        scroll.widthAnchor.constraint(equalTo: view.widthAnchor, constant: -24).isActive = true
        scroll.contentView.postsFrameChangedNotifications = true
        NotificationCenter.default.addObserver(self, selector: #selector(resized), name: NSView.frameDidChangeNotification, object: scroll.contentView)
    }

    func load() { sendPage("dashboard") }

    func receive(_ reply: [String: Any]) {
        guard let next = reply["rows"] as? [[String: Any]] else {
            showNotice((reply["error"] ?? reply["notice"]) as? String ?? "")
            return
        }
        showNotice(next.isEmpty ? "No chats have published a dashboard." : "")
        if columns == 0 || !NSArray(array: rows).isEqual(to: next) {
            rows = next
            render()
        }
    }

    private func showNotice(_ message: String) {
        notice.stringValue = message
        notice.isHidden = message.isEmpty
    }

    @objc private func openLink(_ link: DashboardLink) {
        openURL(link.url)
    }

    @objc private func resized() {
        if viewportColumns != columns { render() }
    }

    private func render() {
        columns = viewportColumns
        for line in grid.arrangedSubviews {
            grid.removeArrangedSubview(line)
            line.removeFromSuperview()
        }
        let cards = rows.compactMap(makeCard)
        for start in stride(from: 0, to: cards.count, by: columns) {
            let rowCards = cards[start..<min(start + columns, cards.count)]
            let line = NSStackView()
            line.distribution = .fillEqually
            grid.addArrangedSubview(line)
            line.widthAnchor.constraint(equalTo: grid.widthAnchor).isActive = true
            // Equal card areas require a shorter row when fewer cards share its width.
            if start > 0, let first = grid.arrangedSubviews.first {
                let weight = CGFloat(rowCards.count) / CGFloat(columns)
                let height = line.heightAnchor.constraint(equalTo: first.heightAnchor, multiplier: weight)
                height.priority = NSLayoutConstraint.Priority(480)
                height.isActive = true
            }
            for card in rowCards {
                line.addArrangedSubview(card)
                card.heightAnchor.constraint(equalTo: line.heightAnchor).isActive = true
            }
        }
    }

    private func makeCard(_ row: [String: Any]) -> NSBox? {
        guard let board = row["board"] as? [String: Any] else { return nil }
        let card = NSBox()
        card.title = board["title"] as? String ?? ""
        let content = NSStackView()
        content.orientation = .vertical
        content.alignment = .leading

        func addText(_ value: String) {
            let field = NSTextField(wrappingLabelWithString: value)
            field.isSelectable = true
            content.addArrangedSubview(field)
            field.widthAnchor.constraint(lessThanOrEqualTo: content.widthAnchor).isActive = true
        }

        addText(row["chat"] as? String ?? "")
        for item in board["widgets"] as? [[String: Any]] ?? [] {
            let title = item["label"] as? String ?? ""
            let kind = item["kind"] as? String ?? ""
            let value = item["value"]
            if kind == "link" {
                if let url = dashboardURL(value) {
                    let link = DashboardLink(title: title, url: url)
                    link.target = self
                    link.action = #selector(openLink(_:))
                    content.addArrangedSubview(link)
                    link.widthAnchor.constraint(lessThanOrEqualTo: content.widthAnchor).isActive = true
                } else {
                    addText(title)
                }
                continue
            }
            if kind == "button" {
                let button = DashboardButton(title: title, target: nil, action: #selector(DashboardButton.invoke))
                button.target = button
                button.toolTip = value as? String
                button.fields = ["agent": row["agent"]!, "revision": row["revision"]!, "widget": item["id"]!]
                content.addArrangedSubview(button)
                continue
            }
            addText(title)
            let unit = (item["unit"] as? String).map { " " + $0 } ?? ""
            if kind == "graph" {
                let plot = Plot()
                plot.samples = value as? [Double] ?? []
                content.addArrangedSubview(plot)
                plot.heightAnchor.constraint(equalToConstant: 48).isActive = true
                plot.widthAnchor.constraint(equalTo: content.widthAnchor).isActive = true
                addText(plot.samples.last.map { String($0) + unit } ?? "—")
            } else if kind == "progress" || kind == "gauge" {
                let bar = NSLevelIndicator()
                bar.levelIndicatorStyle = .continuousCapacity
                bar.minValue = item["min"] as? Double ?? 0
                bar.maxValue = item["max"] as? Double ?? 100
                bar.doubleValue = value as? Double ?? 0
                content.addArrangedSubview(bar)
                bar.widthAnchor.constraint(equalTo: content.widthAnchor).isActive = true
                addText(String(bar.doubleValue) + unit)
            } else {
                addText((value as? [String])?.joined(separator: "\n") ?? value as? String ?? "")
            }
        }
        // Keep controls at their natural height, grouped at the top of a tall card.
        content.distribution = .fill
        content.addArrangedSubview(NSView())
        card.contentView = content
        card.heightAnchor.constraint(greaterThanOrEqualToConstant: 160).isActive = true
        return card
    }
}
