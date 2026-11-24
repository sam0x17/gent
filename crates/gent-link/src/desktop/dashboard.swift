import AppKit
import ImageIO
import UniformTypeIdentifiers

// Inspect the compressed image's type and pixel dimensions before decoding its first frame.
private func dashboardRaster(_ value: Any?) -> NSImage? {
    guard let uri = value as? String, uri.utf8.count <= 32 * 1024,
          let comma = uri.firstIndex(of: ",") else { return nil }
    let payload = uri[uri.index(after: comma)...]
    guard let bytes = Data(base64Encoded: String(payload)) else { return nil }
    // ImageIO can recover a partial image after a truncated stream. Require its terminator.
    let type: UTType
    switch uri[..<comma] {
    case "data:image/png;base64":
        guard bytes.starts(with: [137, 80, 78, 71, 13, 10, 26, 10]),
              bytes.suffix(12).elementsEqual([0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130]) else { return nil }
        type = .png
    case "data:image/jpeg;base64":
        guard bytes.starts(with: [0xff, 0xd8]), bytes.suffix(2).elementsEqual([0xff, 0xd9]) else { return nil }
        type = .jpeg
    default: return nil
    }
    guard let source = CGImageSourceCreateWithData(bytes as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
          CGImageSourceGetType(source) as String? == type.identifier,
          CGImageSourceGetStatus(source) == .statusComplete, CGImageSourceGetCount(source) == 1,
          let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
          let width = properties[kCGImagePropertyPixelWidth] as? Int, (1...2048).contains(width),
          let height = properties[kCGImagePropertyPixelHeight] as? Int, (1...2048).contains(height),
          width * height <= 1_048_576 else { return nil }
    let options: [CFString: Any] = [
        kCGImageSourceCreateThumbnailFromImageAlways: true,
        kCGImageSourceCreateThumbnailWithTransform: true,
        kCGImageSourceThumbnailMaxPixelSize: max(width, height),
        kCGImageSourceShouldCacheImmediately: true,
    ]
    guard let pixels = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary),
          CGImageSourceGetStatusAtIndex(source, 0) == .statusComplete else { return nil }
    return NSImage(cgImage: pixels, size: NSSize(width: pixels.width, height: pixels.height))
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
    private var cards: [NSBox] = []
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
        if let next = reply["rows"] as? [[String: Any]] {
            if !NSArray(array: rows).isEqual(to: next) {
                rows = next
                cards = next.compactMap(makeCard)
                arrangeCards()
            }
        } else if reply["unchanged"] as? Bool != true {
            showNotice((reply["error"] ?? reply["notice"]) as? String ?? "")
            return
        }
        showNotice(rows.isEmpty ? "No chats have published a dashboard." : "")
    }

    private func showNotice(_ message: String) {
        guard notice.stringValue != message else { return }
        notice.stringValue = message
        notice.isHidden = message.isEmpty
    }

    @objc private func openLink(_ link: DashboardLink) {
        openURL(link.url)
    }

    @objc private func resized() {
        if viewportColumns != columns { arrangeCards() }
    }

    private func arrangeCards() {
        columns = viewportColumns
        for line in grid.arrangedSubviews {
            grid.removeArrangedSubview(line)
            line.removeFromSuperview()
        }
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

        @discardableResult
        func addText(_ value: String) -> NSTextField {
            let field = NSTextField(wrappingLabelWithString: value)
            field.isSelectable = true
            content.addArrangedSubview(field)
            field.widthAnchor.constraint(lessThanOrEqualTo: content.widthAnchor).isActive = true
            return field
        }

        func addImage(_ image: NSImage, description: String, chart: Bool) {
            let view = NSImageView()
            view.image = image
            view.imageScaling = .scaleProportionallyUpOrDown
            view.setAccessibilityElement(true)
            view.setAccessibilityRole(.image)
            view.setAccessibilityLabel(description)
            view.toolTip = description
            view.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            view.setContentCompressionResistancePriority(.defaultLow, for: .vertical)
            content.addArrangedSubview(view)
            let width = view.widthAnchor.constraint(equalTo: content.widthAnchor)
            if !chart {
                // Keep small images at native size and fit portraits on a laptop screen.
                width.priority = NSLayoutConstraint.Priority(495)
                view.widthAnchor.constraint(lessThanOrEqualTo: content.widthAnchor).isActive = true
                view.widthAnchor.constraint(lessThanOrEqualToConstant: image.size.width).isActive = true
                view.heightAnchor.constraint(lessThanOrEqualToConstant: 360).isActive = true
            }
            width.isActive = true
            view.heightAnchor.constraint(equalTo: view.widthAnchor, multiplier: image.size.height / image.size.width).isActive = true
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
            let unit = (item["unit"] as? String).map { " " + $0 } ?? ""
            if kind == "metric" {
                let number = (value as? NSNumber)?.stringValue ?? "—"
                var label = title[...]
                while let last = label.last, last.isWhitespace || last == ":" { label = label.dropLast() }
                let text = NSMutableAttributedString(string: label + ":", attributes: [
                    .font: NSFont.boldSystemFont(ofSize: NSFont.systemFontSize)
                ])
                text.append(NSAttributedString(string: " " + number + unit, attributes: [
                    .font: NSFont.systemFont(ofSize: NSFont.systemFontSize)
                ]))
                addText("").attributedStringValue = text
                continue
            }
            addText(title)
            switch kind {
            case "graph", "bar", "pie", "radar", "scatter":
                let description = item["chart_description"] as? String ?? title
                // Only the supervisor supplies chart_svg. AppKit keeps its SVG representation scalable.
                if let svg = item["chart_svg"] as? String, let chart = NSImage(data: Data(svg.utf8)),
                   chart.size.width > 0, chart.size.height > 0 {
                    chart.cacheMode = .never
                    addImage(chart, description: description, chart: true)
                } else {
                    addText(item["chart_description"] as? String ?? "Chart unavailable")
                }
                if kind == "graph" {
                    addText((value as? [Double])?.last.map { String($0) + unit } ?? "—")
                }
            case "image":
                if let image = dashboardRaster(value) {
                    addImage(image, description: title, chart: false)
                } else {
                    addText("Image unavailable")
                }
            case "progress", "gauge":
                let bar = NSLevelIndicator()
                bar.levelIndicatorStyle = .continuousCapacity
                bar.minValue = item["min"] as? Double ?? 0
                bar.maxValue = item["max"] as? Double ?? 100
                bar.doubleValue = value as? Double ?? 0
                content.addArrangedSubview(bar)
                bar.widthAnchor.constraint(equalTo: content.widthAnchor).isActive = true
                addText(String(bar.doubleValue) + unit)
            default:
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
