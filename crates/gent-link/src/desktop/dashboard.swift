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

private func dashboardReading(_ value: NSNumber?, unit: String?) -> String {
    guard let value = value else { return "—" }
    var number = value.stringValue
    if number.hasSuffix(".0") { number.removeLast(2) }
    guard let unit = unit, !unit.isEmpty else { return number }
    return number + (unit == "%" ? "" : " ") + unit
}

private let cardSurface = NSColor.textBackgroundColor

private func dashboardPalette(_ appearance: NSAppearance, accent: () -> NSColor) -> [String: [Int]] {
    var palette: [String: [Int]] = [:]
    appearance.performAsCurrentDrawingAppearance {
        let surface = cardSurface.usingColorSpace(.sRGB)!
        for (name, color) in [("surface", cardSurface), ("text", .labelColor),
                              ("secondary", .secondaryLabelColor), ("accent", accent())] {
            let ink = color.usingColorSpace(.sRGB)!
            func channel(_ foreground: CGFloat, over background: CGFloat) -> Int {
                let composited = foreground * ink.alphaComponent + background * (1 - ink.alphaComponent)
                return Int((min(1, max(0, composited)) * 255).rounded())
            }
            palette[name] = [channel(ink.redComponent, over: surface.redComponent),
                             channel(ink.greenComponent, over: surface.greenComponent),
                             channel(ink.blueComponent, over: surface.blueComponent)]
        }
    }
    return palette
}

private final class DashboardGrid: NSStackView {
    var appearanceChanged: (() -> Void)?
    override var isFlipped: Bool { true }
    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        appearanceChanged?()
    }
}

private extension NSStackView {
    func addSection(spacing: CGFloat = 4) -> NSStackView {
        let section = NSStackView()
        section.orientation = .vertical
        section.alignment = .leading
        section.distribution = .fill
        section.spacing = spacing
        addArrangedSubview(section)
        section.widthAnchor.constraint(equalTo: widthAnchor).isActive = true
        return section
    }

    @discardableResult
    func addText(_ value: String, font: NSFont = .systemFont(ofSize: NSFont.systemFontSize),
                 color: NSColor = .labelColor) -> NSTextField {
        let field = NSTextField(wrappingLabelWithString: value)
        field.font = font
        field.textColor = color
        field.isSelectable = true
        addArrangedSubview(field)
        field.widthAnchor.constraint(lessThanOrEqualTo: widthAnchor).isActive = true
        return field
    }

    func addReading(_ label: String, _ value: String, metric: Bool = false) {
        let line = NSStackView()
        line.distribution = .fill
        line.alignment = .firstBaseline
        line.spacing = 8
        addArrangedSubview(line)
        line.widthAnchor.constraint(equalTo: widthAnchor).isActive = true
        let caption = line.addText(label, font: .systemFont(ofSize: 13, weight: metric ? .bold : .semibold))
        let reading = line.addText(value, font: .monospacedDigitSystemFont(ofSize: 13, weight: .regular))
        reading.alignment = .right
        caption.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        caption.setContentHuggingPriority(.defaultLow, for: .horizontal)
        reading.setContentHuggingPriority(.defaultHigh, for: .horizontal)
        reading.widthAnchor.constraint(lessThanOrEqualTo: line.widthAnchor, multiplier: 0.55).isActive = true
        line.setAccessibilityRole(.group)
        line.setAccessibilityLabel(label + " " + value)
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
        addArrangedSubview(view)
        let width = view.widthAnchor.constraint(equalTo: widthAnchor)
        if !chart {
            // Keep small images at native size and fit portraits on a laptop screen.
            width.priority = NSLayoutConstraint.Priority(495)
            view.widthAnchor.constraint(lessThanOrEqualTo: widthAnchor).isActive = true
            view.widthAnchor.constraint(lessThanOrEqualToConstant: image.size.width).isActive = true
            view.heightAnchor.constraint(lessThanOrEqualToConstant: 360).isActive = true
        }
        width.isActive = true
        view.heightAnchor.constraint(equalTo: view.widthAnchor, multiplier: image.size.height / image.size.width).isActive = true
    }
}

final class DashboardTab: NSObject {
    let view = NSStackView()
    private let grid = DashboardGrid()
    private let scroll = NSScrollView()
    private let notice = NSTextField(wrappingLabelWithString: "")
    var openURL: (URL) -> Void = { url in _ = NSWorkspace.shared.open(url) }
    var accentColor: () -> NSColor = { .controlAccentColor }
    private var lastPalette: [String: [Int]]?
    private var lastWidths: [Int] = []
    private var pendingLayout: DispatchWorkItem?
    private var rows: [[String: Any]] = []
    private var cards: [NSBox] = []
    private var columns = 0
    private static let cardSpacing: CGFloat = 10
    private static let cardMargins = NSSize(width: 16, height: 14)
    private static let cardBorder: CGFloat = 1
    private var viewportWidth: CGFloat { scroll.contentView.bounds.width }
    private var viewportColumns: Int { max(1, min(4, Int(viewportWidth / 280))) }
    private var chartWidths: [Int] {
        guard view.bounds.width > 0 && viewportWidth > 0 else { return [260] }
        return (1...viewportColumns).map { count in
            let gutters = Self.cardSpacing * CGFloat(count - 1)
            let card = (viewportWidth - gutters) / CGFloat(count)
            let content = card - 2 * (Self.cardMargins.width + Self.cardBorder)
            return Int(min(16_384, max(160, (content / 8).rounded() * 8)))
        }
    }

    override init() {
        super.init()
        view.orientation = .vertical
        view.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        view.distribution = .fill
        notice.isHidden = true
        grid.distribution = .fill
        grid.orientation = .vertical
        grid.alignment = .leading
        grid.spacing = Self.cardSpacing
        scroll.drawsBackground = false
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
        grid.appearanceChanged = { [weak self] in self?.paletteDidChange() }
        NotificationCenter.default.addObserver(self, selector: #selector(paletteDidChange),
                                               name: NSColor.systemColorsDidChangeNotification, object: nil)
    }

    func load() {
        if view.bounds.width > 0 { view.layoutSubtreeIfNeeded() }
        pendingLayout?.cancel()
        pendingLayout = nil
        requestDashboard(layoutOnly: false)
    }

    private func requestDashboard(layoutOnly: Bool) {
        let widths = chartWidths
        let palette = dashboardPalette(grid.effectiveAppearance, accent: accentColor)
        if layoutOnly && widths == lastWidths && palette == lastPalette { return }
        lastWidths = widths
        lastPalette = palette
        sendPage(layoutOnly ? "dashboard_layout" : "dashboard", ["palette": palette, "chart_widths": widths])
    }

    private var isMapped: Bool {
        guard let window = view.window else { return false }
        return window.isVisible && !window.isMiniaturized && !view.isHiddenOrHasHiddenAncestor
    }

    @objc private func paletteDidChange() { scheduleLayout(after: 0) }

    private func scheduleLayout(after delay: TimeInterval) {
        guard isMapped && lastPalette != nil else { return }
        pendingLayout?.cancel()
        let update = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            self.pendingLayout = nil
            if self.isMapped { self.requestDashboard(layoutOnly: true) }
        }
        pendingLayout = update
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: update)
    }

    func receive(_ reply: [String: Any]) {
        if let next = reply["rows"] as? [[String: Any]] {
            if !NSArray(array: rows).isEqual(to: next) {
                let position = scroll.documentVisibleRect.origin
                rows = next
                cards = next.compactMap(makeCard)
                arrangeCards()
                view.layoutSubtreeIfNeeded()
                grid.scroll(position)
            }
        } else if reply["unchanged"] as? Bool != true {
            showNotice((reply["error"] ?? reply["notice"]) as? String ?? "")
            return
        }
        if reply["layout_only"] as? Bool != true {
            showNotice(rows.isEmpty ? "No chats have published a dashboard." : "")
        }
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
        if chartWidths != lastWidths { scheduleLayout(after: 0.08) }
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
            line.spacing = Self.cardSpacing
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
        card.boxType = .custom
        card.title = board["title"] as? String ?? ""
        card.titlePosition = .noTitle
        card.setAccessibilityLabel(card.title)
        card.isTransparent = false
        card.fillColor = cardSurface
        card.borderColor = .separatorColor
        card.borderWidth = Self.cardBorder
        card.cornerRadius = 10
        card.contentViewMargins = Self.cardMargins
        let content = NSStackView()
        content.orientation = .vertical
        content.alignment = .leading
        content.distribution = .fill
        content.spacing = 12
        let header = content.addSection(spacing: 2)
        header.addText(card.title, font: .systemFont(ofSize: 18, weight: .semibold))
        header.addText(row["chat"] as? String ?? "", font: .systemFont(ofSize: 12), color: .secondaryLabelColor)
        var previousMetric: NSView?
        for item in board["widgets"] as? [[String: Any]] ?? [] {
            let title = item["label"] as? String ?? ""
            let kind = item["kind"] as? String ?? ""
            let value = item["value"]
            let section = content.addSection()
            if kind == "metric", let previous = previousMetric { content.setCustomSpacing(4, after: previous) }
            previousMetric = kind == "metric" ? section : nil
            if kind == "link" {
                if let url = dashboardURL(value) {
                    let link = DashboardLink(title: title, url: url)
                    link.target = self
                    link.action = #selector(openLink(_:))
                    section.addArrangedSubview(link)
                    link.widthAnchor.constraint(lessThanOrEqualTo: section.widthAnchor).isActive = true
                } else {
                    section.addText(title)
                }
                continue
            }
            if kind == "button" {
                let button = DashboardButton(title: title, target: nil, action: #selector(DashboardButton.invoke))
                button.target = button
                button.cell?.lineBreakMode = .byTruncatingTail
                button.toolTip = value as? String
                button.fields = ["agent": row["agent"]!, "revision": row["revision"]!, "widget": item["id"]!]
                section.addArrangedSubview(button)
                button.widthAnchor.constraint(lessThanOrEqualTo: section.widthAnchor).isActive = true
                continue
            }
            let unit = item["unit"] as? String
            if kind == "metric" {
                var label = title[...]
                while let last = label.last, last.isWhitespace || last == ":" { label = label.dropLast() }
                section.addReading(String(label) + ":", dashboardReading(value as? NSNumber, unit: unit), metric: true)
                continue
            }
            if kind == "graph" {
                section.addReading(title, dashboardReading((value as? [NSNumber])?.last, unit: unit))
            } else if kind == "progress" || kind == "gauge" {
                section.addReading(title, dashboardReading(value as? NSNumber, unit: unit))
            } else {
                section.addText(title, font: .systemFont(ofSize: 13, weight: .semibold))
            }
            switch kind {
            case "graph", "bar", "pie", "radar", "scatter":
                let description = item["chart_description"] as? String ?? title
                // Only the supervisor supplies chart_svg. AppKit keeps its SVG representation scalable.
                if let svg = item["chart_svg"] as? String, let chart = NSImage(data: Data(svg.utf8)),
                   chart.size.width > 0, chart.size.height > 0 {
                    chart.cacheMode = .never
                    section.addImage(chart, description: description, chart: true)
                } else {
                    section.addText(item["chart_description"] as? String ?? "Chart unavailable")
                }
            case "image":
                if let image = dashboardRaster(value) {
                    section.addImage(image, description: title, chart: false)
                } else {
                    section.addText("Image unavailable")
                }
            case "progress":
                let bar = NSProgressIndicator()
                bar.style = .bar
                bar.isIndeterminate = false
                bar.controlSize = .small
                bar.minValue = (item["min"] as? NSNumber)?.doubleValue ?? 0
                bar.maxValue = (item["max"] as? NSNumber)?.doubleValue ?? 100
                bar.doubleValue = (value as? NSNumber)?.doubleValue ?? 0
                bar.setAccessibilityLabel(title)
                section.addArrangedSubview(bar)
                bar.widthAnchor.constraint(equalTo: section.widthAnchor).isActive = true
            case "gauge":
                let bar = NSLevelIndicator()
                bar.controlSize = .small
                bar.fillColor = .controlAccentColor
                bar.setAccessibilityLabel(title)
                bar.levelIndicatorStyle = .continuousCapacity
                bar.minValue = (item["min"] as? NSNumber)?.doubleValue ?? 0
                bar.maxValue = (item["max"] as? NSNumber)?.doubleValue ?? 100
                bar.doubleValue = (value as? NSNumber)?.doubleValue ?? 0
                section.addArrangedSubview(bar)
                bar.widthAnchor.constraint(equalTo: section.widthAnchor).isActive = true
            case "events":
                let entries = (value as? [String] ?? []).joined(separator: "\n")
                let style = NSMutableParagraphStyle()
                style.paragraphSpacing = 3
                let field = section.addText(entries)
                field.attributedStringValue = NSAttributedString(string: entries, attributes: [
                    .paragraphStyle: style, .font: NSFont.systemFont(ofSize: 12), .foregroundColor: NSColor.labelColor,
                ])
            default:
                section.addText(value as? String ?? "")
            }
        }
        // Keep controls at their natural height, grouped at the top of a tall card.
        let spacer = NSView()
        if let last = content.arrangedSubviews.last { content.setCustomSpacing(0, after: last) }
        content.addArrangedSubview(spacer)
        card.contentView = content
        card.heightAnchor.constraint(greaterThanOrEqualToConstant: 160).isActive = true
        return card
    }
}
