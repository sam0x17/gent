import AppKit
import WebKit
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

    func addWrappingText(_ value: String, font: NSFont, color: NSColor = .labelColor) {
        let field = addText(value, font: font, color: color)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.required, for: .vertical)
        field.widthAnchor.constraint(equalTo: widthAnchor).isActive = true
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

// Reflow only this section when its board is resized or shares a gallery row.
private final class DashboardColumns: NSStackView {
    private let items: [NSView]
    private let minimumWidth: CGFloat
    private let alignHeights: Bool
    private var continuation: (original: NSStackView, column: NSStackView, rows: [NSView])?
    private var columns = 0
    private static let gap: CGFloat = 8

    init(_ items: [NSView], minimumWidth: CGFloat, alignHeights: Bool = false) {
        self.items = items
        self.minimumWidth = minimumWidth
        self.alignHeights = alignHeights
        super.init(frame: .zero)
        orientation = .vertical
        alignment = .leading
        spacing = Self.gap
        arrange(1)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }

    convenience init(left: [String: Any], right: [String: Any]) {
        let leftRows = left["value"] as? [String] ?? []
        let rightRows = right["value"] as? [String] ?? []
        let label = right["label"] as? String ?? ""
        let original = dashboardFeed(label, entries: rightRows)
        self.init([dashboardFeed(left["label"] as? String ?? "", entries: leftRows), original], minimumWidth: 295)
        if rightRows.count >= max(4, 2 * leftRows.count) {
            continuation = (original, dashboardFeed(label + " (continued)", entries: []),
                            Array(original.arrangedSubviews.suffix(rightRows.count / 2)))
        }
    }

    private var fittingColumns: Int {
        let maximum = items.count + (continuation == nil ? 0 : 1)
        return max(1, min(maximum, Int((bounds.width + Self.gap) / (minimumWidth + Self.gap))))
    }

    override func setFrameSize(_ size: NSSize) {
        super.setFrameSize(size)
        if fittingColumns != columns {
            // AppKit can assign intermediate widths during constraint solving.
            DispatchQueue.main.async { [weak self] in
                guard let self, fittingColumns != columns else { return }
                arrange(fittingColumns)
            }
        }
    }

    private func arrange(_ count: Int) {
        guard continuation != nil, (columns == 3) != (count == 3),
              let window, let editor = window.firstResponder as? NSTextView, editor.isFieldEditor,
              let field = editor.delegate as? NSTextField, field.isDescendant(of: self),
              field.currentEditor() === editor else {
            layoutColumns(count)
            return
        }
        // Removing the row ends field editing even though its NSTextField is reused.
        let ranges = editor.selectedRanges, affinity = editor.selectionAffinity
        layoutColumns(count)
        guard field.window === window else { return }
        if field.currentEditor() == nil {
            guard window.firstResponder == nil || window.firstResponder === window else { return }
            field.selectText(nil)
        }
        if field.currentEditor() === editor {
            editor.setSelectedRanges(ranges, affinity: affinity, stillSelecting: false)
        }
    }

    private func layoutColumns(_ count: Int) {
        columns = count
        arrangedSubviews.forEach { $0.removeFromSuperview() }
        var visible = items
        if let continuation {
            let split = count == 3
            let target = split ? continuation.column : continuation.original
            for field in continuation.rows where field.superview !== target {
                field.removeFromSuperview()
                target.addArrangedSubview(field)
                field.widthAnchor.constraint(equalTo: target.widthAnchor).isActive = true
            }
            if split { visible.append(continuation.column) }
        }
        for start in stride(from: 0, to: visible.count, by: count) {
            let row = NSStackView()
            row.orientation = .horizontal
            row.alignment = .top
            row.spacing = Self.gap
            addArrangedSubview(row)
            let fraction = 1 / CGFloat(count)
            for item in visible[start..<min(start + count, visible.count)] {
                row.addArrangedSubview(item)
                item.widthAnchor.constraint(equalTo: widthAnchor, multiplier: fraction,
                                            constant: -Self.gap * (1 - fraction)).isActive = true
                if alignHeights { item.heightAnchor.constraint(equalTo: row.heightAnchor).isActive = true }
            }
        }
    }
}

private func dashboardLane(_ lane: [String: Any]) -> NSBox {
    let label = lane["label"] as? String ?? ""
    let state = lane["state"] as? String ?? ""
    let tone: NSColor
    switch lane["tone"] as? String {
    case "info": tone = .systemBlue
    case "success": tone = .systemGreen
    case "warning": tone = .systemOrange
    case "critical": tone = .systemRed
    default: tone = .secondaryLabelColor
    }
    let card = NSBox()
    card.boxType = .custom
    card.titlePosition = .noTitle
    card.fillColor = .windowBackgroundColor
    card.borderColor = .separatorColor
    card.borderWidth = 1
    card.cornerRadius = 6
    card.contentViewMargins = NSSize(width: 10, height: 8)
    card.setAccessibilityLabel(label)
    let body = NSStackView()
    body.orientation = .vertical
    body.alignment = .leading
    body.spacing = 3
    card.contentView = body
    body.addWrappingText(label, font: .systemFont(ofSize: 13, weight: .semibold))
    let status = NSStackView()
    status.alignment = .centerY
    status.spacing = 5
    body.addArrangedSubview(status)
    status.widthAnchor.constraint(equalTo: body.widthAnchor).isActive = true
    let dot = NSBox()
    dot.boxType = .custom
    dot.titlePosition = .noTitle
    dot.borderWidth = 0
    dot.cornerRadius = 3
    dot.fillColor = tone
    dot.setAccessibilityElement(false)
    status.addArrangedSubview(dot)
    dot.widthAnchor.constraint(equalToConstant: 6).isActive = true
    dot.heightAnchor.constraint(equalToConstant: 6).isActive = true
    let statusText = status.addText(state, font: .systemFont(ofSize: 12, weight: .medium))
    statusText.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
    statusText.setContentHuggingPriority(.defaultLow, for: .horizontal)
    body.setCustomSpacing(6, after: status)
    for detail in lane["details"] as? [String] ?? [] {
        body.addWrappingText(detail, font: .monospacedDigitSystemFont(ofSize: 12, weight: .regular),
                             color: .secondaryLabelColor)
    }
    return card
}

private func dashboardFeed(_ label: String, entries: [String]) -> NSStackView {
    let feed = NSStackView()
    feed.orientation = .vertical
    feed.alignment = .leading
    feed.spacing = 5
    feed.setAccessibilityElement(true)
    feed.setAccessibilityRole(.group)
    feed.setAccessibilityLabel(label)
    feed.addWrappingText(label, font: .systemFont(ofSize: 13, weight: .semibold))
    let rule = NSBox()
    rule.boxType = .separator
    feed.addArrangedSubview(rule)
    rule.widthAnchor.constraint(equalTo: feed.widthAnchor).isActive = true
    for entry in entries {
        feed.addWrappingText(entry, font: .monospacedDigitSystemFont(ofSize: 12, weight: .regular))
    }
    return feed
}

// The preview has one in-memory document and no file or network origin.
private final class DashboardDocument: NSObject, WKURLSchemeHandler {
    static let url = URL(string: "gent-board://local/preview")!
    private let bytes: Data
    init(_ html: String) { bytes = Data(html.utf8) }

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        guard task.request.url == Self.url else {
            task.didFailWithError(URLError(.unsupportedURL))
            return
        }
        let headers = ["Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
                       "X-DNS-Prefetch-Control": "off",
                       "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"]
        task.didReceive(HTTPURLResponse(url: Self.url, statusCode: 200, httpVersion: nil, headerFields: headers)!)
        task.didReceive(bytes)
        task.didFinish()
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {}
}

private final class DashboardPreview: WKWebView, WKNavigationDelegate, WKUIDelegate {
    private var initialLoad = true
    var displayPreview: ((Bool) -> Void)?

    init(_ html: String) {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        config.defaultWebpagePreferences.allowsContentJavaScript = false
        config.preferences.javaScriptCanOpenWindowsAutomatically = false
        config.setURLSchemeHandler(DashboardDocument(html), forURLScheme: "gent-board")
        super.init(frame: .zero, configuration: config)
        navigationDelegate = self
        uiDelegate = self
        allowsLinkPreview = false
        isHidden = true
        // Install a subresource block before loading any private HTML. Only the invariant rule is compiled.
        let rules = #"[{"trigger":{"url-filter":".*"},"action":{"type":"block"}},{"trigger":{"url-filter":"^gent-board://local/preview$"},"action":{"type":"ignore-previous-rules"}}]"#
        WKContentRuleListStore.default().compileContentRuleList(forIdentifier: "GentStaticBoard-v1", encodedContentRuleList: rules) { [weak self] list, _ in
            guard let self, let list else { return }
            configuration.userContentController.add(list)
            load(URLRequest(url: DashboardDocument.url))
        }
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        let allow = initialLoad && action.navigationType == .other && action.targetFrame?.isMainFrame == true
            && action.request.url == DashboardDocument.url
        if allow { initialLoad = false }
        decisionHandler(allow ? .allow : .cancel)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        displayPreview?(webView.url == DashboardDocument.url)
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { displayPreview?(false) }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) { displayPreview?(false) }

    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters, initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping ([URL]?) -> Void) { completionHandler(nil) }

    override func willOpenMenu(_ menu: NSMenu, with event: NSEvent) {
        menu.removeAllItems()
        menu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "")
        menu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "")
    }
}

private final class DashboardPreviewCard: NSBox {
    let publisher: String
    let revision: Int
    let chat: String
    let html: String

    private var viewportFit: NSLayoutConstraint?
    var previewReady = false {
        didSet { viewportFit?.isActive = previewReady }
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        viewportFit?.isActive = false
        viewportFit = nil
        guard window != nil, let clip = enclosingScrollView?.contentView else { return }
        // Fit the whole ready card. The document uses the space below its actual heading.
        let fit = heightAnchor.constraint(equalTo: clip.heightAnchor)
        fit.priority = .defaultHigh
        fit.isActive = previewReady
        viewportFit = fit
    }

    init(_ row: [String: Any], html: String) {
        publisher = row["agent"] as? String ?? ""
        revision = row["revision"] as? Int ?? 0
        chat = row["chat"] as? String ?? ""
        self.html = html
        super.init(frame: .zero)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }
}

final class DashboardTab: NSObject {
    let view = NSStackView()
    private let grid = DashboardGrid()
    private let scroll = NSScrollView()
    private let notice = NSTextField(wrappingLabelWithString: "")
    private var showingFeedback = false
    private lazy var restore = NSButton(title: "Restore hidden dashboards", target: self, action: #selector(chooseDashboard(_:)))
    private lazy var pricing = NSButton(title: "View Gent plans", target: self, action: #selector(openPricing))
    @objc private func openPricing() { openURL(URL(string: "https://gent.link/pricing")!) }
    var openURL: (URL) -> Void = { url in _ = NSWorkspace.shared.open(url) }
    var accentColor: () -> NSColor = { .controlAccentColor }
    private var lastPalette: [String: [Int]]?
    private var lastWidths: [Int] = []
    private var pendingLayout: DispatchWorkItem?
    private var rows: [[String: Any]]?
    private var hidden: [[String: String]] = []
    private var example: [String: Any]?
    private var allHidden = false
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
        restore.isBordered = false
        restore.controlSize = .small
        restore.attributedTitle = NSAttributedString(string: restore.title, attributes: [
            .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
            .foregroundColor: NSColor.linkColor,
            .underlineStyle: NSUnderlineStyle.single.rawValue,
        ])
        restore.setAccessibilityRole(.link)
        restore.isHidden = true
        view.addArrangedSubview(restore)
        pricing.isHidden = true
        view.addArrangedSubview(pricing)
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

    private var displayedRows: [[String: Any]] {
        if let example, !showingFeedback { return [example] }
        return rows ?? []
    }

    func receive(_ reply: [String: Any]) {
        let previous = displayedRows
        let wasExample = example != nil && !showingFeedback
        let locked = reply["pro_required"] as? Bool == true
        if let next: [[String: Any]] = locked ? [] : reply["rows"] as? [[String: Any]] {
            allHidden = reply["all_hidden"] as? Bool == true
            rows = next
            example = next.isEmpty ? reply["example"] as? [String: Any] : nil
        }
        pricing.isHidden = !locked
        if locked {
            setHidden([])
            showingFeedback = false
            showNotice("Dashboards require an active Gent Pro plan for this cluster.")
        } else {
            if let next = reply["hidden"] as? [[String: String]] { setHidden(next) }
            if let message = (reply["error"] ?? reply["notice"]) as? String {
                showingFeedback = true
                showNotice(message)
            } else if !showingFeedback || (reply["layout_only"] as? Bool != true && reply["stale"] as? Bool != true) {
                showingFeedback = false
                let empty = allHidden ? "All dashboards are hidden." : "No chats have published a dashboard."
                showNotice(rows?.isEmpty == true ? empty : "")
            }
        }
        let displayed = displayedRows
        if !NSArray(array: previous).isEqual(to: displayed) {
            let position = scroll.documentVisibleRect.origin
            updateCards(displayed.compactMap(makeCard))
            view.layoutSubtreeIfNeeded()
            grid.scroll(example != nil && !wasExample && !showingFeedback ? .zero : position)
        }
    }

    private func setHidden(_ next: [[String: String]]) {
        guard hidden != next else { return }
        hidden = next
        restore.menu?.cancelTracking()
        let menu = NSMenu()
        let choices = next.compactMap { board -> (agent: String, label: String)? in
            guard let agent = board["agent"], let title = board["title"], let chat = board["chat"] else { return nil }
            return (agent, "\(title) — \(chat)")
        }
        let groups = Dictionary(grouping: choices, by: { $0.label })
        for choice in choices {
            let duplicate = (groups[choice.label]?.count ?? 0) > 1
            let label = duplicate ? "\(choice.label) (\(choice.agent))" : choice.label
            let item = menu.addItem(withTitle: label, action: #selector(restoreDashboard(_:)), keyEquivalent: "")
            item.representedObject = choice.agent
            item.target = self
        }
        restore.menu = menu.items.isEmpty ? nil : menu
        restore.isHidden = menu.items.isEmpty
    }

    @objc private func chooseDashboard(_ button: NSButton) {
        button.menu?.popUp(positioning: nil, at: NSPoint(x: button.bounds.minX, y: button.bounds.minY), in: button)
    }

    @objc private func restoreDashboard(_ item: NSMenuItem) {
        guard let menu = restore.menu, item.menu === menu, let agent = item.representedObject as? String else { return }
        sendPage("dashboard_restore", ["agent": agent])
    }

    @objc private func hideDashboard(_ button: NSButton) {
        guard let agent = button.cell?.representedObject as? String else { return }
        sendPage("dashboard_hide", ["agent": agent])
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

    private func updateCards(_ updated: [NSBox]) {
        let previous = cards
        cards = updated
        // Only replace siblings in place if a retained card can stay in its original slot.
        // Removing a web view from the window would discard its first responder.
        let slots = zip(previous, updated)
        guard updated.count == previous.count, slots.contains(where: { $0 === $1 }),
              slots.allSatisfy({ $0 === $1 || $1.superview == nil }) else {
            arrangeCards()
            return
        }
        for (index, card) in updated.enumerated() where card !== previous[index] {
            let line = grid.arrangedSubviews[index / columns] as! NSStackView
            line.removeArrangedSubview(previous[index])
            previous[index].removeFromSuperview()
            line.insertArrangedSubview(card, at: index % columns)
            card.heightAnchor.constraint(equalTo: line.heightAnchor).isActive = true
        }
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
        let card: NSBox
        if let html = board["static_html"] as? String, !html.isEmpty {
            if let cached = cards.compactMap({ $0 as? DashboardPreviewCard }).first(where: {
                $0.publisher == row["agent"] as? String && $0.revision == row["revision"] as? Int
                    && $0.chat == row["chat"] as? String && $0.title == board["title"] as? String && $0.html == html
            }) { return cached }
            card = DashboardPreviewCard(row, html: html)
        } else {
            card = NSBox()
        }
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
        let heading = NSStackView()
        heading.alignment = .top
        heading.distribution = .fill
        heading.spacing = 6
        header.addArrangedSubview(heading)
        heading.widthAnchor.constraint(equalTo: header.widthAnchor).isActive = true
        let title = heading.addText(card.title, font: .systemFont(ofSize: 18, weight: .semibold))
        title.setContentHuggingPriority(.defaultLow, for: .horizontal)
        title.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        if let agent = row["agent"] as? String {
            let hide = NSButton(title: "×", target: self, action: #selector(hideDashboard(_:)))
            hide.isBordered = false
            hide.font = .systemFont(ofSize: 16)
            hide.toolTip = "Hide dashboard"
            hide.setAccessibilityLabel("Hide dashboard")
            hide.cell?.representedObject = agent
            heading.addArrangedSubview(hide)
            hide.widthAnchor.constraint(equalToConstant: 24).isActive = true
            hide.heightAnchor.constraint(equalToConstant: 24).isActive = true
        }
        let byline = header.addText(row["chat"] as? String ?? "", font: .systemFont(ofSize: 12), color: .secondaryLabelColor)
        var previousMetric: NSView?
        func addWidget(_ item: [String: Any]) {
            let title = item["label"] as? String ?? ""
            let kind = item["kind"] as? String ?? ""
            let value = item["value"]
            if (kind == "button" || kind == "link") && row["agent"] == nil { return }
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
                return
            }
            if kind == "button" {
                let button = DashboardButton(title: title, target: nil, action: #selector(DashboardButton.invoke))
                button.target = button
                button.cell?.lineBreakMode = .byTruncatingTail
                button.toolTip = value as? String
                button.fields = ["agent": row["agent"]!, "revision": row["revision"]!, "widget": item["id"]!]
                section.addArrangedSubview(button)
                button.widthAnchor.constraint(lessThanOrEqualTo: section.widthAnchor).isActive = true
                return
            }
            let unit = item["unit"] as? String
            if kind == "metric" {
                var label = title[...]
                while let last = label.last, last.isWhitespace || last == ":" { label = label.dropLast() }
                section.addReading(String(label) + ":", dashboardReading(value as? NSNumber, unit: unit), metric: true)
                return
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
        let widgets = board["widgets"] as? [[String: Any]] ?? []
        if let layout = board["layout_v1"] as? [Any] {
            for part in layout {
                if let index = part as? Int, widgets.indices.contains(index) {
                    addWidget(widgets[index])
                    continue
                }
                let group = part as? [String: Any]
                let columns: DashboardColumns
                if let lanes = group?["lanes"] as? [[String: Any]], !lanes.isEmpty {
                    columns = DashboardColumns(lanes.map(dashboardLane), minimumWidth: 140, alignHeights: true)
                } else if let feeds = group?["feeds"] as? [Int], feeds.count == 2,
                          feeds.allSatisfy({ widgets.indices.contains($0) && widgets[$0]["kind"] as? String == "events" }) {
                    columns = DashboardColumns(left: widgets[feeds[0]], right: widgets[feeds[1]])
                } else {
                    continue
                }
                previousMetric = nil
                content.addArrangedSubview(columns)
                columns.widthAnchor.constraint(equalTo: content.widthAnchor).isActive = true
            }
        } else {
            widgets.forEach(addWidget)
        }
        // Keep controls at their natural height, grouped at the top of a tall card.
        let spacer = NSView()
        if let last = content.arrangedSubviews.last { content.setCustomSpacing(0, after: last) }
        content.addArrangedSubview(spacer)
        if let previewCard = card as? DashboardPreviewCard {
            let native = Array(content.arrangedSubviews.dropFirst())
            let preview = DashboardPreview(previewCard.html)
            content.addArrangedSubview(preview)
            preview.widthAnchor.constraint(equalTo: content.widthAnchor).isActive = true
            // The web document scrolls inside its card while the board header remains available.
            preview.heightAnchor.constraint(greaterThanOrEqualToConstant: 220).isActive = true
            let compactHeight = header.heightAnchor.constraint(equalToConstant: 24)
            let publisher = byline.stringValue.isEmpty ? nil : "Published by \(byline.stringValue)"
            let fullTitle = [previewCard.title, publisher].compactMap { $0 }.joined(separator: ". ")
            preview.displayPreview = { [weak previewCard, weak preview, weak content] ready in
                guard let previewCard, previewCard.previewReady != ready else { return }
                previewCard.previewReady = ready
                compactHeight.isActive = ready
                byline.isHidden = ready
                title.maximumNumberOfLines = ready ? 1 : 0
                title.lineBreakMode = ready ? .byTruncatingTail : .byWordWrapping
                title.toolTip = ready ? fullTitle : nil
                title.setAccessibilityHelp(ready ? publisher : nil)
                title.setAccessibilityLabel(ready ? fullTitle : nil)
                previewCard.contentViewMargins = ready ? NSSize(width: Self.cardMargins.width, height: 6) : Self.cardMargins
                content?.spacing = ready ? 4 : 12
                native.forEach { $0.isHidden = ready }
                preview?.isHidden = !ready
            }
        }
        card.contentView = content
        card.heightAnchor.constraint(greaterThanOrEqualToConstant: 160).isActive = true
        return card
    }
}
