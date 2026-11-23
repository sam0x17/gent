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

private final class DashboardGrid: NSStackView {
    override var isFlipped: Bool { true }
}

final class DashboardTab: NSObject {
    let view = NSStackView()
    private let grid = DashboardGrid()
    private let scroll = NSScrollView()
    private let notice = NSTextField(wrappingLabelWithString: "")
    private var rows: [[String:Any]] = []
    private var columns = 0
    private var viewportColumns: Int { max(1, min(4, Int(scroll.contentSize.width / 280))) }
    override init() {
        super.init()
        view.orientation = .vertical
        view.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        grid.orientation = .vertical
        grid.alignment = .leading
        scroll.hasVerticalScroller = true
        scroll.documentView = grid
        grid.translatesAutoresizingMaskIntoConstraints = false
        let clip = scroll.contentView
        NSLayoutConstraint.activate([
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
    func receive(_ reply: [String:Any]) {
        guard let next = reply["rows"] as? [[String:Any]] else {
            notice.stringValue = (reply["error"] ?? reply["notice"]) as? String ?? ""
            return
        }
        if columns == 0 || !NSArray(array:rows).isEqual(to:next) {
            rows = next
            notice.stringValue = ""
            render()
        }
        if rows.isEmpty { notice.stringValue = "No chats have published a dashboard." }
    }
    @objc private func resized() {
        if viewportColumns != columns { render() }
    }
    private func render() {
        columns = viewportColumns
        grid.arrangedSubviews.forEach { grid.removeArrangedSubview($0); $0.removeFromSuperview() }
        var line = NSStackView()
        for (i,row) in rows.enumerated() {
            guard let board = row["board"] as? [String:Any] else { continue }
            if i % columns == 0 {
                line = NSStackView()
                line.alignment = .top
                grid.addArrangedSubview(line)
            }
            let card = NSBox()
            card.title = board["title"] as? String ?? ""
            let content = NSStackView()
            content.orientation = .vertical
            content.alignment = .leading
            func addText(_ value:String) {
                let field = NSTextField(wrappingLabelWithString:value)
                field.isSelectable = true
                content.addArrangedSubview(field)
                field.widthAnchor.constraint(lessThanOrEqualTo:content.widthAnchor).isActive = true
            }
            addText(row["chat"] as? String ?? "")
            for item in board["widgets"] as? [[String:Any]] ?? [] {
                let title = item["label"] as? String ?? ""
                let kind = item["kind"] as? String ?? ""
                let value = item["value"]
                if kind == "button" {
                    let button = DashboardButton(title:title,target:nil,action:#selector(DashboardButton.invoke))
                    button.target = button
                    button.toolTip = value as? String
                    button.fields = ["agent":row["agent"]!, "revision":row["revision"]!, "widget":item["id"]!]
                    content.addArrangedSubview(button)
                    continue
                }
                addText(title)
                let unit = (item["unit"] as? String).map { " " + $0 } ?? ""
                if kind == "graph" {
                    let plot = Plot()
                    plot.samples = value as? [Double] ?? []
                    content.addArrangedSubview(plot)
                    plot.heightAnchor.constraint(equalToConstant:48).isActive = true
                    plot.widthAnchor.constraint(equalTo:content.widthAnchor).isActive = true
                    addText(plot.samples.last.map { String($0) + unit } ?? "—")
                } else if kind == "progress" || kind == "gauge" {
                    let bar = NSLevelIndicator()
                    bar.levelIndicatorStyle = .continuousCapacity
                    bar.minValue = item["min"] as? Double ?? 0
                    bar.maxValue = item["max"] as? Double ?? 100
                    bar.doubleValue = value as? Double ?? 0
                    content.addArrangedSubview(bar)
                    bar.widthAnchor.constraint(equalTo:content.widthAnchor).isActive = true
                    addText(String(bar.doubleValue) + unit)
                } else {
                    addText((value as? [String])?.joined(separator:"\n") ?? value as? String ?? "")
                }
            }
            card.contentView = content
            line.addArrangedSubview(card)
            // A partial last row uses the same column width as a full row.
            let gaps = line.spacing * CGFloat(columns - 1)
            card.widthAnchor.constraint(equalTo: grid.widthAnchor, multiplier: 1 / CGFloat(columns),
                                        constant: -gaps / CGFloat(columns)).isActive = true
        }
    }
}
