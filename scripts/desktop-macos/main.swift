// Compile alongside the production AppKit delegate in a logged-in Aqua session.
import AppKit

func require(_ condition: Bool, _ name: String) {
    if !condition {
        FileHandle.standardError.write(Data(("FAIL: " + name + "\n").utf8))
        exit(1)
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let desktop = Desktop(iconPath: CommandLine.arguments[1], openAtLaunch: false)
app.delegate = desktop
// The pipe stays open so the UI has the same lifetime as a normal Gent child.
let lifetime = Pipe()
dup2(lifetime.fileHandleForReading.fileDescriptor, STDIN_FILENO)
DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
    require(desktop.statusItem.isVisible && desktop.statusItem.button?.image != nil, "visible menu-bar item and image")
    require(!desktop.window.isVisible, "starts in tray")
    let menu = desktop.statusItem.menu!
    guard let open = menu.item(withTitle: "Open Gent Desktop"), let action = open.action else {
        require(false, "Open menu item")
        return
    }
    require(app.sendAction(action, to: open.target, from: open), "open through actual menu target")
    require(desktop.window.isVisible && desktop.window.windowNumber > 0, "ordered AppKit window")
    desktop.receive(["node":"desktop-test", "cluster":"Local fixture", "running":true,
                     "state":"Running", "sync":"idle", "queue":0, "chats":2,
                     "can_stop":true, "peers":[["name":"fixture-peer","state":"matched","route":"Direct QUIC"]]])
    require(desktop.node.stringValue == "desktop-test" && desktop.table.numberOfRows == 1, "model displayed")
    require(desktop.toggle.title == "Stop daemon" && desktop.toggle.isEnabled, "service controls")
    require(desktop.trayState.title == "Daemon running", "tray status")
    require(desktop.tabs.tabViewItems.map { $0.label } == ["Overview","Chats","Nodes","Settings"], "four native tabs")
    desktop.tabs.selectTabViewItem(at: 1)
    desktop.receive(["page":"chats","rows":[["name":"Remote chat","node":"Other node","provider":"codex","state":"Registered","id":"c"]]])
    require(desktop.chats.table.numberOfRows == 1, "cluster chat rendered")
    desktop.tabs.selectTabViewItem(at: 2)
    desktop.receive(["page":"nodes","rows":[["name":"Hosted","state":"hosted","role":"Admin","host":"Fixture","id":"n"]]])
    require(desktop.nodes.table.numberOfRows == 1, "hosted node rendered")
    desktop.tabs.selectTabViewItem(at: 3)
    desktop.receive(["page":"settings","values":["updates":true, "discovery":false]])
    desktop.settings.openEditor()
    desktop.receive(["page":"settings","document":"fixture = true"])
    require(!desktop.settings.text.isHiddenOrHasHiddenAncestor && desktop.settings.text.string == "fixture = true", "editable configuration")
    desktop.settings.text.string = "fixture = false"
    desktop.settings.saveLocal()
    desktop.receive(["page":"settings","error":"concurrent edit"])
    require(desktop.settings.text.string == "fixture = false" && desktop.settings.text.isEditable, "failed save preserves draft")
    desktop.settings.saveLocal()
    desktop.receive(["page":"settings","saved":true,"values":["updates":true]])
    require(desktop.settings.text.isHiddenOrHasHiddenAncestor, "successful save returns to settings")
    desktop.window.performClose(nil)
    require(!desktop.window.isVisible && desktop.statusItem.isVisible, "closes to tray")
    require(app.sendAction(action, to: open.target, from: open) && desktop.window.isVisible, "menu reopens window")
    guard let quit = menu.item(withTitle: "Quit Gent Desktop"), let stop = quit.action else {
        require(false, "Quit menu item")
        return
    }
    FileHandle.standardError.write(Data("PASS: AppKit menu bar, overview, chats, nodes, editable settings, close, reopen and quit\n".utf8))
    _ = app.sendAction(stop, to: quit.target, from: quit)
}
app.run()
