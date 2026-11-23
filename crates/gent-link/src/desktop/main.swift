import AppKit

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let desktop = Desktop(iconPath: CommandLine.arguments[1], openAtLaunch: CommandLine.arguments[2] != "tray")
app.delegate = desktop
app.run()
