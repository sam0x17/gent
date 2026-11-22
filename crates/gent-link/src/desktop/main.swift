import AppKit

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let desktop = Desktop(iconPath: CommandLine.arguments[1], openAtLaunch: CommandLine.arguments[2] == "window")
app.delegate = desktop
app.run()
