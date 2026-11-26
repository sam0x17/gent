import AppKit
import CoreServices
import Security
import UserNotifications

// Finder and Notification Center may launch an app without a supervisor.
let args = CommandLine.arguments
guard Bundle.main.bundleIdentifier == "link.gent.notifications" else { exit(0) }
let flags = args.dropFirst(3)
let launchedByServices = flags.contains("--launch-services")
let diagnose = flags.contains("--notification-diagnostics")
var session = SessionAttributeBits()
let sessionStatus = SessionGetInfo(callerSecuritySession, nil, &session)
let graphical = sessionStatus == errSecSuccess && session.contains(.sessionHasGraphicAccess)
if args.count == 1 || (args.count == 2 && args[1].hasPrefix("-psn_")) {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let launcher = DesktopLauncher(graphical: graphical)
    app.delegate = launcher
    withExtendedLifetime(launcher) { app.run() }
    exit(0)
}
guard args.count >= 3, ["tray", "window", "setup"].contains(args[2]),
      flags.allSatisfy({ ["--launch-services", "--notification-diagnostics"].contains($0) }) else { exit(0) }
guard graphical else {
    if diagnose { sendPage("notification_diagnostic", ["stage": "no_gui", "code": sessionStatus]) }
    exit(1)
}
if launchedByServices || diagnose {
    FileHandle.standardOutput.write(Data("gent-desktop-ready\n".utf8))
}

final class Presentation: NSObject, UNUserNotificationCenterDelegate {
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler reply: @escaping (UNNotificationPresentationOptions) -> Void) {
        reply([.banner, .list])
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let desktop = Desktop(iconPath: args[1], openAtLaunch: args[2] != "tray")
let presentation = Presentation()
// A Launch Services launch has already registered this exact app. Keep direct
// registration for the comparison fixture.
let registration = launchedByServices ? nil : LSRegisterURL(Bundle.main.bundleURL as CFURL, true)
if diagnose {
    let current = Bundle.main.bundleURL.resolvingSymlinksInPath()
    let preferred = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "link.gent.notifications")?.resolvingSymlinksInPath()
    var fields: [String: Any] = ["stage": "lookup", "preferred": preferred == nil ? "missing" : preferred == current ? "same" : "other",
                                 "translocated": current.pathComponents.contains("AppTranslocation")]
    if let registration = registration { fields["code"] = registration }
    sendPage("notification_diagnostic", fields)
}
if registration == nil || registration == noErr {
    let center = UNUserNotificationCenter.current()
    center.delegate = presentation
    desktop.useNotificationCenter(center)
} else {
    desktop.useNotificationCenter(nil)
}
app.delegate = desktop
app.run()
