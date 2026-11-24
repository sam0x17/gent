import AppKit
import CoreServices
import Security
import UserNotifications

// Finder and Notification Center may launch an app without a supervisor.
let args = CommandLine.arguments
guard args.count == 3, ["tray", "window", "setup"].contains(args[2]),
      Bundle.main.bundleIdentifier == "link.gent.notifications" else { exit(0) }
var session = SessionAttributeBits()
guard SessionGetInfo(callerSecuritySession, nil, &session) == errSecSuccess,
      session.contains(.sessionHasGraphicAccess) else { exit(1) }

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
// This profile-local app may be outside the directories indexed by Launch Services.
if LSRegisterURL(Bundle.main.bundleURL as CFURL, true) == noErr {
    let center = UNUserNotificationCenter.current()
    center.delegate = presentation
    desktop.useNotificationCenter(center)
} else {
    desktop.useNotificationCenter(nil)
}
app.delegate = desktop
app.run()
