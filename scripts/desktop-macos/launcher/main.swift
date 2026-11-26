// Exercise Finder's handoff without invoking Launch Services or a notification center.
import AppKit

precondition(DesktopLauncher.isUserLaunch([NSApplication.launchIsDefaultUserInfoKey: true]))
precondition(!DesktopLauncher.isUserLaunch([NSApplication.launchIsDefaultUserInfoKey: false]))
precondition(!DesktopLauncher.isUserLaunch([NSApplication.launchUserNotificationUserInfoKey: NSObject()]))

do {
    try DesktopLauncher.openDesktop(userHome: URL(fileURLWithPath: CommandLine.arguments[1]))
} catch {
    exit(1)
}
