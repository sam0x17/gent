import AppKit
import UserNotifications

// A Notification Center click may relaunch this accessory without a delivery.
guard CommandLine.arguments.dropFirst().contains("--deliver"),
      Bundle.main.bundleIdentifier == "link.gent.notifications",
      let banner = try? JSONDecoder().decode(Banner.self, from: FileHandle.standardInput.readDataToEndOfFile())
else { exit(1) }

final class Sender: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    let banner: Banner

    init(banner: Banner) { self.banner = banner }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        banner.submit(to: center) { [banner] accepted in
            if accepted {
                FileHandle.standardOutput.write(Data(banner.id.uuidString.lowercased().utf8))
            }
            DispatchQueue.main.async { NSApp.terminate(nil) }
        }
        // The OS may never answer, including when the permission prompt is ignored.
        DispatchQueue.main.asyncAfter(deadline: .now() + 120) { NSApp.terminate(nil) }
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler reply: @escaping (UNNotificationPresentationOptions) -> Void) {
        reply([.banner, .list])
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let sender = Sender(banner: banner)
app.delegate = sender
app.run()
