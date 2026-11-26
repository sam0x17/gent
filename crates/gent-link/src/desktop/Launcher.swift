// A Finder launch hands off to the same Rust supervisor as `gent desktop`.
import AppKit

private struct DesktopLaunch: Decodable {
    let binary: String
    let home: String
}

final class DesktopLauncher: NSObject, NSApplicationDelegate {
    private let graphical: Bool

    init(graphical: Bool) { self.graphical = graphical }

    static func openDesktop(userHome: URL) throws {
        let file = userHome.appendingPathComponent("Library/Application Support/Gent/desktop-launch.json")
        let fd = open(file.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw CocoaError(.fileReadNoPermission) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid(),
              info.st_nlink == 1, info.st_mode & 0o077 == 0 else { throw CocoaError(.fileReadNoPermission) }
        let data = try handle.read(upToCount: 16385) ?? Data()
        guard data.count <= 16384 else { throw CocoaError(.fileReadCorruptFile) }
        let binding = try JSONDecoder().decode(DesktopLaunch.self, from: data)
        guard [binding.binary, binding.home].allSatisfy({ $0.hasPrefix("/") && !$0.contains("\0") })
        else { throw CocoaError(.fileReadCorruptFile) }

        let child = Process()
        child.executableURL = URL(fileURLWithPath: binding.binary)
        child.arguments = ["--home", binding.home, "desktop"]
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        try child.run()
    }

    static func isUserLaunch(_ info: [AnyHashable: Any]?) -> Bool {
        // A service or notification activation can launch the same executable.
        info?[NSApplication.launchUserNotificationUserInfoKey] == nil &&
            info?[NSApplication.launchIsDefaultUserInfoKey] as? Bool != false
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if Self.isUserLaunch(notification.userInfo) {
            do {
                let home = ProcessInfo.processInfo.environment["HOME"].map { URL(fileURLWithPath: $0) }
                    ?? FileManager.default.homeDirectoryForCurrentUser
                try Self.openDesktop(userHome: home)
            } catch {
                let message = "Run gent desktop in Terminal to reconnect this app to your Gent installation."
                if graphical {
                    let alert = NSAlert()
                    alert.messageText = "Gent Desktop couldn’t open"
                    alert.informativeText = message
                    NSApp.activate(ignoringOtherApps: true)
                    alert.runModal()
                } else {
                    FileHandle.standardError.write(Data((message + "\n").utf8))
                }
                exit(1)
            }
        }
        NSApp.terminate(nil)
    }
}
