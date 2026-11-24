// Exercise the production authorization/submission sequence without opening a
// notification center, requesting OS permission, or displaying a banner.
import AppKit
import ImageIO
import UserNotifications

final class Center: NotificationCenterClient {
    let status: UNAuthorizationStatus
    var permission: (@Sendable (Bool, Error?) -> Void)?
    var added: (@Sendable (Error?) -> Void)?
    var deliveredID: String?
    var request: UNNotificationRequest?

    init(_ status: UNAuthorizationStatus) { self.status = status }

    func wasDelivered(_ id: String, reply: @escaping @Sendable (Bool) -> Void) { reply(id == deliveredID) }

    func authorization(_ reply: @escaping @Sendable (UNAuthorizationStatus) -> Void) { reply(status) }

    func requestAuthorization(options: UNAuthorizationOptions,
                              completionHandler: @escaping @Sendable (Bool, Error?) -> Void) {
        precondition(options == [.alert])
        permission = completionHandler
    }

    func add(_ request: UNNotificationRequest, withCompletionHandler reply: (@Sendable (Error?) -> Void)?) {
        self.request = request
        added = reply
    }
}

final class Acknowledgment {
    var received: [Bool] = []
    func record(_ accepted: Bool) { received.append(accepted) }
}

let id = UUID()
let banner = Banner(id: id, attempt: UUID(), title: "Goal resumed", body: "Example resumed.")
let error = NSError(domain: "fixture", code: 1)

for (granted, failure) in [(false, nil), (true, nil), (false, error as Error?)] {
    let center = Center(.notDetermined)
    let ack = Acknowledgment()
    banner.submit(to: center) { ack.record($0) }
    precondition(ack.received.isEmpty && center.request == nil)
    center.permission!(granted, failure)
    precondition(ack.received == [false] && center.request == nil)
}

for status: UNAuthorizationStatus in [.denied, .authorized, .provisional] {
    for failure in [nil, error as Error?] {
        let center = Center(status)
        let ack = Acknowledgment()
        banner.submit(to: center) { ack.record($0) }
        precondition(center.permission == nil)
        if status == .denied {
            precondition(ack.received == [false] && center.request == nil)
        } else {
            let request = center.request!
            precondition(request.identifier == id.uuidString.lowercased() && request.trigger == nil)
            precondition(request.content.title == banner.title && request.content.body == banner.body)
            precondition(ack.received.isEmpty)
            center.added!(failure)
            precondition(ack.received == [failure == nil])
        }
    }
}
let retry = Center(.authorized)
retry.deliveredID = id.uuidString.lowercased()
let duplicate = Acknowledgment()
banner.submit(to: retry) { duplicate.record($0) }
precondition(duplicate.received == [true] && retry.request == nil)
print("macOS notification authorization and acknowledgment fixture passed")

// Exercise the tray's real message dispatch and asynchronous acceptance without
// giving this test access to the user's notification center or account inbox.
let desktop = Desktop(iconPath: CommandLine.arguments[2], openAtLaunch: false)
let trayCenter = Center(.authorized)
var replies: [(UUID, Bool)] = []
desktop.useNotificationCenter(trayCenter) { replies.append(($0, $1)) }
let attempt = UUID()
let body = "A \"quoted\" chat resumed.\n✓"
let fields = ["notification": ["id": id.uuidString, "attempt": attempt.uuidString,
                               "title": "Gent updated", "body": body]]
desktop.receive(fields)
precondition(trayCenter.request?.identifier == id.uuidString.lowercased() && trayCenter.request?.content.body == body && replies.isEmpty)
trayCenter.added!(nil)
let deadline = Date(timeIntervalSinceNow: 2)
while replies.isEmpty && Date() < deadline { RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01)) }
precondition(replies.count == 1 && replies[0].0 == attempt && replies[0].1)
precondition(desktop.lastRead == .distantPast && desktop.window == nil)
desktop.useNotificationCenter(nil) { replies.append(($0, $1)) }
desktop.receive(fields)
precondition(replies.count == 2 && replies[1].0 == attempt && !replies[1].1)
print("Tray JSON dispatch acknowledges only the native result and leaves the window closed")

// Compare decoded pixels since iconutil may re-encode PNG data in an ICNS.
func pixels(_ image: CGImage) -> Data {
    let stride = 4 * image.width
    let context = CGContext(data: nil, width: image.width, height: image.height, bitsPerComponent: 8,
                            bytesPerRow: stride, space: CGColorSpaceCreateDeviceRGB(),
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    context.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
    return Data(bytes: context.data!, count: stride * image.height)
}

let app = Bundle(url: URL(fileURLWithPath: CommandLine.arguments[1]))!
precondition(app.executableURL?.lastPathComponent == "GentDesktop")
precondition(app.bundleIdentifier == "link.gent.notifications")
precondition(app.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String == "Gent")
let resource = app.object(forInfoDictionaryKey: "CFBundleIconFile") as! String
let icon = CGImageSourceCreateWithURL(app.url(forResource: resource, withExtension: nil)! as CFURL, nil)!
let source = CGImageSourceCreateWithURL(URL(fileURLWithPath: CommandLine.arguments[2]) as CFURL, nil)!
let inkling = CGImageSourceCreateImageAtIndex(source, 0, nil)!
let decoded = (0..<CGImageSourceGetCount(icon)).compactMap { CGImageSourceCreateImageAtIndex(icon, $0, nil) }
precondition(decoded.contains { $0.width == inkling.width && $0.height == inkling.height && pixels($0) == pixels(inkling) })
print("Gent bundle identity and Inkling pixels verified")
