// Exercise the production authorization/submission sequence without opening a
// notification center, requesting OS permission, or displaying a banner.
import Foundation
import ImageIO
import UserNotifications

final class Center: NotificationCenterClient {
    let status: UNAuthorizationStatus
    var permission: (@Sendable (Bool, Error?) -> Void)?
    var added: (@Sendable (Error?) -> Void)?
    var request: UNNotificationRequest?

    init(_ status: UNAuthorizationStatus) { self.status = status }

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
let banner = Banner(id: id, title: "Goal resumed", body: "Example resumed.")
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
print("macOS notification authorization and acknowledgment fixture passed")

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
precondition(app.bundleIdentifier == "link.gent.notifications")
precondition(app.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String == "Gent")
let resource = app.object(forInfoDictionaryKey: "CFBundleIconFile") as! String
let icon = CGImageSourceCreateWithURL(app.url(forResource: resource, withExtension: nil)! as CFURL, nil)!
let source = CGImageSourceCreateWithURL(URL(fileURLWithPath: CommandLine.arguments[2]) as CFURL, nil)!
let inkling = CGImageSourceCreateImageAtIndex(source, 0, nil)!
let decoded = (0..<CGImageSourceGetCount(icon)).compactMap { CGImageSourceCreateImageAtIndex(icon, $0, nil) }
precondition(decoded.contains { $0.width == inkling.width && $0.height == inkling.height && pixels($0) == pixels(inkling) })
print("Gent bundle identity and Inkling pixels verified")
