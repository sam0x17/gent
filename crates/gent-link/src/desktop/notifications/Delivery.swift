import Foundation
import UserNotifications

struct Banner: Decodable {
    let id: UUID
    let attempt: UUID
    let title: String
    let body: String

    func submit(to center: NotificationCenterClient, accepted: @escaping @Sendable (Bool) -> Void) {
        center.authorization { status in
            switch status {
            case .notDetermined:
                // Permission can take arbitrarily long. Re-read the signed-in account
                // and pending event on the next attempt before actually submitting.
                center.requestAuthorization(options: [.alert]) { _, _ in accepted(false) }
            case .authorized, .provisional:
                let identifier = id.uuidString.lowercased()
                center.wasDelivered(identifier) { delivered in
                    // Retry after an interrupted acknowledgment or cursor write.
                    if delivered { accepted(true); return }
                    let content = UNMutableNotificationContent()
                    content.title = title
                    content.body = body
                    let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
                    center.add(request) { error in accepted(error == nil) }
                }
            default:
                accepted(false)
            }
        }
    }
}

protocol NotificationCenterClient {
    func wasDelivered(_ id: String, reply: @escaping @Sendable (Bool) -> Void)
    func authorization(_ reply: @escaping @Sendable (UNAuthorizationStatus) -> Void)
    func requestAuthorization(options: UNAuthorizationOptions,
                              completionHandler: @escaping @Sendable (Bool, Error?) -> Void)
    func add(_ request: UNNotificationRequest, withCompletionHandler: (@Sendable (Error?) -> Void)?)
}

extension UNUserNotificationCenter: NotificationCenterClient {
    func wasDelivered(_ id: String, reply: @escaping @Sendable (Bool) -> Void) {
        getDeliveredNotifications { reply($0.contains { $0.request.identifier == id }) }
    }

    func authorization(_ reply: @escaping @Sendable (UNAuthorizationStatus) -> Void) {
        getNotificationSettings { reply($0.authorizationStatus) }
    }
}

// The GUI receives only display data. Reply on the main queue alongside other
// supervisor messages, after the native center completes this particular attempt.
extension Desktop {
    func useNotificationCenter(_ center: NotificationCenterClient?,
                               reply: @escaping (UUID, Bool) -> Void = { attempt, accepted in
                                   sendPage("notification_result", ["attempt": attempt.uuidString.lowercased(),
                                                                    "accepted": accepted])
                               }) {
        deliverNotification = { fields in
            guard let bytes = try? JSONSerialization.data(withJSONObject: fields),
                  let banner = try? JSONDecoder().decode(Banner.self, from: bytes) else { return }
            guard let center = center else { reply(banner.attempt, false); return }
            banner.submit(to: center) { accepted in
                DispatchQueue.main.async { reply(banner.attempt, accepted) }
            }
        }
    }
}
