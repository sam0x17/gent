import Foundation
import UserNotifications

struct Banner: Decodable {
    let id: UUID
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
                let content = UNMutableNotificationContent()
                content.title = title
                content.body = body
                let request = UNNotificationRequest(identifier: id.uuidString.lowercased(),
                                                    content: content, trigger: nil)
                center.add(request) { error in accepted(error == nil) }
            default:
                accepted(false)
            }
        }
    }
}

protocol NotificationCenterClient {
    func authorization(_ reply: @escaping @Sendable (UNAuthorizationStatus) -> Void)
    func requestAuthorization(options: UNAuthorizationOptions,
                              completionHandler: @escaping @Sendable (Bool, Error?) -> Void)
    func add(_ request: UNNotificationRequest, withCompletionHandler: (@Sendable (Error?) -> Void)?)
}

extension UNUserNotificationCenter: NotificationCenterClient {
    func authorization(_ reply: @escaping @Sendable (UNAuthorizationStatus) -> Void) {
        getNotificationSettings { reply($0.authorizationStatus) }
    }
}
