import Foundation
import UserNotifications

private func authorizationName(_ status: UNAuthorizationStatus) -> String {
    switch status {
    case .notDetermined: return "not_determined"
    case .authorized: return "authorized"
    case .provisional: return "provisional"
    case .denied: return "denied"
    default: return "unknown"
    }
}

struct Banner: Decodable {
    typealias Trace = @Sendable (String, UNAuthorizationStatus?, Error?) -> Void
    static func diagnostic(_ stage: String, status: UNAuthorizationStatus?, error: Error?) -> [String: Any] {
        var fields: [String: Any] = ["stage": stage]
        if let status = status { fields["authorization"] = authorizationName(status) }
        if let error = error as NSError? {
            let domains = [UNErrorDomain, NSPOSIXErrorDomain, NSCocoaErrorDomain, NSOSStatusErrorDomain]
            fields["domain"] = domains.contains(error.domain) ? error.domain : "other"
            fields["code"] = error.code
            if let cause = error.userInfo[NSUnderlyingErrorKey] as? NSError {
                fields["underlying_domain"] = domains.contains(cause.domain) ? cause.domain : "other"
                fields["underlying_code"] = cause.code
            }
        }
        return fields
    }

    let id: UUID
    let attempt: UUID
    let title: String
    let body: String

    func submit(to center: NotificationCenterClient, trace: @escaping Trace = { _, _, _ in },
                accepted: @escaping @Sendable (Bool) -> Void) {
        trace("settings_requested", nil, nil)
        center.authorization { status in
            trace("settings_received", status, nil)
            switch status {
            case .notDetermined:
                // Permission can take arbitrarily long. Re-read the signed-in account
                // and pending event on the next attempt before actually submitting.
                trace("permission_requested", status, nil)
                center.requestAuthorization(options: [.alert]) { granted, error in
                    trace(error != nil ? "permission_error" : granted ? "permission_granted" : "permission_not_granted", status, error)
                    accepted(false)
                }
            case .authorized, .provisional:
                let identifier = id.uuidString.lowercased()
                center.wasDelivered(identifier) { delivered in
                    // Retry after an interrupted acknowledgment or cursor write.
                    if delivered {
                        trace("already_delivered", status, nil)
                        accepted(true)
                        return
                    }
                    let content = UNMutableNotificationContent()
                    content.title = title
                    content.body = body
                    let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
                    trace("submission_requested", status, nil)
                    center.add(request) { error in
                        trace(error == nil ? "submitted" : "submission_error", status, error)
                        accepted(error == nil)
                    }
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
            let diagnosing = fields["diagnose"] as? Bool == true
            let trace: Banner.Trace = { stage, status, error in
                guard diagnosing else { return }
                // Only fixed labels and integer error codes cross the diagnostic
                // boundary. NSError descriptions/userInfo can contain filesystem paths.
                DispatchQueue.main.async {
                    var data = Banner.diagnostic(stage, status: status, error: error)
                    data["attempt"] = banner.attempt.uuidString.lowercased()
                    sendPage("notification_diagnostic", data)
                }
            }
            guard let center = center else {
                trace("registration_unavailable", nil, nil)
                DispatchQueue.main.async { reply(banner.attempt, false) }
                return
            }
            banner.submit(to: center, trace: trace) { accepted in
                DispatchQueue.main.async { reply(banner.attempt, accepted) }
            }
        }
    }
}
