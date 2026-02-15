import Foundation
import UserNotifications

/// Handles local notification permissions and posting alerts.
final class NotificationService {

    func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(
            options: [.alert, .sound, .badge]
        ) { _, _ in }
    }

    func postAlert(_ alert: AlertItem) {
        let content = UNMutableNotificationContent()
        content.title = "TrueMonitor Alert"
        content.body = alert.message

        switch alert.level {
        case .critical:
            content.sound = .defaultCritical
        case .warning:
            content.sound = .default
        case .info:
            content.sound = nil
        }

        let request = UNNotificationRequest(
            identifier: alert.id.uuidString,
            content: content,
            trigger: nil // Deliver immediately
        )

        UNUserNotificationCenter.current().add(request)
    }
}
