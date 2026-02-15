import Foundation

enum AlertLevel: String, Codable {
    case info
    case warning
    case critical
}

struct AlertItem: Identifiable, Codable {
    let id: UUID
    let timestamp: Date
    let level: AlertLevel
    let message: String

    init(level: AlertLevel, message: String) {
        self.id = UUID()
        self.timestamp = Date()
        self.level = level
        self.message = message
    }
}
