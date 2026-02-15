import SwiftUI
import BackgroundTasks
import UserNotifications

@main
struct TrueMonClientApp: App {

    init() {
        // Request notification permissions on first launch
        NotificationService().requestPermission()

        // Register background task
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: "com.truemonitor.client.refresh",
            using: nil
        ) { task in
            Self.handleBackgroundRefresh(task as! BGProcessingTask)
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .onReceive(NotificationCenter.default.publisher(
                    for: UIApplication.willResignActiveNotification
                )) { _ in
                    scheduleBackgroundRefresh()
                }
        }
    }

    // MARK: - Background Tasks

    private func scheduleBackgroundRefresh() {
        let request = BGProcessingTaskRequest(identifier: "com.truemonitor.client.refresh")
        request.requiresNetworkConnectivity = true
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60) // 15 minutes
        try? BGTaskScheduler.shared.submit(request)
    }

    private static func handleBackgroundRefresh(_ task: BGProcessingTask) {
        let host = UserDefaults.standard.string(forKey: "serverHost") ?? ""
        let port = UserDefaults.standard.integer(forKey: "serverPort")
        guard !host.isEmpty, port > 0 else {
            task.setTaskCompleted(success: true)
            return
        }

        // Load passphrase from keychain
        let passphrase = loadKeychainPassphrase() ?? "truemonitor"

        let connection = MonitorConnection()
        var receivedCount = 0
        let tempThreshold = UserDefaults.standard.object(forKey: "tempThreshold") as? Double ?? 80.0

        connection.onStats = { stats in
            receivedCount += 1

            // Check alert conditions
            if let temp = stats.cpuTemp, temp > tempThreshold {
                let alert = AlertItem(level: temp > 90 ? .critical : .warning,
                                      message: "CPU temperature \(String(format: "%.0f", temp))°C exceeds threshold")
                NotificationService().postAlert(alert)
            }
            if let cpu = stats.cpuPercent, cpu > 95 {
                let alert = AlertItem(level: .warning, message: "CPU usage at \(String(format: "%.1f", cpu))%")
                NotificationService().postAlert(alert)
            }
            if let mem = stats.memoryPercent, mem > 95 {
                let alert = AlertItem(level: .warning, message: "Memory usage at \(String(format: "%.1f", mem))%")
                NotificationService().postAlert(alert)
            }

            // Disconnect after receiving a couple of updates
            if receivedCount >= 2 {
                connection.disconnect()
                task.setTaskCompleted(success: true)
            }
        }

        connection.onError = { _ in
            task.setTaskCompleted(success: false)
        }

        task.expirationHandler = {
            connection.disconnect()
        }

        connection.connect(host: host, port: UInt16(port), passphrase: passphrase)

        // Schedule next refresh
        let request = BGProcessingTaskRequest(identifier: "com.truemonitor.client.refresh")
        request.requiresNetworkConnectivity = true
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    private static func loadKeychainPassphrase() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.truemonitor.client",
            kSecAttrAccount as String: "broadcastKey",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data {
            return String(data: data, encoding: .utf8)
        }
        return nil
    }
}
