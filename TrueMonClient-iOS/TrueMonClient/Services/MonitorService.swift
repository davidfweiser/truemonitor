import Foundation
import UIKit
import Combine
import Security

/// Central service managing connection lifecycle, stats history, and alert evaluation.
@MainActor
final class MonitorService: ObservableObject {

    enum ConnectionState: Equatable {
        case disconnected
        case connecting
        case connected
        case failed(String)

        var label: String {
            switch self {
            case .disconnected: return "Disconnected"
            case .connecting:   return "Connecting..."
            case .connected:    return "Connected"
            case .failed(let msg): return "Error: \(msg)"
            }
        }
    }

    // MARK: - Published State

    @Published var stats: ServerStats?
    @Published var connectionState: ConnectionState = .disconnected
    @Published var errorMessage: String?
    @Published var alerts: [AlertItem] = []

    // History buffers for charts (60 data points)
    @Published var netRxHistory: [Double] = []
    @Published var netTxHistory: [Double] = []
    @Published var tempHistory: [Double] = []

    static let historySize = 60

    // MARK: - Settings

    @Published var serverHost: String {
        didSet { UserDefaults.standard.set(serverHost, forKey: "serverHost") }
    }
    @Published var serverPort: UInt16 {
        didSet { UserDefaults.standard.set(Int(serverPort), forKey: "serverPort") }
    }
    @Published var tempThreshold: Double {
        didSet { UserDefaults.standard.set(tempThreshold, forKey: "tempThreshold") }
    }
    @Published var cpuAlertEnabled: Bool {
        didSet { UserDefaults.standard.set(cpuAlertEnabled, forKey: "cpuAlertEnabled") }
    }
    @Published var memoryAlertEnabled: Bool {
        didSet { UserDefaults.standard.set(memoryAlertEnabled, forKey: "memoryAlertEnabled") }
    }

    // MARK: - Private

    private let connection = MonitorConnection()
    private var reconnectTask: Task<Void, Never>?
    private var shouldAutoReconnect = false
    private let notificationService = NotificationService()
    private var backgroundTaskID: UIBackgroundTaskIdentifier = .invalid

    // MARK: - Init

    init() {
        serverHost = UserDefaults.standard.string(forKey: "serverHost") ?? ""
        let savedPort = UserDefaults.standard.integer(forKey: "serverPort")
        serverPort = savedPort > 0 ? UInt16(savedPort) : 7337
        tempThreshold = UserDefaults.standard.object(forKey: "tempThreshold") as? Double ?? 80.0
        cpuAlertEnabled = UserDefaults.standard.object(forKey: "cpuAlertEnabled") as? Bool ?? true
        memoryAlertEnabled = UserDefaults.standard.object(forKey: "memoryAlertEnabled") as? Bool ?? true

        loadAlerts()

        // Auto-connect on launch if a host is already configured
        if !serverHost.isEmpty {
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: 500_000_000)
                self?.connect()
            }
        }

        connection.onStats = { [weak self] stats in
            Task { @MainActor [weak self] in
                self?.handleStats(stats)
            }
        }
        connection.onStateChange = { [weak self] state in
            Task { @MainActor [weak self] in
                self?.handleConnectionState(state)
            }
        }
        connection.onError = { [weak self] msg in
            Task { @MainActor [weak self] in
                self?.errorMessage = msg
            }
        }
    }

    // MARK: - Connection Management

    func connect() {
        guard !serverHost.isEmpty else {
            errorMessage = "Enter a server address"
            return
        }

        let passphrase = loadPassphrase() ?? "truemonitor"
        shouldAutoReconnect = true
        errorMessage = nil
        connection.connect(host: serverHost, port: serverPort, passphrase: passphrase)
    }

    /// Reconnect if the user had an active session (e.g. after returning from background).
    func reconnectIfNeeded() {
        endBackgroundTask()
        guard shouldAutoReconnect else { return }
        // Only reconnect if we're not already connected/connecting
        switch connectionState {
        case .connected, .connecting:
            return
        default:
            reconnectTask?.cancel()
            reconnectTask = nil
            connect()
        }
    }

    /// Request extended background execution time to keep the connection alive briefly.
    func beginBackgroundExecution() {
        guard shouldAutoReconnect else { return }
        endBackgroundTask()
        backgroundTaskID = UIApplication.shared.beginBackgroundTask(withName: "TrueMonitor") { [weak self] in
            // iOS is about to kill our background time — clean up
            self?.endBackgroundTask()
        }
    }

    private func endBackgroundTask() {
        guard backgroundTaskID != .invalid else { return }
        UIApplication.shared.endBackgroundTask(backgroundTaskID)
        backgroundTaskID = .invalid
    }

    func disconnect() {
        shouldAutoReconnect = false
        reconnectTask?.cancel()
        reconnectTask = nil
        endBackgroundTask()
        connection.disconnect()
        connectionState = .disconnected
        BackgroundAudioService.shared.stop()
        seenTrueNASAlerts.removeAll()
    }

    // MARK: - Stats Handling

    private func handleStats(_ newStats: ServerStats) {
        stats = newStats

        // Update history
        if let rx = newStats.netRx {
            netRxHistory.append(rx)
            if netRxHistory.count > Self.historySize {
                netRxHistory.removeFirst()
            }
        }
        if let tx = newStats.netTx {
            netTxHistory.append(tx)
            if netTxHistory.count > Self.historySize {
                netTxHistory.removeFirst()
            }
        }
        if let temp = newStats.cpuTemp {
            tempHistory.append(temp)
            if tempHistory.count > Self.historySize {
                tempHistory.removeFirst()
            }
        }

        // Evaluate alert conditions
        evaluateAlerts(newStats)
    }

    private func handleConnectionState(_ state: MonitorConnection.State) {
        switch state {
        case .disconnected:
            connectionState = .disconnected
            BackgroundAudioService.shared.stop()
            if shouldAutoReconnect {
                scheduleReconnect()
            }
        case .connecting:
            connectionState = .connecting
        case .connected:
            connectionState = .connected
            errorMessage = nil
            // Play silent audio to keep the app alive when backgrounded
            BackgroundAudioService.shared.start()
        case .failed(let msg):
            connectionState = .failed(msg)
            BackgroundAudioService.shared.stop()
            if shouldAutoReconnect {
                scheduleReconnect()
            }
        }
    }

    private func scheduleReconnect() {
        reconnectTask?.cancel()
        reconnectTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000) // 5 seconds
            guard !Task.isCancelled else { return }
            await self?.connect()
        }
    }

    // MARK: - Alert Evaluation

    private var lastAlertTimes: [String: Date] = [:]
    private let alertCooldown: TimeInterval = 300 // 5 minutes
    private var seenTrueNASAlerts: Set<String> = []

    private func evaluateAlerts(_ stats: ServerStats) {
        processSystemAlerts(stats.systemAlerts ?? [])
        if let temp = stats.cpuTemp, temp > tempThreshold {
            addAlert(key: "temp", level: temp > 90 ? .critical : .warning,
                     message: "CPU temperature \(String(format: "%.0f", temp))°C exceeds threshold (\(String(format: "%.0f", tempThreshold))°C)")
        }
        if cpuAlertEnabled, let cpu = stats.cpuPercent, cpu > 95 {
            addAlert(key: "cpu", level: .warning,
                     message: "CPU usage at \(String(format: "%.1f", cpu))%")
        }
        if memoryAlertEnabled, let mem = stats.memoryPercent, mem > 95 {
            addAlert(key: "memory", level: .warning,
                     message: "Memory usage at \(String(format: "%.1f", mem))%")
        }
    }

    private func processSystemAlerts(_ systemAlerts: [SystemAlert]) {
        let currentIDs = Set(systemAlerts.map(\.id))

        for alert in systemAlerts {
            guard !seenTrueNASAlerts.contains(alert.id) else { continue }
            seenTrueNASAlerts.insert(alert.id)

            let level: AlertLevel
            switch alert.severity {
            case "critical": level = .critical
            case "warning":  level = .warning
            default:         level = .info
            }

            let item = AlertItem(level: level, message: "[TrueNAS] \(alert.message)")
            alerts.insert(item, at: 0)
            saveAlerts()
            notificationService.postAlert(item)
        }

        // Detect resolved/dismissed alerts
        let resolved = seenTrueNASAlerts.subtracting(currentIDs)
        if !resolved.isEmpty {
            for alertID in resolved {
                seenTrueNASAlerts.remove(alertID)
            }
            let item = AlertItem(level: .info, message: "[TrueNAS] Alert cleared")
            alerts.insert(item, at: 0)
            saveAlerts()
        }
    }

    private func addAlert(key: String, level: AlertLevel, message: String) {
        let now = Date()
        if let last = lastAlertTimes[key], now.timeIntervalSince(last) < alertCooldown {
            return
        }
        lastAlertTimes[key] = now

        let alert = AlertItem(level: level, message: message)
        alerts.insert(alert, at: 0)
        saveAlerts()

        notificationService.postAlert(alert)
    }

    func clearAlerts() {
        alerts.removeAll()
        lastAlertTimes.removeAll()
        saveAlerts()
    }

    // MARK: - Persistence

    private func saveAlerts() {
        if let data = try? JSONEncoder().encode(alerts) {
            UserDefaults.standard.set(data, forKey: "savedAlerts")
        }
    }

    private func loadAlerts() {
        if let data = UserDefaults.standard.data(forKey: "savedAlerts"),
           let saved = try? JSONDecoder().decode([AlertItem].self, from: data) {
            alerts = saved
        }
    }

    // MARK: - Keychain (Passphrase)

    func savePassphrase(_ passphrase: String) {
        let data = passphrase.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.truemonitor.client",
            kSecAttrAccount as String: "broadcastKey",
        ]
        SecItemDelete(query as CFDictionary)
        var addQuery = query
        addQuery[kSecValueData as String] = data
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    func loadPassphrase() -> String? {
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
        // Fallback: seed from UserDefaults (used during simulator setup)
        if let seeded = UserDefaults.standard.string(forKey: "serverPassphrase") {
            savePassphrase(seeded)
            UserDefaults.standard.removeObject(forKey: "serverPassphrase")
            return seeded
        }
        return nil
    }
}
