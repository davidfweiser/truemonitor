import Foundation
import UIKit
import Combine
import Security
import Network
import BackgroundTasks

// MARK: - DataModule
// Singleton data layer — not owned by any view.
// Manages the server connection, processes incoming stats, evaluates alerts,
// and keeps the app alive in the background via silent audio.
// Always running: created at app launch, persists for the lifetime of the process.
@MainActor
final class DataModule: ObservableObject {

    static let shared = DataModule()

    // MARK: - Connection State

    enum ConnectionState: Equatable {
        case disconnected
        case connecting
        case connected
        case failed(String)

        var label: String {
            switch self {
            case .disconnected:       return "Disconnected"
            case .connecting:         return "Connecting..."
            case .connected:          return "Connected"
            case .failed(let msg):    return "Error: \(msg)"
            }
        }
    }

    // MARK: - Published State (read by display layer)

    @Published private(set) var stats: ServerStats?
    @Published private(set) var connectionState: ConnectionState = .disconnected
    @Published private(set) var errorMessage: String?
    @Published private(set) var alerts: [AlertItem] = []

    // History buffers for charts (60 data points)
    @Published private(set) var netRxHistory: [Double] = []
    @Published private(set) var netTxHistory: [Double] = []
    @Published private(set) var tempHistory: [Double] = []

    static let historySize = 60

    // MARK: - Settings (read/write by SettingsView)

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
    private var pathMonitor: NWPathMonitor?
    private var lastDataReceived: Date?
    private var watchdogTimer: Timer?

    private var lastAlertTimes: [String: Date] = [:]
    private let alertCooldown: TimeInterval = 300 // 5 minutes
    // In-memory only — deduplicates within a session but resets on app restart
    // so persistent TrueNAS alerts (stable IDs) are shown again each launch.
    private var seenTrueNASAlerts: Set<String> = []

    // MARK: - Init

    private init() {
        serverHost = UserDefaults.standard.string(forKey: "serverHost") ?? ""
        let savedPort = UserDefaults.standard.integer(forKey: "serverPort")
        serverPort = savedPort > 0 ? UInt16(savedPort) : 7337
        tempThreshold = UserDefaults.standard.object(forKey: "tempThreshold") as? Double ?? 80.0
        cpuAlertEnabled = UserDefaults.standard.object(forKey: "cpuAlertEnabled") as? Bool ?? true
        memoryAlertEnabled = UserDefaults.standard.object(forKey: "memoryAlertEnabled") as? Bool ?? true

        loadAlerts()
        // Clear any stale persisted seenTrueNASAlerts from old versions
        UserDefaults.standard.removeObject(forKey: "seenTrueNASAlerts")

        // Register this instance as UNUserNotificationCenterDelegate before any
        // notifications fire, and request permission.
        notificationService.requestPermission()

        // When audio resumes after a phone call etc., reconnect if needed
        BackgroundAudioService.shared.onInterruptionEnded = { [weak self] in
            Task { @MainActor [weak self] in
                self?.reconnectIfNeeded()
            }
        }

        setupConnectionCallbacks()
        startNetworkMonitor()

        // Auto-connect on launch if a host is already configured
        if !serverHost.isEmpty {
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: 500_000_000)
                self?.connect()
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

    func reconnectIfNeeded() {
        endBackgroundTask()
        guard shouldAutoReconnect else { return }
        switch connectionState {
        case .connected:
            // If connected but data is stale, force reconnect
            if let last = lastDataReceived, Date().timeIntervalSince(last) > 30 {
                connection.disconnect()
                connect()
            }
            return
        case .connecting:
            return
        default:
            reconnectTask?.cancel()
            reconnectTask = nil
            connect()
        }
    }

    func beginBackgroundExecution() {
        guard shouldAutoReconnect else { return }
        endBackgroundTask()
        backgroundTaskID = UIApplication.shared.beginBackgroundTask(withName: "TrueMonitor") { [weak self] in
            self?.endBackgroundTask()
        }
    }

    func disconnect() {
        shouldAutoReconnect = false
        reconnectTask?.cancel()
        reconnectTask = nil
        stopWatchdog()
        endBackgroundTask()
        connection.disconnect()
        connectionState = .disconnected
        BackgroundAudioService.shared.stop()
    }

    // MARK: - Background Tasks

    /// Register the background processing task handler.
    /// Must be called before the app finishes launching.
    func registerBackgroundTask() {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: "com.truemonitor.client.refresh",
            using: nil // called on main queue
        ) { task in
            Task { @MainActor in
                DataModule.shared.handleBackgroundRefresh(task as! BGProcessingTask)
            }
        }
    }

    /// Schedule the next background refresh 15 minutes from now.
    func scheduleBackgroundRefresh() {
        let request = BGProcessingTaskRequest(identifier: "com.truemonitor.client.refresh")
        request.requiresNetworkConnectivity = true
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    private func handleBackgroundRefresh(_ task: BGProcessingTask) {
        // Always schedule the next cycle first
        scheduleBackgroundRefresh()

        task.expirationHandler = {
            task.setTaskCompleted(success: false)
        }

        // Connect — DataModule.evaluateAlerts() will fire notifications as needed
        connect()

        Task {
            try? await Task.sleep(nanoseconds: 10_000_000_000) // 10 seconds
            task.setTaskCompleted(success: true)
        }
    }

    // MARK: - Private Helpers

    private func setupConnectionCallbacks() {
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

    private func handleStats(_ newStats: ServerStats) {
        if newStats.clearAlertsAt != nil {
            clearAlerts(fromServer: true)
        }
        lastDataReceived = Date()
        stats = newStats

        if let rx = newStats.netRx {
            netRxHistory.append(rx)
            if netRxHistory.count > Self.historySize { netRxHistory.removeFirst() }
        }
        if let tx = newStats.netTx {
            netTxHistory.append(tx)
            if netTxHistory.count > Self.historySize { netTxHistory.removeFirst() }
        }
        if let temp = newStats.cpuTemp {
            tempHistory.append(temp)
            if tempHistory.count > Self.historySize { tempHistory.removeFirst() }
        }

        evaluateAlerts(newStats)
    }

    private func handleConnectionState(_ state: MonitorConnection.State) {
        switch state {
        case .disconnected:
            connectionState = .disconnected
            stopWatchdog()
            if shouldAutoReconnect {
                scheduleReconnect()
            } else {
                BackgroundAudioService.shared.stop()
            }
        case .connecting:
            connectionState = .connecting
        case .connected:
            reconnectTask?.cancel()
            reconnectTask = nil
            connectionState = .connected
            errorMessage = nil
            lastDataReceived = Date()
            startWatchdog()
            BackgroundAudioService.shared.start()
        case .failed(let msg):
            connectionState = .failed(msg)
            stopWatchdog()
            if shouldAutoReconnect {
                scheduleReconnect()
            } else {
                BackgroundAudioService.shared.stop()
            }
        }
    }

    private func startNetworkMonitor() {
        pathMonitor = NWPathMonitor()
        pathMonitor?.pathUpdateHandler = { [weak self] path in
            guard path.status == .satisfied else { return }
            Task { @MainActor [weak self] in
                self?.reconnectIfNeeded()
            }
        }
        pathMonitor?.start(queue: DispatchQueue(label: "com.truemonitor.pathmonitor", qos: .utility))
    }

    private func scheduleReconnect() {
        reconnectTask?.cancel()
        reconnectTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000) // 5 seconds
            guard !Task.isCancelled else { return }
            self?.connect()
        }
    }

    private func startWatchdog() {
        watchdogTimer?.invalidate()
        watchdogTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.checkWatchdog()
            }
        }
    }

    private func stopWatchdog() {
        watchdogTimer?.invalidate()
        watchdogTimer = nil
        lastDataReceived = nil
    }

    private func checkWatchdog() {
        guard connectionState == .connected, shouldAutoReconnect else { return }
        guard let last = lastDataReceived, Date().timeIntervalSince(last) > 30 else { return }
        connection.disconnect()
        connect()
    }

    private func endBackgroundTask() {
        guard backgroundTaskID != .invalid else { return }
        UIApplication.shared.endBackgroundTask(backgroundTaskID)
        backgroundTaskID = .invalid
    }

    // MARK: - Alert Evaluation

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
        if let last = lastAlertTimes[key], now.timeIntervalSince(last) < alertCooldown { return }
        lastAlertTimes[key] = now
        let alert = AlertItem(level: level, message: message)
        alerts.insert(alert, at: 0)
        saveAlerts()
        notificationService.postAlert(alert)
    }

    func clearAlerts(fromServer: Bool = false) {
        alerts.removeAll()
        lastAlertTimes.removeAll()
        saveAlerts()
        if !fromServer {
            connection.sendCommand(["cmd": "clear_alerts"])
        }
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
        if let seeded = UserDefaults.standard.string(forKey: "serverPassphrase") {
            savePassphrase(seeded)
            UserDefaults.standard.removeObject(forKey: "serverPassphrase")
            return seeded
        }
        return nil
    }
}
