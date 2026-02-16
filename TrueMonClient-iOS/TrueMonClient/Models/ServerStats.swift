import Foundation

/// Matches the broadcast JSON from TrueMonitor's `fetch_all_stats()`.
struct ServerStats: Codable {
    let cpuPercent: Double?
    let memoryUsed: Int?
    let memoryTotal: Int?
    let memoryPercent: Double?
    let cpuTemp: Double?
    let netRx: Double?
    let netTx: Double?
    let netIface: String?
    let hostname: String?
    let version: String?
    let uptime: String?
    let loadavg: [Double]?
    let pools: [PoolInfo]?
    let systemAlerts: [SystemAlert]?

    enum CodingKeys: String, CodingKey {
        case cpuPercent   = "cpu_percent"
        case memoryUsed   = "memory_used"
        case memoryTotal  = "memory_total"
        case memoryPercent = "memory_percent"
        case cpuTemp      = "cpu_temp"
        case netRx        = "net_rx"
        case netTx        = "net_tx"
        case netIface     = "net_iface"
        case systemAlerts = "system_alerts"
        case hostname, version, uptime, loadavg, pools
    }
}

struct PoolInfo: Codable, Identifiable {
    var id: String { name }
    let name: String
    let used: Int64?
    let available: Int64?
    let total: Int64?
    let percent: Double?
    let disks: [DiskInfo]?
    let topology: [String: [VdevGroup]]?
}

struct DiskInfo: Codable, Identifiable {
    var id: String { name }
    let name: String
    let hasError: Bool

    enum CodingKeys: String, CodingKey {
        case name
        case hasError = "has_error"
    }
}

struct VdevGroup: Codable, Identifiable {
    var id: String { "\(type)-\(status)-\(disks.map(\.name).joined())" }
    let type: String
    let status: String
    let disks: [VdevDisk]
}

struct VdevDisk: Codable, Identifiable {
    var id: String { name }
    let name: String
    let status: String
    let errors: Int
}

struct SystemAlert: Codable, Identifiable {
    var id: String
    let severity: String
    let message: String
}
