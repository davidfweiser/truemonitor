import Foundation

/// Formats a byte value into a human-readable string (KB/MB/GB/TB).
/// Matches the Python `format_bytes()` exactly (base-1024).
func formatBytes(_ val: Double?, perSecond: Bool = false) -> String {
    guard let val = val else { return "N/A" }
    let suffix = perSecond ? "/s" : ""
    var v = val
    for unit in ["B", "KB", "MB", "GB", "TB"] {
        if abs(v) < 1024.0 {
            return String(format: "%.1f %@%@", v, unit, suffix)
        }
        v /= 1024.0
    }
    return String(format: "%.1f PB%@", v, suffix)
}
