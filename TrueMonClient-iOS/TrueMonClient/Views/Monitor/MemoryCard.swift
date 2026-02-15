import SwiftUI

struct MemoryCard: View {
    let memoryPercent: Double?
    let memoryUsed: Int?
    let memoryTotal: Int?

    var body: some View {
        CardContainer(title: "Memory") {
            if let pct = memoryPercent {
                HStack(alignment: .firstTextBaseline) {
                    Text(String(format: "%.1f%%", pct))
                        .font(.system(size: 36, weight: .bold, design: .monospaced))
                        .foregroundColor(colorForPercent(pct))
                    Spacer()
                }

                ProgressView(value: min(pct, 100), total: 100)
                    .tint(colorForPercent(pct))
                    .padding(.vertical, 4)

                let used = formatBytes(memoryUsed.map(Double.init))
                let total = formatBytes(memoryTotal.map(Double.init))
                Text("\(used) / \(total)")
                    .font(.caption)
                    .foregroundColor(AppTheme.textDim)
            } else {
                Text("N/A")
                    .foregroundColor(AppTheme.textDim)
            }
        }
    }

    private func colorForPercent(_ pct: Double) -> Color {
        if pct < 70 { return AppTheme.good }
        if pct < 90 { return AppTheme.warning }
        return AppTheme.critical
    }
}
