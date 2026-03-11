import SwiftUI

struct MemoryCard: View {
    let memoryPercent: Double?
    let memoryUsed: Int?
    let memoryTotal: Int?

    var body: some View {
        CardContainer(title: "Memory") {
            if let pct = memoryPercent {
                HStack(alignment: .center, spacing: 16) {
                    // Circular gauge
                    Gauge(value: min(pct, 100), in: 0...100) {
                        Image(systemName: "memorychip")
                    } currentValueLabel: {
                        Text("\(Int(pct))")
                            .font(.system(size: 18, weight: .bold, design: .rounded))
                            .foregroundColor(colorForPercent(pct))
                            .contentTransition(.numericText())
                    }
                    .gaugeStyle(.accessoryCircular)
                    .tint(Gradient(colors: [AppTheme.good, AppTheme.warning, AppTheme.critical]))
                    .scaleEffect(1.4)
                    .frame(width: 64, height: 64)

                    VStack(alignment: .leading, spacing: 6) {
                        Text(String(format: "%.1f%%", pct))
                            .font(AppTheme.metricFont())
                            .foregroundColor(colorForPercent(pct))
                            .contentTransition(.numericText())

                        let used = formatBytes(memoryUsed.map(Double.init))
                        let total = formatBytes(memoryTotal.map(Double.init))
                        Text("\(used) / \(total)")
                            .font(.caption)
                            .foregroundColor(AppTheme.textDim)
                    }

                    Spacer()
                }
                .animation(.easeInOut(duration: 0.4), value: pct)
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
