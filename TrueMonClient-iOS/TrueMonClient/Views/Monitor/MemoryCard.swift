import SwiftUI

struct MemoryCard: View {
    let memoryPercent: Double?
    let memoryUsed: Int?
    let memoryTotal: Int?

    var body: some View {
        CardContainer(title: "Memory", accentColor: AppTheme.memAccent) {
            if let pct = memoryPercent {
                HStack(alignment: .center, spacing: 16) {
                    // Circular gauge
                    Gauge(value: min(pct, 100), in: 0...100) {
                        Image(systemName: "memorychip")
                    } currentValueLabel: {
                        Text("\(Int(pct))")
                            .font(.system(size: 18, weight: .bold, design: .monospaced))
                            .foregroundColor(neonColorForPercent(pct))
                            .contentTransition(.numericText())
                    }
                    .gaugeStyle(.accessoryCircular)
                    .tint(Gradient(colors: [AppTheme.magenta, AppTheme.purple, AppTheme.critical]))
                    .scaleEffect(1.4)
                    .frame(width: 64, height: 64)

                    VStack(alignment: .leading, spacing: 6) {
                        Text(String(format: "%.1f%%", pct))
                            .font(AppTheme.metricFont())
                            .foregroundColor(neonColorForPercent(pct))
                            .shadow(color: neonColorForPercent(pct).opacity(0.3), radius: 8)
                            .contentTransition(.numericText())

                        let used = formatBytes(memoryUsed.map(Double.init))
                        let total = formatBytes(memoryTotal.map(Double.init))
                        Text("\(used) / \(total)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(AppTheme.textDim)
                    }

                    Spacer()
                }
                .animation(.easeInOut(duration: 0.4), value: pct)
            } else {
                Text("N/A")
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(AppTheme.textDim)
            }
        }
    }

    private func neonColorForPercent(_ pct: Double) -> Color {
        if pct < 70 { return AppTheme.magenta }
        if pct < 90 { return AppTheme.gold }
        return AppTheme.critical
    }
}
