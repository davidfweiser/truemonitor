import SwiftUI

struct CPUCard: View {
    let cpuPercent: Double?
    let loadavg: [Double]?

    var body: some View {
        CardContainer(title: "Processor", accentColor: AppTheme.cpuAccent) {
            if let cpu = cpuPercent {
                HStack(alignment: .center, spacing: 16) {
                    // Circular gauge
                    Gauge(value: min(cpu, 100), in: 0...100) {
                        Image(systemName: "cpu")
                    } currentValueLabel: {
                        Text("\(Int(cpu))")
                            .font(.system(size: 18, weight: .bold, design: .monospaced))
                            .foregroundColor(neonColorForPercent(cpu))
                            .contentTransition(.numericText())
                    }
                    .gaugeStyle(.accessoryCircular)
                    .tint(Gradient(colors: [AppTheme.cyan, AppTheme.gold, AppTheme.magenta]))
                    .scaleEffect(1.4)
                    .frame(width: 64, height: 64)

                    VStack(alignment: .leading, spacing: 6) {
                        Text(String(format: "%.1f%%", cpu))
                            .font(AppTheme.metricFont())
                            .foregroundColor(neonColorForPercent(cpu))
                            .shadow(color: neonColorForPercent(cpu).opacity(0.3), radius: 8)
                            .contentTransition(.numericText())

                        if let load = loadavg, load.count >= 3 {
                            Text(String(format: "Load  %.2f · %.2f · %.2f", load[0], load[1], load[2]))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(AppTheme.textDim)
                        }
                    }

                    Spacer()
                }
                .animation(.easeInOut(duration: 0.4), value: cpu)
            } else {
                Text("N/A")
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(AppTheme.textDim)
            }
        }
    }

    private func neonColorForPercent(_ pct: Double) -> Color {
        if pct < 70 { return AppTheme.cyan }
        if pct < 90 { return AppTheme.gold }
        return AppTheme.magenta
    }
}
