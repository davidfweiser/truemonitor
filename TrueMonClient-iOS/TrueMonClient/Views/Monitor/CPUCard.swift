import SwiftUI

struct CPUCard: View {
    let cpuPercent: Double?
    let loadavg: [Double]?

    var body: some View {
        CardContainer(title: "CPU") {
            if let cpu = cpuPercent {
                HStack(alignment: .center, spacing: 16) {
                    // Circular gauge
                    Gauge(value: min(cpu, 100), in: 0...100) {
                        Image(systemName: "cpu")
                    } currentValueLabel: {
                        Text("\(Int(cpu))")
                            .font(.system(size: 18, weight: .bold, design: .rounded))
                            .foregroundColor(colorForPercent(cpu))
                            .contentTransition(.numericText())
                    }
                    .gaugeStyle(.accessoryCircular)
                    .tint(Gradient(colors: [AppTheme.good, AppTheme.warning, AppTheme.critical]))
                    .scaleEffect(1.4)
                    .frame(width: 64, height: 64)

                    VStack(alignment: .leading, spacing: 6) {
                        Text(String(format: "%.1f%%", cpu))
                            .font(AppTheme.metricFont())
                            .foregroundColor(colorForPercent(cpu))
                            .contentTransition(.numericText())

                        if let load = loadavg, load.count >= 3 {
                            Text(String(format: "Load  %.2f · %.2f · %.2f", load[0], load[1], load[2]))
                                .font(.caption)
                                .foregroundColor(AppTheme.textDim)
                        }
                    }

                    Spacer()
                }
                .animation(.easeInOut(duration: 0.4), value: cpu)
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
