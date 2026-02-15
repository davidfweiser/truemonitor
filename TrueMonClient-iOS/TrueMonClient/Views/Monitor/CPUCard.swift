import SwiftUI

struct CPUCard: View {
    let cpuPercent: Double?
    let loadavg: [Double]?

    var body: some View {
        CardContainer(title: "CPU") {
            if let cpu = cpuPercent {
                HStack(alignment: .firstTextBaseline) {
                    Text(String(format: "%.1f%%", cpu))
                        .font(.system(size: 36, weight: .bold, design: .monospaced))
                        .foregroundColor(colorForPercent(cpu))
                    Spacer()
                }

                ProgressView(value: min(cpu, 100), total: 100)
                    .tint(colorForPercent(cpu))
                    .padding(.vertical, 4)

                if let load = loadavg, load.count >= 3 {
                    Text(String(format: "Load: %.2f  %.2f  %.2f", load[0], load[1], load[2]))
                        .font(.caption)
                        .foregroundColor(AppTheme.textDim)
                }
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
