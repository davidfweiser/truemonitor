import SwiftUI

struct PoolCard: View {
    let pool: PoolInfo
    @State private var showDriveMap = false

    var body: some View {
        CardContainer(title: pool.name) {
            if let pct = pool.percent {
                HStack(alignment: .center, spacing: 16) {
                    // Circular gauge
                    Gauge(value: min(pct, 100), in: 0...100) {
                        Image(systemName: "internaldrive")
                    } currentValueLabel: {
                        Text("\(Int(pct))")
                            .font(.system(size: 14, weight: .bold, design: .rounded))
                            .foregroundColor(colorForPercent(pct))
                            .contentTransition(.numericText())
                    }
                    .gaugeStyle(.accessoryCircular)
                    .tint(Gradient(colors: [AppTheme.good, AppTheme.warning, AppTheme.critical]))
                    .scaleEffect(1.2)
                    .frame(width: 52, height: 52)

                    VStack(alignment: .leading, spacing: 4) {
                        Text(String(format: "%.1f%%", pct))
                            .font(AppTheme.metricFont(size: 28))
                            .foregroundColor(colorForPercent(pct))
                            .contentTransition(.numericText())

                        HStack(spacing: 12) {
                            Label("Used: \(formatBytes(pool.used.map(Double.init)))", systemImage: "square.fill")
                                .foregroundColor(colorForPercent(pct))
                            Label("Free: \(formatBytes(pool.available.map(Double.init)))", systemImage: "square")
                                .foregroundColor(AppTheme.textDim)
                        }
                        .font(.caption2)

                        Text("Total: \(formatBytes(pool.total.map(Double.init)))")
                            .font(.caption2)
                            .foregroundColor(AppTheme.textDim)
                    }

                    Spacer()
                }
                .animation(.easeInOut(duration: 0.4), value: pct)
            }

            // Disk health grid
            if let disks = pool.disks, !disks.isEmpty {
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 6), count: min(disks.count, 8)), spacing: 6) {
                    ForEach(disks) { disk in
                        VStack(spacing: 2) {
                            Image(systemName: "internaldrive.fill")
                                .font(.system(size: 14))
                                .foregroundColor(disk.hasError ? AppTheme.critical : AppTheme.good)
                                .pulseEffect(isActive: disk.hasError)
                            Text(disk.shortName)
                                .font(.system(size: 8, design: .monospaced))
                                .foregroundColor(AppTheme.textDim)
                                .lineLimit(1)
                        }
                        .frame(minWidth: 32)
                    }
                }
                .padding(.top, 4)
            }

            // Drive Map button
            Button {
                showDriveMap = true
            } label: {
                Label("Drive Map", systemImage: "internaldrive")
                    .font(.caption.weight(.medium))
            }
            .buttonStyle(.bordered)
            .tint(AppTheme.accent)
            .padding(.top, 4)
            .sheet(isPresented: $showDriveMap) {
                DriveMapSheet(poolName: pool.name, topology: pool.topology ?? [:])
            }
        }
    }

    private func colorForPercent(_ pct: Double) -> Color {
        if pct < 70 { return AppTheme.good }
        if pct < 85 { return AppTheme.warning }
        return AppTheme.critical
    }
}
