import SwiftUI

struct PoolCard: View {
    let pool: PoolInfo
    @State private var showDriveMap = false

    var body: some View {
        CardContainer(title: pool.name, accentColor: AppTheme.poolAccent) {
            if let pct = pool.percent {
                HStack(alignment: .center, spacing: 16) {
                    // Circular gauge
                    Gauge(value: min(pct, 100), in: 0...100) {
                        Image(systemName: "internaldrive")
                    } currentValueLabel: {
                        Text("\(Int(pct))")
                            .font(.system(size: 14, weight: .bold, design: .monospaced))
                            .foregroundColor(neonColorForPercent(pct))
                            .contentTransition(.numericText())
                    }
                    .gaugeStyle(.accessoryCircular)
                    .tint(Gradient(colors: [AppTheme.purple, AppTheme.magenta, AppTheme.critical]))
                    .scaleEffect(1.2)
                    .frame(width: 52, height: 52)

                    VStack(alignment: .leading, spacing: 4) {
                        Text(String(format: "%.1f%%", pct))
                            .font(AppTheme.metricFont(size: 28))
                            .foregroundColor(neonColorForPercent(pct))
                            .shadow(color: neonColorForPercent(pct).opacity(0.3), radius: 6)
                            .contentTransition(.numericText())

                        HStack(spacing: 12) {
                            Label("Used: \(formatBytes(pool.used.map(Double.init)))", systemImage: "square.fill")
                                .foregroundColor(neonColorForPercent(pct))
                            Label("Free: \(formatBytes(pool.available.map(Double.init)))", systemImage: "square")
                                .foregroundColor(AppTheme.textDim)
                        }
                        .font(.system(size: 10, design: .monospaced))

                        Text("Total: \(formatBytes(pool.total.map(Double.init)))")
                            .font(.system(size: 10, design: .monospaced))
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
                                .foregroundColor(disk.hasError ? AppTheme.critical : AppTheme.lime)
                                .shadow(color: (disk.hasError ? AppTheme.critical : AppTheme.lime).opacity(0.4), radius: 4)
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
                Label("DRIVE MAP", systemImage: "internaldrive")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .tracking(1)
            }
            .buttonStyle(.bordered)
            .tint(AppTheme.purple)
            .padding(.top, 4)
            .sheet(isPresented: $showDriveMap) {
                DriveMapSheet(poolName: pool.name, topology: pool.topology ?? [:])
            }
        }
    }

    private func neonColorForPercent(_ pct: Double) -> Color {
        if pct < 70 { return AppTheme.lime }
        if pct < 85 { return AppTheme.gold }
        return AppTheme.magenta
    }
}
