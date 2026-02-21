import SwiftUI

struct PoolCard: View {
    let pool: PoolInfo
    @State private var showDriveMap = false

    var body: some View {
        CardContainer(title: pool.name) {
            if let pct = pool.percent {
                HStack(alignment: .firstTextBaseline) {
                    Text(String(format: "%.1f%%", pct))
                        .font(.system(size: 28, weight: .bold, design: .monospaced))
                        .foregroundColor(colorForPercent(pct))
                    Spacer()
                }

                ProgressView(value: min(pct, 100), total: 100)
                    .tint(colorForPercent(pct))
                    .padding(.vertical, 4)
            }

            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Used: \(formatBytes(pool.used.map(Double.init)))")
                    Text("Free: \(formatBytes(pool.available.map(Double.init)))")
                    Text("Total: \(formatBytes(pool.total.map(Double.init)))")
                }
                .font(.caption)
                .foregroundColor(AppTheme.textDim)
                Spacer()
            }

            // Disk health dots
            if let disks = pool.disks, !disks.isEmpty {
                HStack(spacing: 4) {
                    Text("Disks:")
                        .font(.caption)
                        .foregroundColor(AppTheme.textDim)

                    ForEach(disks) { disk in
                        Circle()
                            .fill(disk.hasError ? AppTheme.critical : AppTheme.good)
                            .frame(width: 12, height: 12)
                            .help(disk.name)
                    }
                    Spacer()
                }
                .padding(.top, 4)
            }

            // Drive Map button
            Button {
                showDriveMap = true
            } label: {
                Label("Drive Map", systemImage: "internaldrive")
                    .font(.caption)
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
