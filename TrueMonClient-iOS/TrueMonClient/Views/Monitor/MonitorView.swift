import SwiftUI

struct MonitorView: View {
    @EnvironmentObject var data: DataModule

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                // Connection status header
                connectionHeader

                if let stats = data.stats {
                    // System info
                    systemInfoRow(stats)

                    CPUCard(
                        cpuPercent: stats.cpuPercent,
                        loadavg: stats.loadavg
                    )

                    MemoryCard(
                        memoryPercent: stats.memoryPercent,
                        memoryUsed: stats.memoryUsed,
                        memoryTotal: stats.memoryTotal
                    )

                    NetworkCard(
                        netRx: stats.netRx,
                        netTx: stats.netTx,
                        netIface: stats.netIface,
                        rxHistory: data.netRxHistory,
                        txHistory: data.netTxHistory
                    )

                    TemperatureCard(
                        cpuTemp: stats.cpuTemp,
                        tempHistory: data.tempHistory
                    )

                    // Pool cards
                    if let pools = stats.pools {
                        ForEach(pools) { pool in
                            PoolCard(pool: pool)
                        }
                    }
                } else if data.connectionState == .connected {
                    Text("Waiting for data...")
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(AppTheme.textDim)
                        .padding(.top, 40)
                } else if case .disconnected = data.connectionState {
                    VStack(spacing: 16) {
                        Image(systemName: "antenna.radiowaves.left.and.right.slash")
                            .font(.system(size: 52))
                            .foregroundStyle(AppTheme.cyan.opacity(0.3))
                            .pulseEffect(isActive: true)
                        Text("Not Connected")
                            .font(.system(.title3, design: .monospaced).weight(.semibold))
                            .foregroundColor(AppTheme.textDim)
                        Text("Go to Settings to configure and connect")
                            .font(.system(.subheadline, design: .monospaced))
                            .foregroundColor(AppTheme.textDim.opacity(0.7))
                    }
                    .padding(.top, 80)
                }
            }
            .padding(.horizontal)
            .padding(.bottom, 20)
        }
        .background {
            AppTheme.backgroundGradient.ignoresSafeArea()
        }
    }

    private var connectionHeader: some View {
        HStack(spacing: 8) {
            // Glowing status dot
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
                .shadow(color: statusColor.opacity(0.6), radius: 6)

            Text(data.connectionState.label.uppercased())
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .tracking(2)
                .foregroundColor(statusColor)

            Spacer()

            if let error = data.errorMessage {
                Text(error)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(AppTheme.critical)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 8)
    }

    private var statusColor: Color {
        switch data.connectionState {
        case .connected:    return AppTheme.lime
        case .connecting:   return AppTheme.gold
        case .disconnected: return AppTheme.textDim
        case .failed:       return AppTheme.critical
        }
    }

    @ViewBuilder
    private func systemInfoRow(_ stats: ServerStats) -> some View {
        HStack {
            if let host = stats.hostname {
                Label(host, systemImage: "server.rack")
                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                    .foregroundColor(AppTheme.cyan)
            }
            Spacer()
            if let uptime = stats.uptime {
                Label(uptime, systemImage: "clock")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(AppTheme.textDim)
            }
        }
        .padding(.vertical, 4)
    }
}

/// Reusable neon card container with iOS 26 Liquid Glass effect.
struct CardContainer<Content: View>: View {
    let title: String
    var accentColor: Color = AppTheme.cyan
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title.uppercased())
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .tracking(3)
                .foregroundStyle(accentColor)
            content()
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .neonCard(accent: accentColor)
    }
}
