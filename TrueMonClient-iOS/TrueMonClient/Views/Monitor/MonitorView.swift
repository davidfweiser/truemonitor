import SwiftUI

struct MonitorView: View {
    @EnvironmentObject var service: MonitorService

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                // Connection status header
                connectionHeader

                if let stats = service.stats {
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
                        rxHistory: service.netRxHistory,
                        txHistory: service.netTxHistory
                    )

                    TemperatureCard(
                        cpuTemp: stats.cpuTemp,
                        tempHistory: service.tempHistory
                    )

                    // Pool cards
                    if let pools = stats.pools {
                        ForEach(pools) { pool in
                            PoolCard(pool: pool)
                        }
                    }
                } else if service.connectionState == .connected {
                    Text("Waiting for data...")
                        .foregroundColor(AppTheme.textDim)
                        .padding(.top, 40)
                } else if case .disconnected = service.connectionState {
                    VStack(spacing: 12) {
                        Image(systemName: "antenna.radiowaves.left.and.right.slash")
                            .font(.system(size: 48))
                            .foregroundColor(AppTheme.textDim)
                        Text("Not Connected")
                            .font(.headline)
                            .foregroundColor(AppTheme.textDim)
                        Text("Go to Settings to configure and connect")
                            .font(.caption)
                            .foregroundColor(AppTheme.textDim)
                    }
                    .padding(.top, 60)
                }
            }
            .padding(.horizontal)
            .padding(.bottom, 20)
        }
        .background(AppTheme.bg)
    }

    private var connectionHeader: some View {
        HStack {
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
            Text(service.connectionState.label)
                .font(.caption)
                .foregroundColor(AppTheme.textDim)

            Spacer()

            if let error = service.errorMessage {
                Text(error)
                    .font(.caption2)
                    .foregroundColor(AppTheme.critical)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 8)
    }

    private var statusColor: Color {
        switch service.connectionState {
        case .connected:    return AppTheme.good
        case .connecting:   return AppTheme.warning
        case .disconnected: return AppTheme.textDim
        case .failed:       return AppTheme.critical
        }
    }

    @ViewBuilder
    private func systemInfoRow(_ stats: ServerStats) -> some View {
        HStack {
            if let host = stats.hostname {
                Label(host, systemImage: "server.rack")
                    .font(.caption)
                    .foregroundColor(AppTheme.accent)
            }
            Spacer()
            if let uptime = stats.uptime {
                Label(uptime, systemImage: "clock")
                    .font(.caption)
                    .foregroundColor(AppTheme.textDim)
            }
        }
        .padding(.vertical, 4)
    }
}

/// Reusable dark card container matching the desktop design.
struct CardContainer<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)
                .foregroundColor(AppTheme.accent)
            content()
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppTheme.card)
        .cornerRadius(12)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(AppTheme.cardBorder, lineWidth: 1)
        )
    }
}
