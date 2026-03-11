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
                        .foregroundColor(AppTheme.textDim)
                        .padding(.top, 40)
                } else if case .disconnected = data.connectionState {
                    VStack(spacing: 16) {
                        Image(systemName: "antenna.radiowaves.left.and.right.slash")
                            .font(.system(size: 52))
                            .foregroundStyle(AppTheme.textDim.opacity(0.6))
                            .pulseEffect(isActive: true)
                        Text("Not Connected")
                            .font(.title3.weight(.semibold))
                            .foregroundColor(AppTheme.textDim)
                        Text("Go to Settings to configure and connect")
                            .font(.subheadline)
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
        HStack(spacing: 6) {
            Image(systemName: connectionIcon)
                .font(.system(size: 11))
                .foregroundStyle(statusColor)
                .variableColorEffect(isActive: data.connectionState == .connecting)

            Text(data.connectionState.label)
                .font(.caption.weight(.medium))
                .foregroundColor(AppTheme.textDim)

            Spacer()

            if let error = data.errorMessage {
                Text(error)
                    .font(.caption2)
                    .foregroundColor(AppTheme.critical)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 8)
    }

    private var connectionIcon: String {
        switch data.connectionState {
        case .connected:    return "circle.fill"
        case .connecting:   return "antenna.radiowaves.left.and.right"
        case .disconnected: return "circle"
        case .failed:       return "exclamationmark.circle.fill"
        }
    }

    private var statusColor: Color {
        switch data.connectionState {
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
                    .font(.caption.weight(.medium))
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

/// Reusable glass card container with iOS 26 Liquid Glass effect.
struct CardContainer<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.headline.bold())
                .foregroundStyle(AppTheme.accent)
            content()
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background {
            if #available(iOS 26.0, *) {
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .fill(.ultraThinMaterial)
                    .glassEffect(in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            } else {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(AppTheme.card)
                    .overlay(
                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                            .stroke(AppTheme.cardBorder, lineWidth: 1)
                    )
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}
