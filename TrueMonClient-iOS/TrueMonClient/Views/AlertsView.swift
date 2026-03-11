import SwiftUI

struct AlertsView: View {
    @EnvironmentObject var data: DataModule

    var body: some View {
        VStack(spacing: 0) {
            if data.alerts.isEmpty {
                Spacer()
                VStack(spacing: 16) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 52))
                        .foregroundStyle(AppTheme.good.opacity(0.6))
                        .slowPulseEffect(isActive: true)
                    Text("No Alerts")
                        .font(.title3.weight(.semibold))
                        .foregroundColor(AppTheme.textDim)
                    Text("You're all clear")
                        .font(.subheadline)
                        .foregroundColor(AppTheme.textDim.opacity(0.6))
                }
                Spacer()
            } else {
                HStack {
                    Text("\(data.alerts.count) alert\(data.alerts.count == 1 ? "" : "s")")
                        .font(.caption.weight(.medium))
                        .foregroundColor(AppTheme.textDim)
                        .contentTransition(.numericText())
                    Spacer()
                    Button {
                        data.clearAlerts()
                    } label: {
                        Label("Clear All", systemImage: "trash")
                            .font(.caption.weight(.medium))
                    }
                    .tint(AppTheme.critical)
                }
                .padding(.horizontal)
                .padding(.vertical, 8)

                List {
                    ForEach(data.alerts) { alert in
                        alertRow(alert)
                            .listRowBackground(
                                RoundedRectangle(cornerRadius: 12, style: .continuous)
                                    .fill(.ultraThinMaterial)
                                    .padding(.vertical, 2)
                            )
                            .listRowSeparator(.hidden)
                            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                Button(role: .destructive) {
                                    data.removeAlert(id: alert.id)
                                } label: {
                                    Label("Dismiss", systemImage: "trash")
                                }
                            }
                    }
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background {
            AppTheme.backgroundGradient.ignoresSafeArea()
        }
    }

    @ViewBuilder
    private func alertRow(_ alert: AlertItem) -> some View {
        HStack(spacing: 12) {
            // Colored severity icon
            Image(systemName: iconForLevel(alert.level))
                .font(.system(size: 16))
                .foregroundColor(colorForLevel(alert.level))
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 4) {
                Text(alert.message)
                    .font(.subheadline)
                    .foregroundColor(AppTheme.text)

                Text(alert.timestamp, style: .date)
                    + Text(" ")
                    + Text(alert.timestamp, style: .time)
            }
            .font(.caption)
            .foregroundColor(AppTheme.textDim)

            Spacer()
        }
        .padding(.vertical, 4)
    }

    private func iconForLevel(_ level: AlertLevel) -> String {
        switch level {
        case .info:     return "info.circle.fill"
        case .warning:  return "exclamationmark.triangle.fill"
        case .critical: return "xmark.octagon.fill"
        }
    }

    private func colorForLevel(_ level: AlertLevel) -> Color {
        switch level {
        case .info:     return AppTheme.good
        case .warning:  return AppTheme.warning
        case .critical: return AppTheme.critical
        }
    }
}
