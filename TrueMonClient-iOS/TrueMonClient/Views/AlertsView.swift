import SwiftUI

struct AlertsView: View {
    @EnvironmentObject var data: DataModule

    var body: some View {
        VStack(spacing: 0) {
            if data.alerts.isEmpty {
                Spacer()
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 48))
                        .foregroundColor(AppTheme.good)
                    Text("No Alerts")
                        .font(.headline)
                        .foregroundColor(AppTheme.textDim)
                }
                Spacer()
            } else {
                HStack {
                    Text("\(data.alerts.count) alert\(data.alerts.count == 1 ? "" : "s")")
                        .font(.caption)
                        .foregroundColor(AppTheme.textDim)
                    Spacer()
                    Button("Clear All") {
                        data.clearAlerts()
                    }
                    .font(.caption)
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
            // Colored left border
            RoundedRectangle(cornerRadius: 2)
                .fill(colorForLevel(alert.level))
                .frame(width: 4)

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

    private func colorForLevel(_ level: AlertLevel) -> Color {
        switch level {
        case .info:     return AppTheme.good
        case .warning:  return AppTheme.warning
        case .critical: return AppTheme.critical
        }
    }
}
