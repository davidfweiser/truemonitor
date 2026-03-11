import SwiftUI
import Charts

struct NetworkCard: View {
    let netRx: Double?
    let netTx: Double?
    let netIface: String?
    let rxHistory: [Double]
    let txHistory: [Double]

    var body: some View {
        CardContainer(title: "Network" + (netIface.map { " (\($0))" } ?? "")) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Label {
                        Text(formatBytes(netRx, perSecond: true))
                            .contentTransition(.numericText())
                    } icon: {
                        Image(systemName: "arrow.down.circle.fill")
                            .foregroundColor(AppTheme.good)
                    }
                    .foregroundColor(AppTheme.good)
                    .font(.system(.body, design: .monospaced))

                    Text("RX")
                        .font(.caption2.weight(.medium))
                        .foregroundColor(AppTheme.textDim)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 4) {
                    Label {
                        Text(formatBytes(netTx, perSecond: true))
                            .contentTransition(.numericText())
                    } icon: {
                        Image(systemName: "arrow.up.circle.fill")
                            .foregroundColor(AppTheme.accent)
                    }
                    .foregroundColor(AppTheme.accent)
                    .font(.system(.body, design: .monospaced))

                    Text("TX")
                        .font(.caption2.weight(.medium))
                        .foregroundColor(AppTheme.textDim)
                }
            }

            if !rxHistory.isEmpty || !txHistory.isEmpty {
                Chart {
                    ForEach(Array(rxHistory.enumerated()), id: \.offset) { i, val in
                        AreaMark(
                            x: .value("Time", i),
                            y: .value("Bytes", val)
                        )
                        .foregroundStyle(
                            LinearGradient(
                                colors: [AppTheme.good.opacity(0.3), AppTheme.good.opacity(0.05)],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                        .interpolationMethod(.monotone)

                        LineMark(
                            x: .value("Time", i),
                            y: .value("Bytes", val)
                        )
                        .foregroundStyle(AppTheme.good)
                        .interpolationMethod(.monotone)
                        .lineStyle(StrokeStyle(lineWidth: 2))
                    }
                    ForEach(Array(txHistory.enumerated()), id: \.offset) { i, val in
                        AreaMark(
                            x: .value("Time", i),
                            y: .value("Bytes", val)
                        )
                        .foregroundStyle(
                            LinearGradient(
                                colors: [AppTheme.accent.opacity(0.2), AppTheme.accent.opacity(0.02)],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                        .interpolationMethod(.monotone)

                        LineMark(
                            x: .value("Time", i),
                            y: .value("Bytes", val)
                        )
                        .foregroundStyle(AppTheme.accent)
                        .interpolationMethod(.monotone)
                        .lineStyle(StrokeStyle(lineWidth: 2))
                    }
                }
                .chartLegend(.hidden)
                .chartXAxis(.hidden)
                .chartYAxis {
                    AxisMarks(position: .leading) { value in
                        AxisValueLabel {
                            if let v = value.as(Double.self) {
                                Text(formatBytes(v, perSecond: true))
                                    .font(.system(size: 9))
                                    .foregroundColor(AppTheme.textDim)
                            }
                        }
                    }
                }
                .frame(height: 130)
                .padding(.top, 8)

                HStack(spacing: 16) {
                    if let peak = rxHistory.max() {
                        Label("Peak \(formatBytes(peak, perSecond: true))", systemImage: "arrow.down")
                            .font(.caption2)
                            .foregroundColor(AppTheme.textDim)
                    }
                    Spacer()
                    if let peak = txHistory.max() {
                        Label("Peak \(formatBytes(peak, perSecond: true))", systemImage: "arrow.up")
                            .font(.caption2)
                            .foregroundColor(AppTheme.textDim)
                    }
                }
            }
        }
    }
}
