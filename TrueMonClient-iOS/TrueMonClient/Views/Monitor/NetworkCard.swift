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
                    Label(formatBytes(netRx, perSecond: true), systemImage: "arrow.down")
                        .foregroundColor(AppTheme.good)
                        .font(.system(.body, design: .monospaced))
                    Text("RX")
                        .font(.caption2)
                        .foregroundColor(AppTheme.textDim)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 4) {
                    Label(formatBytes(netTx, perSecond: true), systemImage: "arrow.up")
                        .foregroundColor(AppTheme.accent)
                        .font(.system(.body, design: .monospaced))
                    Text("TX")
                        .font(.caption2)
                        .foregroundColor(AppTheme.textDim)
                }
            }

            if !rxHistory.isEmpty || !txHistory.isEmpty {
                Chart {
                    ForEach(Array(rxHistory.enumerated()), id: \.offset) { i, val in
                        LineMark(
                            x: .value("Time", i),
                            y: .value("Bytes", val)
                        )
                        .foregroundStyle(by: .value("Series", "↓ RX"))
                        .interpolationMethod(.monotone)
                    }
                    ForEach(Array(txHistory.enumerated()), id: \.offset) { i, val in
                        LineMark(
                            x: .value("Time", i),
                            y: .value("Bytes", val)
                        )
                        .foregroundStyle(by: .value("Series", "↑ TX"))
                        .interpolationMethod(.monotone)
                    }
                }
                .chartForegroundStyleScale(["↓ RX": AppTheme.good, "↑ TX": AppTheme.accent])
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
                .frame(height: 120)
                .padding(.top, 8)

                HStack(spacing: 16) {
                    if let peak = rxHistory.max() {
                        Text("RX peak: \(formatBytes(peak, perSecond: true))")
                            .font(.caption2)
                            .foregroundColor(AppTheme.textDim)
                    }
                    if let peak = txHistory.max() {
                        Text("TX peak: \(formatBytes(peak, perSecond: true))")
                            .font(.caption2)
                            .foregroundColor(AppTheme.textDim)
                    }
                }
            }
        }
    }
}
