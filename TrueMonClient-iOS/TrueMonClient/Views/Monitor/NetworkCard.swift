import SwiftUI
import Charts

struct NetworkCard: View {
    let netRx: Double?
    let netTx: Double?
    let netIface: String?
    let rxHistory: [Double]
    let txHistory: [Double]

    var body: some View {
        CardContainer(title: "Network" + (netIface.map { " (\($0))" } ?? ""), accentColor: AppTheme.netAccent) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Label {
                        Text(formatBytes(netRx, perSecond: true))
                            .contentTransition(.numericText())
                    } icon: {
                        Image(systemName: "arrow.down.circle.fill")
                            .foregroundColor(AppTheme.lime)
                    }
                    .foregroundColor(AppTheme.lime)
                    .font(.system(.body, design: .monospaced))

                    Text("RX")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .tracking(2)
                        .foregroundColor(AppTheme.textDim)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 4) {
                    Label {
                        Text(formatBytes(netTx, perSecond: true))
                            .contentTransition(.numericText())
                    } icon: {
                        Image(systemName: "arrow.up.circle.fill")
                            .foregroundColor(AppTheme.cyan)
                    }
                    .foregroundColor(AppTheme.cyan)
                    .font(.system(.body, design: .monospaced))

                    Text("TX")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .tracking(2)
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
                        .foregroundStyle(by: .value("Series", "RX"))
                        .interpolationMethod(.catmullRom)
                        .lineStyle(StrokeStyle(lineWidth: 2))

                        AreaMark(
                            x: .value("Time", i),
                            y: .value("Bytes", val)
                        )
                        .foregroundStyle(by: .value("Series", "RX"))
                        .interpolationMethod(.catmullRom)
                        .opacity(0.12)
                    }
                    ForEach(Array(txHistory.enumerated()), id: \.offset) { i, val in
                        LineMark(
                            x: .value("Time", i),
                            y: .value("Bytes", val)
                        )
                        .foregroundStyle(by: .value("Series", "TX"))
                        .interpolationMethod(.catmullRom)
                        .lineStyle(StrokeStyle(lineWidth: 2))

                        AreaMark(
                            x: .value("Time", i),
                            y: .value("Bytes", val)
                        )
                        .foregroundStyle(by: .value("Series", "TX"))
                        .interpolationMethod(.catmullRom)
                        .opacity(0.08)
                    }
                }
                .chartForegroundStyleScale(["RX": AppTheme.lime, "TX": AppTheme.cyan])
                .chartLegend(.hidden)
                .chartXAxis(.hidden)
                .chartYAxis {
                    AxisMarks(position: .leading) { value in
                        AxisValueLabel {
                            if let v = value.as(Double.self) {
                                Text(formatBytes(v, perSecond: true))
                                    .font(.system(size: 9, design: .monospaced))
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
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(AppTheme.textDim)
                    }
                    Spacer()
                    if let peak = txHistory.max() {
                        Label("Peak \(formatBytes(peak, perSecond: true))", systemImage: "arrow.up")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(AppTheme.textDim)
                    }
                }
            }
        }
    }
}
