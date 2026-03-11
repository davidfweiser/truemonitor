import SwiftUI
import Charts

struct TemperatureCard: View {
    let cpuTemp: Double?
    let tempHistory: [Double]

    var body: some View {
        CardContainer(title: "Temperature") {
            if let temp = cpuTemp {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: thermometerIcon(temp))
                        .font(.title2)
                        .foregroundColor(colorForTemp(temp))
                        .symbolReplaceTransition()

                    Text(String(format: "%.0f°C", temp))
                        .font(AppTheme.metricFont())
                        .foregroundColor(colorForTemp(temp))
                        .contentTransition(.numericText())

                    Text(statusLabel(temp))
                        .font(.callout.weight(.medium))
                        .foregroundColor(colorForTemp(temp).opacity(0.8))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(colorForTemp(temp).opacity(0.12))
                        .clipShape(Capsule())

                    Spacer()
                }
                .animation(.easeInOut(duration: 0.4), value: temp)

                if !tempHistory.isEmpty {
                    Chart {
                        // Warning zone (60-80°C)
                        RectangleMark(
                            xStart: .value("", 0),
                            xEnd: .value("", max(tempHistory.count - 1, 1)),
                            yStart: .value("", 60),
                            yEnd: .value("", 80)
                        )
                        .foregroundStyle(AppTheme.warning.opacity(0.08))

                        // Critical zone (80°C+)
                        RectangleMark(
                            xStart: .value("", 0),
                            xEnd: .value("", max(tempHistory.count - 1, 1)),
                            yStart: .value("", 80),
                            yEnd: .value("", 100)
                        )
                        .foregroundStyle(AppTheme.critical.opacity(0.08))

                        // Temperature area + line as a single series
                        ForEach(Array(tempHistory.enumerated()), id: \.offset) { i, val in
                            AreaMark(
                                x: .value("Time", i),
                                y: .value("Temp", val)
                            )
                            .interpolationMethod(.catmullRom)

                            LineMark(
                                x: .value("Time", i),
                                y: .value("Temp", val)
                            )
                            .interpolationMethod(.catmullRom)
                            .lineStyle(StrokeStyle(lineWidth: 2.5))
                        }
                        .foregroundStyle(
                            .linearGradient(
                                stops: [
                                    .init(color: AppTheme.good, location: 0),
                                    .init(color: AppTheme.warning, location: 0.5),
                                    .init(color: AppTheme.critical, location: 1.0)
                                ],
                                startPoint: .bottom,
                                endPoint: .top
                            )
                        )
                        .opacity(0.8)

                        // Threshold markers
                        RuleMark(y: .value("Warm", 60))
                            .foregroundStyle(AppTheme.warning.opacity(0.4))
                            .lineStyle(StrokeStyle(dash: [4, 4]))
                        RuleMark(y: .value("Hot", 80))
                            .foregroundStyle(AppTheme.critical.opacity(0.4))
                            .lineStyle(StrokeStyle(dash: [4, 4]))
                    }
                    .chartXAxis(.hidden)
                    .chartYScale(domain: chartDomain)
                    .chartYAxis {
                        AxisMarks(position: .leading) { value in
                            AxisValueLabel {
                                if let v = value.as(Double.self) {
                                    Text("\(Int(v))°")
                                        .font(.system(size: 9))
                                        .foregroundColor(AppTheme.textDim)
                                }
                            }
                        }
                    }
                    .frame(height: 130)
                    .padding(.top, 8)

                    if let lo = tempHistory.min(), let hi = tempHistory.max() {
                        HStack {
                            Label(String(format: "%.0f°C", lo), systemImage: "arrow.down")
                            Spacer()
                            Label(String(format: "%.0f°C", hi), systemImage: "arrow.up")
                        }
                        .font(.caption2)
                        .foregroundColor(AppTheme.textDim)
                    }
                }
            } else {
                Text("N/A")
                    .foregroundColor(AppTheme.textDim)
            }
        }
    }

    private var chartDomain: ClosedRange<Double> {
        let lo = min(tempHistory.min() ?? 20, 20)
        let hi = max(tempHistory.max() ?? 100, 85)
        return (lo - 5)...(hi + 5)
    }

    private func colorForTemp(_ t: Double) -> Color {
        if t < 60 { return AppTheme.good }
        if t < 80 { return AppTheme.warning }
        return AppTheme.critical
    }

    private func statusLabel(_ t: Double) -> String {
        if t < 60 { return "Normal" }
        if t < 80 { return "Warm" }
        return "Hot"
    }

    private func thermometerIcon(_ t: Double) -> String {
        if t < 40 { return "thermometer.low" }
        if t < 70 { return "thermometer.medium" }
        return "thermometer.high"
    }
}
