import SwiftUI
import Charts

struct TemperatureCard: View {
    let cpuTemp: Double?
    let tempHistory: [Double]

    var body: some View {
        CardContainer(title: "Temperature") {
            if let temp = cpuTemp {
                HStack(alignment: .firstTextBaseline) {
                    Text(String(format: "%.0f°C", temp))
                        .font(.system(size: 36, weight: .bold, design: .monospaced))
                        .foregroundColor(colorForTemp(temp))
                    Text(statusLabel(temp))
                        .font(.callout)
                        .foregroundColor(colorForTemp(temp))
                    Spacer()
                }

                if !tempHistory.isEmpty {
                    Chart {
                        // Warning zone (60-80°C)
                        RectangleMark(
                            xStart: .value("", 0),
                            xEnd: .value("", max(tempHistory.count - 1, 1)),
                            yStart: .value("", 60),
                            yEnd: .value("", 80)
                        )
                        .foregroundStyle(AppTheme.warning.opacity(0.1))

                        // Critical zone (80°C+)
                        RectangleMark(
                            xStart: .value("", 0),
                            xEnd: .value("", max(tempHistory.count - 1, 1)),
                            yStart: .value("", 80),
                            yEnd: .value("", 100)
                        )
                        .foregroundStyle(AppTheme.critical.opacity(0.1))

                        // Temperature line
                        ForEach(Array(tempHistory.enumerated()), id: \.offset) { i, val in
                            LineMark(
                                x: .value("Time", i),
                                y: .value("Temp", val)
                            )
                            .foregroundStyle(colorForTemp(val))
                            .interpolationMethod(.monotone)
                        }

                        // Threshold markers
                        RuleMark(y: .value("Warm", 60))
                            .foregroundStyle(AppTheme.warning.opacity(0.5))
                            .lineStyle(StrokeStyle(dash: [4, 4]))
                        RuleMark(y: .value("Hot", 80))
                            .foregroundStyle(AppTheme.critical.opacity(0.5))
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
                    .frame(height: 120)
                    .padding(.top, 8)

                    if let lo = tempHistory.min(), let hi = tempHistory.max() {
                        Text(String(format: "Range: %.0f°C – %.0f°C", lo, hi))
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
}
