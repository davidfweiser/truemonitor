import SwiftUI

struct JobsCard: View {
    let jobs: [JobInfo]

    var body: some View {
        CardContainer(title: "Active Jobs", accentColor: AppTheme.gold) {
            if jobs.isEmpty {
                Text("No active jobs")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(AppTheme.textDim)
                    .padding(.vertical, 4)
            } else {
                VStack(spacing: 12) {
                    ForEach(jobs) { job in
                        JobRow(job: job)
                    }
                }
            }
        }
    }
}

private struct JobRow: View {
    let job: JobInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(job.method)
                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                    .foregroundColor(AppTheme.gold)
                    .lineLimit(1)
                Spacer()
                Text(String(format: "%.1f%%", job.progress))
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundColor(AppTheme.gold)
                    .shadow(color: AppTheme.gold.opacity(0.4), radius: 4)
                    .contentTransition(.numericText())
            }

            ProgressView(value: job.progress, total: 100)
                .tint(AppTheme.gold)
                .animation(.easeInOut(duration: 0.5), value: job.progress)

            if let desc = job.description, !desc.isEmpty, desc != job.method {
                Text(desc)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(AppTheme.textDim)
                    .lineLimit(2)
            }
        }
    }
}
