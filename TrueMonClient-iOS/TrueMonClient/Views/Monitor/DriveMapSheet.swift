import SwiftUI

struct DriveMapSheet: View {
    let poolName: String
    let topology: [String: [VdevGroup]]
    @Environment(\.dismiss) private var dismiss

    private let groupOrder = ["data", "cache", "log", "spare", "special", "dedup"]

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if topology.isEmpty {
                        Text("No topology data available")
                            .font(.system(.body, design: .monospaced))
                            .foregroundColor(AppTheme.textDim)
                            .padding()
                    } else {
                        ForEach(groupOrder, id: \.self) { key in
                            if let vdevs = topology[key], !vdevs.isEmpty {
                                groupSection(title: key.uppercased(), vdevs: vdevs)
                            }
                        }
                    }
                }
                .padding()
            }
            .background(AppTheme.backgroundGradient.ignoresSafeArea())
            .navigationTitle("\(poolName) — Drive Map")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                        .font(.system(size: 12, weight: .bold, design: .monospaced))
                        .foregroundStyle(AppTheme.cyan)
                }
            }
            .toolbarColorScheme(.dark, for: .navigationBar)
        }
        .preferredColorScheme(.dark)
    }

    @ViewBuilder
    private func groupSection(title: String, vdevs: [VdevGroup]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .tracking(3)
                .foregroundColor(AppTheme.cyan)

            ForEach(vdevs) { vdev in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(vdev.type)
                            .font(.system(.subheadline, design: .monospaced).bold())
                            .foregroundColor(AppTheme.text)
                        Spacer()
                        Text(vdev.status)
                            .font(.system(size: 10, weight: .bold, design: .monospaced))
                            .tracking(1)
                            .foregroundColor(vdev.status == "ONLINE" ? AppTheme.lime : AppTheme.critical)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                            .background(
                                (vdev.status == "ONLINE" ? AppTheme.lime : AppTheme.critical)
                                    .opacity(0.15)
                            )
                            .clipShape(Capsule())
                    }

                    // Disk list
                    ForEach(vdev.disks) { disk in
                        HStack(spacing: 8) {
                            Image(systemName: disk.errors > 0 ? "internaldrive.trianglebadge.exclamationmark" : "internaldrive.fill")
                                .font(.caption)
                                .foregroundColor(disk.errors > 0 ? AppTheme.critical : AppTheme.lime)
                                .shadow(color: (disk.errors > 0 ? AppTheme.critical : AppTheme.lime).opacity(0.4), radius: 4)
                                .pulseEffect(isActive: disk.errors > 0)

                            Text(disk.name)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(AppTheme.text)

                            Spacer()

                            Text(disk.status)
                                .font(.system(size: 10, weight: .medium, design: .monospaced))
                                .foregroundColor(disk.status == "ONLINE" ? AppTheme.lime : AppTheme.critical)

                            if disk.errors > 0 {
                                Text("\(disk.errors) err")
                                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(AppTheme.critical)
                                    .clipShape(Capsule())
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .fill(disk.errors > 0
                                    ? AppTheme.critical.opacity(0.1)
                                    : AppTheme.lime.opacity(0.05))
                        )
                    }
                }
                .padding()
                .neonCard(accent: AppTheme.purple)
            }
        }
    }
}
