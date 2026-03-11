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
                        .foregroundStyle(AppTheme.accent)
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
                .font(.headline)
                .foregroundColor(AppTheme.accent)

            ForEach(vdevs) { vdev in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(vdev.type)
                            .font(.subheadline.bold())
                            .foregroundColor(AppTheme.text)
                        Spacer()
                        Text(vdev.status)
                            .font(.caption.weight(.medium))
                            .foregroundColor(vdev.status == "ONLINE" ? AppTheme.good : AppTheme.critical)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(
                                (vdev.status == "ONLINE" ? AppTheme.good : AppTheme.critical)
                                    .opacity(0.15)
                            )
                            .clipShape(Capsule())
                    }

                    // Disk list
                    ForEach(vdev.disks) { disk in
                        HStack(spacing: 8) {
                            Image(systemName: disk.errors > 0 ? "internaldrive.trianglebadge.exclamationmark" : "internaldrive.fill")
                                .font(.caption)
                                .foregroundColor(disk.errors > 0 ? AppTheme.critical : AppTheme.good)
                                .pulseEffect(isActive: disk.errors > 0)

                            Text(disk.name)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(AppTheme.text)

                            Spacer()

                            Text(disk.status)
                                .font(.caption2.weight(.medium))
                                .foregroundColor(disk.status == "ONLINE" ? AppTheme.good : AppTheme.critical)

                            if disk.errors > 0 {
                                Text("\(disk.errors) err")
                                    .font(.caption2.weight(.semibold))
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
                                    ? Color(hex: 0x5c1a1a)
                                    : Color(hex: 0x1a2a1a))
                        )
                    }
                }
                .padding()
                .background {
                    if #available(iOS 26.0, *) {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(.ultraThinMaterial)
                            .glassEffect(in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    } else {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(AppTheme.card)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12, style: .continuous)
                                    .stroke(AppTheme.cardBorder, lineWidth: 1)
                            )
                    }
                }
            }
        }
    }
}
