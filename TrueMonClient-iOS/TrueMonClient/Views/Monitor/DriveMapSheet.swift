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
            .background(AppTheme.bg)
            .navigationTitle("\(poolName) — Drive Map")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                        .foregroundStyle(AppTheme.cardBorder)
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
                            .font(.caption)
                            .foregroundColor(vdev.status == "ONLINE" ? AppTheme.good : AppTheme.critical)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(
                                (vdev.status == "ONLINE" ? AppTheme.good : AppTheme.critical)
                                    .opacity(0.15)
                            )
                            .clipShape(Capsule())
                    }

                    // Disk list
                    ForEach(vdev.disks) { disk in
                        HStack(spacing: 8) {
                            Image(systemName: "internaldrive")
                                .font(.caption)
                                .foregroundColor(disk.errors > 0 ? AppTheme.critical : AppTheme.textDim)

                            Text(disk.name)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(AppTheme.text)

                            Spacer()

                            Text(disk.status)
                                .font(.caption2)
                                .foregroundColor(disk.status == "ONLINE" ? AppTheme.good : AppTheme.critical)

                            if disk.errors > 0 {
                                Text("\(disk.errors) err")
                                    .font(.caption2)
                                    .foregroundColor(AppTheme.critical)
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 4)
                        .background(
                            disk.errors > 0
                                ? Color(hex: 0x5c1a1a)
                                : Color(hex: 0x1a2a1a)
                        )
                        .cornerRadius(4)
                    }
                }
                .padding()
                .background(AppTheme.card)
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(AppTheme.cardBorder, lineWidth: 1)
                )
            }
        }
    }
}
