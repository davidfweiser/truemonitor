import SwiftUI

struct ContentView: View {
    @EnvironmentObject var display: DisplayModule
    @EnvironmentObject var data: DataModule
    @Environment(\.scenePhase) private var scenePhase
    @State private var menuOpen = false

    var body: some View {
        ZStack(alignment: .topLeading) {
            AppTheme.backgroundGradient
                .ignoresSafeArea()

            // Active tab content — fills the full screen including safe areas
            activeView
                .ignoresSafeArea()
                .id(display.selectedTab)
                .transition(.opacity)
                .animation(.easeInOut(duration: 0.18), value: display.selectedTab)

            // Dim backdrop — tap to close
            if menuOpen {
                Color.black.opacity(0.35)
                    .ignoresSafeArea()
                    .onTapGesture {
                        withAnimation(.spring(response: 0.28, dampingFraction: 0.8)) {
                            menuOpen = false
                        }
                    }
                    .transition(.opacity)
            }

            // Floating glass menu button + animated drawer
            VStack(alignment: .leading, spacing: 10) {
                Button {
                    withAnimation(.spring(response: 0.32, dampingFraction: 0.72)) {
                        menuOpen.toggle()
                    }
                } label: {
                    Image(systemName: menuOpen ? "xmark" : "line.3.horizontal")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(.white)
                        .frame(width: 42, height: 42)
                        .background(GlassPanel(cornerRadius: 13))
                }
                .buttonStyle(.plain)

                if menuOpen {
                    VStack(alignment: .leading, spacing: 2) {
                        GlassMenuRow(
                            icon: "gauge.with.dots.needle.67percent",
                            label: "Monitor",
                            isSelected: display.selectedTab == 0
                        ) {
                            select(tab: 0)
                        }
                        Divider().overlay(.white.opacity(0.1))
                        GlassMenuRow(
                            icon: "bell",
                            label: "Alerts",
                            badge: data.alerts.count,
                            isSelected: display.selectedTab == 1
                        ) {
                            select(tab: 1)
                        }
                        Divider().overlay(.white.opacity(0.1))
                        GlassMenuRow(
                            icon: "gear",
                            label: "Settings",
                            isSelected: display.selectedTab == 2
                        ) {
                            select(tab: 2)
                        }
                    }
                    .padding(8)
                    .frame(width: 210)
                    .background(GlassPanel(cornerRadius: 18))
                    .transition(
                        .asymmetric(
                            insertion: .scale(scale: 0.82, anchor: .topLeading).combined(with: .opacity),
                            removal:   .scale(scale: 0.82, anchor: .topLeading).combined(with: .opacity)
                        )
                    )
                }
            }
            .padding(.top, 8)
            .padding(.leading, 16)
        }
        .tint(AppTheme.accent)
        .preferredColorScheme(.dark)
        .onChange(of: scenePhase) { newPhase in
            switch newPhase {
            case .active:     display.didBecomeActive()
            case .background: display.willResignActive()
            default: break
            }
        }
        .onOpenURL { url in
            if      url.host == "settings"    { display.selectedTab = 2 }
            else if url.host == "alerts"      { display.selectedTab = 1 }
            else if url.host == "monitor"     { display.selectedTab = 0 }
            else if url.host == "connect"     { data.connect() }
            else if url.host == "disconnect"  { data.disconnect() }
        }
    }

    private func select(tab: Int) {
        withAnimation(.spring(response: 0.28, dampingFraction: 0.8)) {
            display.selectedTab = tab
            menuOpen = false
        }
    }

    @ViewBuilder
    private var activeView: some View {
        switch display.selectedTab {
        case 1:
            NavigationStack {
                AlertsView()
                    .navigationTitle("Alerts")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbarBackground(.hidden, for: .navigationBar)
            }
        case 2:
            NavigationStack {
                SettingsView()
                    .navigationTitle("Settings")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbarBackground(.hidden, for: .navigationBar)
            }
        default:
            NavigationStack {
                MonitorView()
                    .navigationTitle("TrueMonitor")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbarBackground(.hidden, for: .navigationBar)
            }
        }
    }
}

// MARK: - Glass background shape

private struct GlassPanel: View {
    let cornerRadius: CGFloat

    var body: some View {
        if #available(iOS 26.0, *) {
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .fill(.ultraThinMaterial)
                .glassEffect(in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
        } else {
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .fill(AppTheme.card.opacity(0.9))
                .overlay(
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .stroke(.white.opacity(0.14), lineWidth: 1)
                )
        }
    }
}

// MARK: - Menu row

private struct GlassMenuRow: View {
    let icon: String
    let label: String
    var badge: Int = 0
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                ZStack(alignment: .topTrailing) {
                    Image(systemName: icon)
                        .font(.system(size: 16))
                        .foregroundStyle(isSelected ? AppTheme.accent : .white.opacity(0.82))
                        .frame(width: 22, height: 22)
                    if badge > 0 {
                        Text("\(min(badge, 99))")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 4)
                            .padding(.vertical, 2)
                            .background(AppTheme.critical)
                            .clipShape(Capsule())
                            .offset(x: 10, y: -8)
                    }
                }

                Text(label)
                    .font(.system(size: 15, weight: isSelected ? .semibold : .regular))
                    .foregroundStyle(isSelected ? AppTheme.accent : .white.opacity(0.88))

                Spacer()

                if isSelected {
                    Image(systemName: "checkmark")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(AppTheme.accent)
                }
            }
            .padding(.vertical, 10)
            .padding(.horizontal, 12)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
