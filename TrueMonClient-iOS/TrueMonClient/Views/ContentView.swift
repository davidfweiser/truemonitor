import SwiftUI

struct ContentView: View {
    @EnvironmentObject var display: DisplayModule
    @EnvironmentObject var data: DataModule
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            if #available(iOS 18.0, *) {
                modernTabView
            } else {
                legacyTabView
            }
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

    // MARK: - iOS 18+ Tab view (liquid glass on iOS 26)

    @available(iOS 18.0, *)
    private var modernTabView: some View {
        TabView(selection: $display.selectedTab) {
            Tab("Monitor", systemImage: "gauge.with.dots.needle.67percent", value: 0) {
                NavigationStack {
                    MonitorView()
                        .navigationTitle("TrueMonitor")
                        .navigationBarTitleDisplayMode(.large)
                }
            }

            Tab("Alerts", systemImage: "bell.badge", value: 1) {
                NavigationStack {
                    AlertsView()
                        .navigationTitle("Alerts")
                        .navigationBarTitleDisplayMode(.large)
                }
            }
            .badge(data.alerts.count)

            Tab("Settings", systemImage: "gear", value: 2) {
                NavigationStack {
                    SettingsView()
                        .navigationTitle("Settings")
                        .navigationBarTitleDisplayMode(.large)
                }
            }
        }
    }

    // MARK: - iOS 16-17 fallback

    private var legacyTabView: some View {
        TabView(selection: $display.selectedTab) {
            NavigationStack {
                MonitorView()
                    .navigationTitle("TrueMonitor")
                    .navigationBarTitleDisplayMode(.large)
            }
            .tabItem {
                Label("Monitor", systemImage: "gauge.with.dots.needle.67percent")
            }
            .tag(0)

            NavigationStack {
                AlertsView()
                    .navigationTitle("Alerts")
                    .navigationBarTitleDisplayMode(.large)
            }
            .tabItem {
                Label("Alerts", systemImage: "bell.badge")
            }
            .badge(data.alerts.count)
            .tag(1)

            NavigationStack {
                SettingsView()
                    .navigationTitle("Settings")
                    .navigationBarTitleDisplayMode(.large)
            }
            .tabItem {
                Label("Settings", systemImage: "gear")
            }
            .tag(2)
        }
    }
}
