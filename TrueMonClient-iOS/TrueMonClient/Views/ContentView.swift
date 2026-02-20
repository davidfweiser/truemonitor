import SwiftUI

struct ContentView: View {
    @EnvironmentObject var display: DisplayModule
    @EnvironmentObject var data: DataModule
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ZStack {
            // Rich gradient backdrop visible through glass cards
            AppTheme.backgroundGradient
                .ignoresSafeArea()

            TabView(selection: $display.selectedTab) {
                NavigationStack {
                    MonitorView()
                        .navigationTitle("TrueMonitor")
                        .navigationBarTitleDisplayMode(.large)
                        .toolbarBackground(.hidden, for: .navigationBar)
                }
                .tag(0)
                .tabItem {
                    Label("Monitor", systemImage: "gauge.with.dots.needle.67percent")
                }

                NavigationStack {
                    AlertsView()
                        .navigationTitle("Alerts")
                        .navigationBarTitleDisplayMode(.large)
                        .toolbarBackground(.hidden, for: .navigationBar)
                }
                .tag(1)
                .tabItem {
                    Label("Alerts", systemImage: "bell")
                }
                .badge(data.alerts.count)

                NavigationStack {
                    SettingsView()
                        .navigationTitle("Settings")
                        .navigationBarTitleDisplayMode(.large)
                        .toolbarBackground(.hidden, for: .navigationBar)
                }
                .tag(2)
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
            }
        }
        .tint(AppTheme.accent)
        .preferredColorScheme(.dark)
        .onChange(of: scenePhase) { newPhase in
            switch newPhase {
            case .active:
                display.didBecomeActive()
            case .background:
                display.willResignActive()
            default:
                break
            }
        }
        .onOpenURL { url in
            if url.host == "settings"        { display.selectedTab = 2 }
            else if url.host == "alerts"     { display.selectedTab = 1 }
            else if url.host == "monitor"    { display.selectedTab = 0 }
            else if url.host == "connect"    { data.connect() }
            else if url.host == "disconnect" { data.disconnect() }
        }
    }
}
