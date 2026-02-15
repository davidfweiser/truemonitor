import SwiftUI

struct ContentView: View {
    @StateObject private var service = MonitorService()
    @State private var selectedTab = 0

    var body: some View {
        TabView(selection: $selectedTab) {
            NavigationStack {
                MonitorView()
                    .navigationTitle("TrueMonitor")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbarColorScheme(.dark, for: .navigationBar)
            }
            .tag(0)
            .tabItem {
                Label("Monitor", systemImage: "gauge.with.dots.needle.67percent")
            }

            NavigationStack {
                AlertsView()
                    .navigationTitle("Alerts")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbarColorScheme(.dark, for: .navigationBar)
            }
            .tag(1)
            .tabItem {
                Label("Alerts", systemImage: "bell")
            }
            .badge(service.alerts.count)

            NavigationStack {
                SettingsView()
                    .navigationTitle("Settings")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbarColorScheme(.dark, for: .navigationBar)
            }
            .tag(2)
            .tabItem {
                Label("Settings", systemImage: "gear")
            }
        }
        .tint(AppTheme.accent)
        .environmentObject(service)
        .preferredColorScheme(.dark)
        .onOpenURL { url in
            if url.host == "settings" { selectedTab = 2 }
            else if url.host == "alerts" { selectedTab = 1 }
            else if url.host == "monitor" { selectedTab = 0 }
        }
    }
}
