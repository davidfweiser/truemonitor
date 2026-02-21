import SwiftUI
import BackgroundTasks

// MARK: - DisplayModule
// Manages display-only state. Does not own any data.
//
// The display layer naturally sleeps when the iPhone screen turns off or the
// app is minimized — SwiftUI stops rendering and this object goes idle.
// DataModule continues running (kept alive by background audio).
//
// When the user opens the app again, SwiftUI re-renders and views immediately
// show the current live data that DataModule has been collecting.
@MainActor
final class DisplayModule: ObservableObject {

    /// The currently selected tab (Monitor / Alerts / Settings).
    @Published var selectedTab: Int = 0

    // MARK: - Scene Lifecycle

    /// Called when the app becomes active (screen on, app in foreground).
    /// DataModule is already running; views automatically reflect its latest state.
    func didBecomeActive() {
        DataModule.shared.reconnectIfNeeded()
    }

    /// Called when the app enters the background (screen off or app minimized).
    /// DataModule keeps the connection alive via background audio.
    func willResignActive() {
        DataModule.shared.beginBackgroundExecution()
        DataModule.shared.scheduleBackgroundRefresh()
    }
}

// MARK: - App Entry Point

@main
struct TrueMonClientApp: App {

    /// Display module lives here — one instance for the lifetime of the app.
    @StateObject private var display = DisplayModule()

    init() {
        // Initialize DataModule.shared early so background task handlers are
        // registered and notification permission is requested before the first scene renders.
        DataModule.shared.registerBackgroundTask()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(display)
                .environmentObject(DataModule.shared)
        }
    }
}
