import SwiftUI

/// Dark color palette matching the desktop TrueMonitor COLORS dict.
enum AppTheme {
    static let bg         = Color(hex: 0x1a1a2e)
    static let card       = Color(hex: 0x16213e)
    static let cardBorder = Color(hex: 0x0f3460)
    static let text       = Color(hex: 0xe0e0e0)
    static let textDim    = Color(hex: 0x888899)
    static let accent     = Color(hex: 0x4fc3f7)
    static let good       = Color(hex: 0x66bb6a)
    static let warning    = Color(hex: 0xffa726)
    static let critical   = Color(hex: 0xef5350)
    static let inputBg    = Color(hex: 0x0f3460)
    static let button     = Color(hex: 0x533483)
    static let buttonHover = Color(hex: 0x6a42a0)

    static var backgroundGradient: some View {
        if #available(iOS 18.0, *) {
            AnyView(
                MeshGradient(width: 3, height: 3, points: [
                    [0.0, 0.0], [0.5, 0.0], [1.0, 0.0],
                    [0.0, 0.5], [0.5, 0.5], [1.0, 0.5],
                    [0.0, 1.0], [0.5, 1.0], [1.0, 1.0]
                ], colors: [
                    Color(hex: 0x0a0e1a), Color(hex: 0x0d1428), Color(hex: 0x0a1020),
                    Color(hex: 0x121838), Color(hex: 0x1a1a3e), Color(hex: 0x0f1e38),
                    Color(hex: 0x0a1020), Color(hex: 0x0d1830), Color(hex: 0x0a1628)
                ])
            )
        } else {
            AnyView(
                LinearGradient(
                    colors: [
                        Color(hex: 0x0d1020),
                        Color(hex: 0x1a1a3e),
                        Color(hex: 0x0a1628)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
        }
    }

    /// Large metric font — rounded design for a modern dashboard feel.
    static func metricFont(size: CGFloat = 36) -> Font {
        .system(size: size, weight: .bold, design: .rounded)
    }
}

// MARK: - Symbol effect availability helpers

extension View {
    /// Applies a pulsing symbol effect on iOS 17+; no-op on older systems.
    @ViewBuilder
    func pulseEffect(isActive: Bool) -> some View {
        if #available(iOS 17.0, *) {
            self.symbolEffect(.pulse, options: .repeating, isActive: isActive)
        } else {
            self
        }
    }

    /// Applies a variable-color iterative symbol effect on iOS 17+.
    @ViewBuilder
    func variableColorEffect(isActive: Bool) -> some View {
        if #available(iOS 17.0, *) {
            self.symbolEffect(.variableColor.iterative, options: .repeating, isActive: isActive)
        } else {
            self.opacity(isActive ? 0.6 : 1.0)
        }
    }

    /// Applies a slow pulse symbol effect on iOS 17+.
    @ViewBuilder
    func slowPulseEffect(isActive: Bool) -> some View {
        if #available(iOS 17.0, *) {
            self.symbolEffect(.pulse, options: .repeating.speed(0.3), isActive: isActive)
        } else {
            self
        }
    }

    /// Uses symbol replace content transition on iOS 17+.
    @ViewBuilder
    func symbolReplaceTransition() -> some View {
        if #available(iOS 17.0, *) {
            self.contentTransition(.symbolEffect(.replace))
        } else {
            self
        }
    }
}

extension Color {
    init(hex: UInt, opacity: Double = 1.0) {
        self.init(
            .sRGB,
            red:   Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8)  & 0xFF) / 255,
            blue:  Double( hex        & 0xFF) / 255,
            opacity: opacity
        )
    }
}
