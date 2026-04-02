import SwiftUI

/// Cyberpunk neon color palette matching the web dashboard aesthetic.
enum AppTheme {
    // Core neon palette
    static let cyan       = Color(hex: 0x00f0ff)
    static let magenta    = Color(hex: 0xff00aa)
    static let lime       = Color(hex: 0xaaff00)
    static let orange     = Color(hex: 0xff6600)
    static let purple     = Color(hex: 0xaa44ff)
    static let blue       = Color(hex: 0x3366ff)
    static let pink       = Color(hex: 0xff44aa)
    static let gold       = Color(hex: 0xffcc00)

    // Semantic colors (mapped to neon palette)
    static let bg         = Color(hex: 0x06080f)
    static let card       = Color(hex: 0x0a1228)
    static let cardBorder = Color(hex: 0x0a1228).opacity(0.5)
    static let text       = Color(hex: 0xe8eaf6)
    static let textDim    = Color(hex: 0xc8d0f0, opacity: 0.5)
    static let accent     = cyan
    static let good       = Color(hex: 0x66bb6a)
    static let warning    = Color(hex: 0xffa726)
    static let critical   = Color(hex: 0xef5350)
    static let inputBg    = Color(hex: 0x0f1940)
    static let button     = purple
    static let buttonHover = Color(hex: 0x6a42a0)

    // Card-specific accent colors
    static let cpuAccent  = cyan
    static let memAccent  = magenta
    static let netAccent  = lime
    static let tempAccent = orange
    static let poolAccent = purple

    static var backgroundGradient: some View {
        if #available(iOS 18.0, *) {
            AnyView(
                MeshGradient(width: 3, height: 3, points: [
                    [0.0, 0.0], [0.5, 0.0], [1.0, 0.0],
                    [0.0, 0.5], [0.5, 0.5], [1.0, 0.5],
                    [0.0, 1.0], [0.5, 1.0], [1.0, 1.0]
                ], colors: [
                    Color(hex: 0x06080f), Color(hex: 0x080c18), Color(hex: 0x06080f),
                    Color(hex: 0x0a1228), Color(hex: 0x0c1020), Color(hex: 0x080e1c),
                    Color(hex: 0x06080f), Color(hex: 0x0a0e1a), Color(hex: 0x06080f)
                ])
            )
        } else {
            AnyView(
                LinearGradient(
                    colors: [
                        Color(hex: 0x06080f),
                        Color(hex: 0x0c1020),
                        Color(hex: 0x06080f)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
        }
    }

    /// Large metric font — monospaced geometric for cyberpunk feel.
    static func metricFont(size: CGFloat = 36) -> Font {
        .system(size: size, weight: .bold, design: .monospaced)
    }

    /// Neon glow shadow for a given color.
    static func neonGlow(_ color: Color, radius: CGFloat = 12) -> some View {
        EmptyView()
            .shadow(color: color.opacity(0.4), radius: radius)
    }
}

// MARK: - Neon card style

struct NeonCardStyle: ViewModifier {
    var accentColor: Color = AppTheme.cyan
    var glowRadius: CGFloat = 0

    func body(content: Content) -> some View {
        content
            .background {
                if #available(iOS 26.0, *) {
                    RoundedRectangle(cornerRadius: 20, style: .continuous)
                        .fill(.ultraThinMaterial)
                        .glassEffect(in: RoundedRectangle(cornerRadius: 20, style: .continuous))
                } else {
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(AppTheme.card.opacity(0.85))
                        .overlay(
                            RoundedRectangle(cornerRadius: 16, style: .continuous)
                                .stroke(accentColor.opacity(0.12), lineWidth: 1)
                        )
                        .shadow(color: accentColor.opacity(glowRadius > 0 ? 0.08 : 0), radius: glowRadius)
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}

extension View {
    func neonCard(accent: Color = AppTheme.cyan, glow: CGFloat = 0) -> some View {
        modifier(NeonCardStyle(accentColor: accent, glowRadius: glow))
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
