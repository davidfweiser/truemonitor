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

    static var backgroundGradient: LinearGradient {
        LinearGradient(
            colors: [
                Color(hex: 0x0d1020),
                Color(hex: 0x1a1a3e),
                Color(hex: 0x0a1628)
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
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
