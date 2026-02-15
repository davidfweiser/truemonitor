import Foundation
import CommonCrypto

/// PBKDF2-HMAC-SHA256 key derivation matching the Python `_derive_broadcast_key()`.
enum KeyDerivation {

    /// Derives a 32-byte key from the shared passphrase using the same parameters
    /// as the Python server: PBKDF2-HMAC-SHA256, 100k iterations, constant salt.
    /// Returns (signingKey: 16 bytes, encryptionKey: 16 bytes).
    static func deriveFernetKey(passphrase: String) -> (signingKey: Data, encryptionKey: Data)? {
        let salt = "truemonitor_broadcast_v1".data(using: .utf8)!
        let passphraseData = passphrase.data(using: .utf8)!

        var derivedKey = Data(count: 32)
        let status = derivedKey.withUnsafeMutableBytes { derivedBytes in
            passphraseData.withUnsafeBytes { passphraseBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passphraseBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                        passphraseData.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        100_000,
                        derivedBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        32
                    )
                }
            }
        }

        guard status == kCCSuccess else { return nil }

        // Python's Fernet base64url-encodes the 32 raw bytes, then uses
        // bytes 0..15 as signing key and bytes 16..31 as encryption key.
        let signingKey    = derivedKey[0..<16]
        let encryptionKey = derivedKey[16..<32]
        return (signingKey: Data(signingKey), encryptionKey: Data(encryptionKey))
    }
}
