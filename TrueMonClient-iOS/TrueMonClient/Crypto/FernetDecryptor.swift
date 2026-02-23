import Foundation
import CommonCrypto
import CryptoKit

/// Decrypts Fernet tokens using the same format as Python's `cryptography.fernet.Fernet`.
///
/// Fernet token layout (after base64url decoding):
///   version (1 byte) | timestamp (8 bytes) | IV (16 bytes) | ciphertext (N bytes) | HMAC (32 bytes)
enum FernetDecryptor {

    enum FernetError: Error {
        case invalidToken
        case hmacVerificationFailed
        case decryptionFailed
        case invalidPadding
    }

    /// Decrypt a Fernet token (raw bytes as received over the wire, already base64url encoded).
    /// The Python Fernet library outputs base64url-encoded tokens as bytes.
    static func decrypt(token: Data, signingKey: Data, encryptionKey: Data) throws -> Data {
        // Fernet tokens are base64url-encoded
        guard let tokenString = String(data: token, encoding: .utf8) else {
            throw FernetError.invalidToken
        }

        // base64url → standard base64
        var base64 = tokenString
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Pad to multiple of 4
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }

        guard let decoded = Data(base64Encoded: base64) else {
            throw FernetError.invalidToken
        }

        // Minimum size: version(1) + timestamp(8) + IV(16) + HMAC(32) = 57 + at least 16 bytes ciphertext
        guard decoded.count >= 57 + 16 else {
            throw FernetError.invalidToken
        }

        // Extract components
        let version    = decoded[0..<1]
        let timestamp  = decoded[1..<9]
        let iv         = decoded[9..<25]
        let ciphertext = decoded[25..<(decoded.count - 32)]
        let hmacValue  = decoded[(decoded.count - 32)...]

        // Verify HMAC-SHA256 over (version + timestamp + iv + ciphertext)
        let signedData = version + timestamp + iv + ciphertext
        let symmetricKey = SymmetricKey(data: signingKey)
        let computedHMAC = HMAC<SHA256>.authenticationCode(for: signedData, using: symmetricKey)
        let computedData = Data(computedHMAC)

        guard computedData == Data(hmacValue) else {
            throw FernetError.hmacVerificationFailed
        }

        // Decrypt AES-128-CBC
        let decrypted = try aes128CBCDecrypt(
            data: Data(ciphertext),
            key: encryptionKey,
            iv: Data(iv)
        )

        // Remove PKCS7 padding
        return try removePKCS7Padding(decrypted)
    }

    private static func aes128CBCDecrypt(data: Data, key: Data, iv: Data) throws -> Data {
        let outBufferSize = data.count + kCCBlockSizeAES128
        var outData = Data(count: outBufferSize)
        var outLength = 0

        let status = outData.withUnsafeMutableBytes { outBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0), // No padding — we handle PKCS7 manually
                            keyBytes.baseAddress, key.count,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress, data.count,
                            outBytes.baseAddress, outBufferSize,
                            &outLength
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw FernetError.decryptionFailed
        }

        return outData.prefix(outLength)
    }

    private static func removePKCS7Padding(_ data: Data) throws -> Data {
        guard let lastByte = data.last else {
            throw FernetError.invalidPadding
        }
        let padLen = Int(lastByte)
        guard padLen > 0, padLen <= 16, data.count >= padLen else {
            throw FernetError.invalidPadding
        }
        // Verify all padding bytes are the same
        for i in (data.count - padLen)..<data.count {
            guard data[i] == lastByte else {
                throw FernetError.invalidPadding
            }
        }
        return data.prefix(data.count - padLen)
    }

    // MARK: - Encrypt

    /// Encrypt plaintext into a Fernet token (base64url-encoded bytes).
    static func encrypt(plaintext: Data, signingKey: Data, encryptionKey: Data) throws -> Data {
        // Random 16-byte IV
        var ivBytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, 16, &ivBytes) == errSecSuccess else {
            throw FernetError.decryptionFailed
        }
        let iv = Data(ivBytes)

        // PKCS7-pad the plaintext to 16-byte blocks
        let blockSize = 16
        let padLen = blockSize - (plaintext.count % blockSize)
        var padded = plaintext
        padded.append(contentsOf: [UInt8](repeating: UInt8(padLen), count: padLen))

        // AES-128-CBC encrypt
        let ciphertext = try aes128CBCEncrypt(data: padded, key: encryptionKey, iv: iv)

        // Build token header: version(1) + timestamp(8) + iv(16)
        let version = Data([0x80])
        var ts = UInt64(Date().timeIntervalSince1970).bigEndian
        let timestamp = Data(bytes: &ts, count: 8)

        let signedData = version + timestamp + iv + ciphertext

        // HMAC-SHA256 over signedData using signingKey
        let symmetricKey = SymmetricKey(data: signingKey)
        let mac = HMAC<SHA256>.authenticationCode(for: signedData, using: symmetricKey)
        let hmacData = Data(mac)

        let tokenRaw = signedData + hmacData

        // base64url-encode (standard base64 with + → - and / → _, no padding)
        let b64 = tokenRaw.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        return b64.data(using: .utf8)!
    }

    private static func aes128CBCEncrypt(data: Data, key: Data, iv: Data) throws -> Data {
        let outBufferSize = data.count + kCCBlockSizeAES128
        var outData = Data(count: outBufferSize)
        var outLength = 0

        let status = outData.withUnsafeMutableBytes { outBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0), // No automatic padding — we handle PKCS7 manually
                            keyBytes.baseAddress, key.count,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress, data.count,
                            outBytes.baseAddress, outBufferSize,
                            &outLength
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw FernetError.decryptionFailed
        }

        return outData.prefix(outLength)
    }
}
