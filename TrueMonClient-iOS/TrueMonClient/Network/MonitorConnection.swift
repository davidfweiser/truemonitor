import Foundation
import Network
import CommonCrypto

/// TCP client that connects to a TrueMonitor broadcast server,
/// reads length-prefixed Fernet-encrypted JSON frames, and decodes them.
final class MonitorConnection {

    enum State: Equatable {
        case disconnected
        case connecting
        case connected
        case failed(String)
    }

    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "MonitorConnection", qos: .utility)

    private var signingKey: Data?
    private var encryptionKey: Data?
    private var rawKey: Data?

    var onStats: ((ServerStats) -> Void)?
    var onStateChange: ((State) -> Void)?
    var onError: ((String) -> Void)?

    private var isRunning = false

    // TRUEMON_AUTH\n as bytes (13 bytes)
    private static let authMagic = "TRUEMON_AUTH\n".data(using: .utf8)!

    func connect(host: String, port: UInt16, passphrase: String) {
        disconnect()

        guard let keys = KeyDerivation.deriveFernetKey(passphrase: passphrase),
              let raw = KeyDerivation.deriveRawKey(passphrase: passphrase) else {
            onError?("Key derivation failed")
            onStateChange?(.failed("Key derivation failed"))
            return
        }
        signingKey = keys.signingKey
        encryptionKey = keys.encryptionKey
        rawKey = raw

        let nwHost = NWEndpoint.Host(host)
        let nwPort = NWEndpoint.Port(rawValue: port)!

        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.enableKeepalive = true
        tcpOptions.keepaliveIdle = 10

        let params = NWParameters(tls: nil, tcp: tcpOptions)

        let conn = NWConnection(host: nwHost, port: nwPort, using: params)
        connection = conn
        isRunning = true

        conn.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                // Don't report .connected yet — wait for auth to complete
                self.readAuthMagic()
            case .waiting(let error):
                self.onStateChange?(.failed("Waiting: \(error.localizedDescription)"))
            case .failed(let error):
                self.onStateChange?(.failed(error.localizedDescription))
                self.onError?(error.localizedDescription)
            case .cancelled:
                self.onStateChange?(.disconnected)
            case .preparing:
                self.onStateChange?(.connecting)
            default:
                break
            }
        }

        onStateChange?(.connecting)
        conn.start(queue: queue)
    }

    func disconnect() {
        isRunning = false
        connection?.cancel()
        connection = nil
    }

    // MARK: - Auth Handshake

    /// Step 1: read the 13-byte magic "TRUEMON_AUTH\n".
    private func readAuthMagic() {
        guard isRunning, let conn = connection else { return }
        let magicLen = Self.authMagic.count  // 13

        conn.receive(minimumIncompleteLength: magicLen, maximumLength: magicLen) { [weak self] data, _, isComplete, error in
            guard let self = self, self.isRunning else { return }
            if let error = error {
                self.onError?(error.localizedDescription)
                self.onStateChange?(.failed(error.localizedDescription))
                return
            }
            guard let magic = data, magic == Self.authMagic else {
                self.onError?("Protocol error — unexpected auth header")
                self.onStateChange?(.failed("Protocol error"))
                self.connection?.cancel()
                return
            }
            self.readAuthChallenge()
        }
    }

    /// Step 2: read the 32-byte random challenge.
    private func readAuthChallenge() {
        guard isRunning, let conn = connection else { return }

        conn.receive(minimumIncompleteLength: 32, maximumLength: 32) { [weak self] data, _, isComplete, error in
            guard let self = self, self.isRunning else { return }
            if let error = error {
                self.onError?(error.localizedDescription)
                self.onStateChange?(.failed(error.localizedDescription))
                return
            }
            guard let challenge = data, challenge.count == 32, let rawKey = self.rawKey else {
                self.onError?("Auth challenge receive error")
                self.onStateChange?(.failed("Auth error"))
                self.connection?.cancel()
                return
            }
            // Compute HMAC-SHA256(rawKey, challenge)
            var hmacBytes = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            challenge.withUnsafeBytes { challengePtr in
                rawKey.withUnsafeBytes { keyPtr in
                    CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),
                           keyPtr.baseAddress, rawKey.count,
                           challengePtr.baseAddress, challenge.count,
                           &hmacBytes)
                }
            }
            let response = Data(hmacBytes)
            conn.send(content: response, completion: .contentProcessed { [weak self] error in
                guard let self = self, self.isRunning else { return }
                if let error = error {
                    self.onError?(error.localizedDescription)
                    self.onStateChange?(.failed(error.localizedDescription))
                    return
                }
                // Auth sent — server will close connection immediately on wrong key,
                // or start sending frames on success.
                self.onStateChange?(.connected)
                self.readFrame()
            })
        }
    }

    // MARK: - Frame Reading

    /// Read the 4-byte big-endian length header, then read that many bytes of payload.
    private func readFrame() {
        guard isRunning, let conn = connection else { return }

        // Read 4-byte length header
        conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self] data, _, isComplete, error in
            guard let self = self, self.isRunning else { return }

            if let error = error {
                self.onError?(error.localizedDescription)
                return
            }
            if isComplete && (data == nil || data!.isEmpty) {
                self.onStateChange?(.disconnected)
                return
            }
            guard let headerData = data, headerData.count == 4 else {
                self.onStateChange?(.disconnected)
                return
            }

            let length = headerData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            guard length > 0, length < 10_000_000 else {
                self.onError?("Invalid frame length: \(length)")
                self.onStateChange?(.disconnected)
                return
            }

            self.readPayload(length: Int(length))
        }
    }

    private func readPayload(length: Int) {
        guard isRunning, let conn = connection else { return }

        conn.receive(minimumIncompleteLength: length, maximumLength: length) { [weak self] data, _, isComplete, error in
            guard let self = self, self.isRunning else { return }

            if let error = error {
                self.onError?(error.localizedDescription)
                return
            }
            if isComplete && (data == nil || data!.isEmpty) {
                self.onStateChange?(.disconnected)
                return
            }
            guard let payloadData = data, payloadData.count == length else {
                self.onStateChange?(.disconnected)
                return
            }

            // Decrypt Fernet token
            guard let signingKey = self.signingKey, let encryptionKey = self.encryptionKey else {
                self.onError?("No encryption keys")
                return
            }

            do {
                let plaintext = try FernetDecryptor.decrypt(
                    token: payloadData,
                    signingKey: signingKey,
                    encryptionKey: encryptionKey
                )
                let decoder = JSONDecoder()
                let stats = try decoder.decode(ServerStats.self, from: plaintext)
                self.onStats?(stats)
            } catch is FernetDecryptor.FernetError {
                self.onError?("Decryption failed — check shared key")
                self.disconnect()
                return
            } catch {
                self.onError?("Data error: \(error.localizedDescription)")
            }

            // Continue reading next frame
            self.readFrame()
        }
    }
}
