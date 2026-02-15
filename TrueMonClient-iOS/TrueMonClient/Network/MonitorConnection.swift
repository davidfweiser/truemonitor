import Foundation
import Network

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

    var onStats: ((ServerStats) -> Void)?
    var onStateChange: ((State) -> Void)?
    var onError: ((String) -> Void)?

    private var isRunning = false

    func connect(host: String, port: UInt16, passphrase: String) {
        disconnect()

        guard let keys = KeyDerivation.deriveFernetKey(passphrase: passphrase) else {
            onError?("Key derivation failed")
            onStateChange?(.failed("Key derivation failed"))
            return
        }
        signingKey = keys.signingKey
        encryptionKey = keys.encryptionKey

        let nwHost = NWEndpoint.Host(host)
        let nwPort = NWEndpoint.Port(rawValue: port)!

        let params = NWParameters.tcp
        params.requiredInterfaceType = .wifi

        let conn = NWConnection(host: nwHost, port: nwPort, using: .tcp)
        connection = conn
        isRunning = true

        conn.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                self.onStateChange?(.connected)
                self.readFrame()
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
