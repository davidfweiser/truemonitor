import AVFoundation

/// Plays a near-silent audio loop to keep the app alive in the background.
/// iOS allows apps with the "audio" background mode to continue running
/// as long as an AVAudioSession is active and audio is "playing".
final class BackgroundAudioService {

    static let shared = BackgroundAudioService()

    private var audioEngine: AVAudioEngine?
    private var playerNode: AVAudioPlayerNode?
    private(set) var isRunning = false

    /// Called when audio is interrupted and then resumes (e.g. after a phone call).
    var onInterruptionEnded: (() -> Void)?

    // Watchdog: if the player stops unexpectedly, restart it
    private var watchdogTimer: Timer?

    private init() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleAudioInterruption(_:)),
            name: AVAudioSession.interruptionNotification,
            object: AVAudioSession.sharedInstance()
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleRouteChange(_:)),
            name: AVAudioSession.routeChangeNotification,
            object: AVAudioSession.sharedInstance()
        )
    }

    func start() {
        guard !isRunning else { return }

        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, mode: .default, options: .mixWithOthers)
            try session.setActive(true)
        } catch {
            print("BackgroundAudioService: Failed to configure audio session: \(error)")
            return
        }

        let engine = AVAudioEngine()
        let player = AVAudioPlayerNode()
        engine.attach(player)

        // 5-second buffer with a barely-inaudible amplitude (prevents iOS from
        // detecting pure silence and suspending the audio session)
        let sampleRate: Double = 44100
        let format = AVAudioFormat(standardFormatWithSampleRate: sampleRate, channels: 1)!
        let frameCount = AVAudioFrameCount(sampleRate * 5) // 5 seconds
        guard let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: frameCount) else {
            return
        }
        buffer.frameLength = frameCount
        // Fill with near-zero amplitude (inaudible but not pure silence)
        if let channelData = buffer.floatChannelData?[0] {
            for i in 0..<Int(frameCount) {
                channelData[i] = Float.random(in: -0.000001...0.000001)
            }
        }

        engine.connect(player, to: engine.mainMixerNode, format: format)
        engine.mainMixerNode.outputVolume = 0.01 // near-zero volume

        do {
            try engine.start()
        } catch {
            print("BackgroundAudioService: Failed to start audio engine: \(error)")
            return
        }

        player.play()
        scheduleLoop(player: player, buffer: buffer)

        self.audioEngine = engine
        self.playerNode = player
        isRunning = true

        startWatchdog()
    }

    func stop() {
        watchdogTimer?.invalidate()
        watchdogTimer = nil
        guard isRunning else { return }
        isRunning = false

        // Capture before clearing so the background task can clean them up
        let engine = audioEngine
        let player = playerNode
        audioEngine = nil
        playerNode = nil

        // AVAudioEngine.stop() and AVAudioSession.setActive(false) can block the
        // calling thread while notifying other apps — run them off the main thread.
        DispatchQueue.global(qos: .utility).async {
            player?.stop()
            engine?.stop()
            try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        }
    }

    /// Stop and restart — useful after an audio interruption ends.
    func restart() {
        stop()
        start()
    }

    private func scheduleLoop(player: AVAudioPlayerNode, buffer: AVAudioPCMBuffer) {
        player.scheduleBuffer(buffer) { [weak self] in
            guard let self = self, self.isRunning else { return }
            self.scheduleLoop(player: player, buffer: buffer)
        }
    }

    // MARK: - Watchdog

    private func startWatchdog() {
        watchdogTimer?.invalidate()
        // Check every 30 seconds that the engine is still running
        watchdogTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            guard let self = self, self.isRunning else { return }
            if self.audioEngine?.isRunning == false {
                print("BackgroundAudioService: watchdog restarting stopped engine")
                self.restart()
            }
        }
    }

    // MARK: - Interruption & Route Handling

    @objc private func handleAudioInterruption(_ notification: Notification) {
        guard let info = notification.userInfo,
              let typeValue = info[AVAudioSessionInterruptionTypeKey] as? UInt,
              let type = AVAudioSession.InterruptionType(rawValue: typeValue) else { return }

        switch type {
        case .began:
            // Pause playback during interruption; keep isRunning=true
            playerNode?.pause()
            audioEngine?.pause()
        case .ended:
            let optionsValue = info[AVAudioSessionInterruptionOptionKey] as? UInt ?? 0
            let options = AVAudioSession.InterruptionOptions(rawValue: optionsValue)
            if options.contains(.shouldResume) {
                do {
                    try AVAudioSession.sharedInstance().setActive(true)
                    try audioEngine?.start()
                    playerNode?.play()
                } catch {
                    restart()
                }
                onInterruptionEnded?()
            }
        @unknown default:
            break
        }
    }

    @objc private func handleRouteChange(_ notification: Notification) {
        guard let info = notification.userInfo,
              let reasonValue = info[AVAudioSessionRouteChangeReasonKey] as? UInt,
              let reason = AVAudioSession.RouteChangeReason(rawValue: reasonValue) else { return }

        if reason == .oldDeviceUnavailable && isRunning {
            restart()
        }
    }
}
