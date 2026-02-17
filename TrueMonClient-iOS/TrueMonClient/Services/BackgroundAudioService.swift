import AVFoundation

/// Plays a silent audio loop to keep the app alive in the background.
/// iOS allows apps with the "audio" background mode to continue running
/// as long as an AVAudioSession is active and audio is "playing".
final class BackgroundAudioService {

    static let shared = BackgroundAudioService()

    private var audioEngine: AVAudioEngine?
    private var playerNode: AVAudioPlayerNode?
    private var isRunning = false

    private init() {}

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

        // Generate a silent audio buffer
        let sampleRate: Double = 44100
        let format = AVAudioFormat(standardFormatWithSampleRate: sampleRate, channels: 1)!
        let frameCount = AVAudioFrameCount(sampleRate) // 1 second of silence
        guard let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: frameCount) else {
            return
        }
        buffer.frameLength = frameCount
        // Buffer is zero-filled by default = silence

        engine.connect(player, to: engine.mainMixerNode, format: format)
        // Set volume to 0 so nothing is audible even if mixWithOthers fails
        engine.mainMixerNode.outputVolume = 0

        do {
            try engine.start()
        } catch {
            print("BackgroundAudioService: Failed to start audio engine: \(error)")
            return
        }

        // Schedule the silent buffer to loop forever
        player.play()
        scheduleLoop(player: player, buffer: buffer)

        self.audioEngine = engine
        self.playerNode = player
        isRunning = true
    }

    func stop() {
        guard isRunning else { return }
        playerNode?.stop()
        audioEngine?.stop()
        audioEngine = nil
        playerNode = nil
        isRunning = false

        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    private func scheduleLoop(player: AVAudioPlayerNode, buffer: AVAudioPCMBuffer) {
        player.scheduleBuffer(buffer) { [weak self] in
            guard let self = self, self.isRunning else { return }
            self.scheduleLoop(player: player, buffer: buffer)
        }
    }
}
