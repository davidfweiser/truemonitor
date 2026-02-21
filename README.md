# TrueMonitor v0.4

A real-time monitoring dashboard for TrueNAS systems. Built with Python and tkinter, TrueMonitor provides a dark-themed GUI that displays system metrics, storage pool health, and alerts from your TrueNAS server.

Two companion apps — **TrueMonClient** (Python desktop) and **TrueMonClient iOS** (native iPhone app) — can connect to TrueMonitor over the network and display the same live data remotely, without needing direct access to the TrueNAS API.

---

## Files

| File | Description |
|------|-------------|
| `truemonitor.py` | Main dashboard — connects to TrueNAS API, displays metrics, broadcasts data to clients |
| `truemonclient.py` | Remote client — receives and displays live data from a running TrueMonitor instance |
| `TrueMonClient-iOS/` | Native iOS app — same monitoring dashboard for iPhone, built with SwiftUI |

---

## TrueMonitor

### Features

#### Monitor Tab
- **CPU Usage** - Real-time percentage with color-coded progress bar and load average
- **Memory Usage** - Used/total with percentage bar
- **Network I/O** - Scrolling line graph showing receive (green) and transmit (blue) speeds with auto-scaling Y-axis
- **CPU Temperature** - Scrolling line graph with color-coded temperature zones (green/yellow/red), threshold lines at 60°C and 80°C
- **Storage Pools** - Dynamic cards for each ZFS pool showing capacity percentage, used/total/free space, and color-coded progress bars (green <70%, yellow <85%, red >=85%)
- **Disk Health Indicators** - Each pool card displays small colored rectangles for every disk. Green = healthy, red = errors. Hover to see the drive name.
- **Drive Map** - Per-pool popup showing the complete vdev layout (Mirror, RAIDZ1/2/3, Stripe, cache, log, spare). Drives with errors highlighted in red. Drive Map and Close buttons styled in dark navy blue to match the app theme.

#### Alerts Tab
- Automatic alerts for configurable CPU temperature threshold, CPU usage >95%, and memory usage >95%
- Pulls system alerts directly from TrueNAS (critical, warning, info levels)
- Popup dialogs with warning sounds for critical and warning alerts
- Color-coded alert log with timestamps
- Persistent alert history saved to disk
- Alert tab flashes when new alerts arrive

#### Settings Tab
- **Connection**: IP address/hostname, API key or username/password authentication
- **Poll Interval**: Configurable refresh rate (minimum 2 seconds)
- **CPU Temp Alert Threshold**: Dropdown selector from 40°C to 96°C
- **Font Size**: Small (85%), Medium (100%), Large (115%) — persists across restarts
- **Broadcast to Clients**: Enable/disable the broadcast server, set port and shared key (see below)
- **Demo Mode**: Preview the dashboard with simulated data including sample vdev topologies

### Usage

```bash
python3 truemonitor.py
```

1. Go to the **Settings** tab
2. Enter your TrueNAS IP address or hostname
3. Enter an API key **or** username and password
4. Set the poll interval and CPU temperature alert threshold
5. Click **Save & Connect**

---

## TrueMonClient

TrueMonClient is an identical monitoring UI that receives its data from a running TrueMonitor instance over the network. It requires no TrueNAS API credentials.

### Features

- Identical Monitor, Alerts, and Settings tabs to TrueMonitor
- Receives live data from TrueMonitor via an encrypted TCP connection
- Auto-reconnects if the connection drops
- TrueNAS system alerts forwarded from the server and displayed in the Alerts tab
- Independent alert thresholds (evaluated locally on received data)
- Demo Mode for testing without a TrueMonitor connection
- Config stored separately in `~/.config/truemonclient/`

### Usage

```bash
python3 truemonclient.py
```

1. In **TrueMonitor**, go to Settings → enable **Broadcast**, set a port and shared key, click **Save & Connect**
2. In **TrueMonClient**, go to Settings → enter the TrueMonitor machine's IP, broadcast port, and the same shared key
3. Click **Save & Connect**

TrueMonClient will connect within seconds and begin displaying the same live metrics as TrueMonitor.

---

## Broadcast Feature

TrueMonitor includes a built-in TCP broadcast server that pushes encrypted monitoring data to any connected TrueMonClient instances after every poll cycle.

### Security

All data sent over the network is encrypted using **Fernet symmetric encryption** (AES-128-CBC + HMAC-SHA256). The encryption key is derived from the shared passphrase using **PBKDF2-HMAC-SHA256** with 100,000 iterations, so a weak passphrase is still hardened against brute-force. Change the default key before exposing the port on an untrusted network.

### Wire Protocol

```
[4 bytes: big-endian payload length] [Fernet-encrypted JSON]
```

### Auth Handshake

Before receiving data, clients must pass a challenge-response handshake:

1. Server sends 13-byte magic: `TRUEMON_AUTH\n`
2. Server sends 32-byte random challenge
3. Client replies with `HMAC-SHA256(rawKey, challenge)`
4. Server closes the connection immediately on a wrong key, or starts streaming frames on success

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Enable Broadcast | Off | Start/stop the broadcast server |
| Broadcast Port | 7337 | TCP port TrueMonitor listens on |
| Shared Key | `truemonitor` | Passphrase used to derive the encryption key |

Both TrueMonitor and TrueMonClient must use the **same port and shared key**.

---

## Requirements

- Python 3.8+
- tkinter (included with Python on Windows and macOS; install `python3-tk` on Linux)

```bash
pip install -r requirements.txt
```

| Package | Version | Used by |
|---------|---------|---------|
| `requests` | >=2.28.0 | `truemonitor.py` only |
| `cryptography` | >=3.4 | Both — Fernet encryption + PBKDF2 key derivation |

### macOS / Apple Silicon note

Newer versions of macOS block `pip install` directly to the system Python to protect OS-managed packages. If you see an error like `externally-managed-environment`, use a virtual environment instead:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 truemonitor.py
```

Next time you open a terminal, just run `source venv/bin/activate` again before launching the app. You can also activate the venv and run everything in one line:

```bash
source venv/bin/activate && python3 truemonitor.py
```

---

## Installation

```bash
git clone https://github.com/davidfweiser/truemonitor.git
cd truemonitor
pip install -r requirements.txt
```

---

## Cross-Platform Support

Both apps run on Linux, Windows, and macOS.

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| GUI | tkinter | tkinter | tkinter |
| Alert sound | paplay/aplay | winsound | afplay |
| Encryption key source | /etc/machine-id | Home directory | Home directory |
| TrueMonitor config | ~/.config/truemonitor/ | ~/.config/truemonitor/ | ~/.config/truemonitor/ |
| TrueMonClient config | ~/.config/truemonclient/ | ~/.config/truemonclient/ | ~/.config/truemonclient/ |

---

## TrueNAS API Compatibility

TrueMonitor auto-detects the correct API format for your TrueNAS version, trying multiple reporting endpoint and payload formats and caching whichever one works. Tested with:

- TrueNAS SCALE 25.10.x
- TrueNAS SCALE 24.10.x

Authentication supports both API key (Bearer token) and basic username/password.

---

## Configuration Files

### TrueMonitor — `~/.config/truemonitor/`

| File | Purpose |
|------|---------|
| `config.json` | Connection settings, encrypted credentials, alert thresholds, broadcast settings |
| `alerts.log` | Persistent alert history |
| `debug.log` | API debug output (cleared on each launch) |

### TrueMonClient — `~/.config/truemonclient/`

| File | Purpose |
|------|---------|
| `config.json` | TrueMonitor server IP/port/key, alert thresholds, font size |
| `alerts.log` | Persistent alert history |
| `debug.log` | Connection debug output (cleared on each launch) |

### Credential Security

TrueMonitor passwords and API keys are encrypted at rest using Fernet symmetric encryption. The key is derived from your machine ID and username, so the config file cannot be decrypted on a different machine or by a different user.

---

## TrueMonClient iOS

A native iPhone app that connects to TrueMonitor's broadcast server and displays the same live monitoring dashboard. Built with SwiftUI for iOS 16+ with full iOS 26 Liquid Glass design support.

### Features

- **Monitor tab** — CPU, Memory, Network, Temperature, and ZFS pool cards with live data
- **Network chart** — Dual-color line graph (green = RX, cyan = TX) with 60-point history
- **Temperature chart** — Line graph with color-coded warning/critical zone overlays
- **Drive Map** — Vdev topology sheet per pool showing disk health; Drive Map and Done buttons styled in dark navy blue
- **Alerts tab** — Color-coded alert list (info/warning/critical) with timestamps, including TrueNAS system alerts forwarded from the server
- **Settings tab** — Server host/port/key, alert thresholds, connect/disconnect button
- **Hamburger menu navigation** — Floating glass menu button with animated drawer, replacing the system tab bar so content fills the full screen
- **iOS 26 Liquid Glass** — Glass cards and panels using the native `.glassEffect()` API on iOS 26, with graceful fallback on earlier versions
- **Always-on background monitoring** — Silent audio loop keeps the TCP connection alive while the screen is off; BGProcessingTask fires every 15 minutes as a safety net
- **TCP keepalive** — Connection probes every 10 seconds so dead connections are detected quickly without waiting for a timeout
- **Data watchdog** — If no stats arrive for 30 seconds while connected, the app forces a reconnect
- **Auto-reconnect** — NWPathMonitor detects network recovery and reconnects immediately; 5-second retry loop on disconnect or failure
- **Local notifications** — Push alerts when thresholds are exceeded, even in the background
- **Keychain storage** — Passphrase stored securely in the iOS Keychain

### Requirements

- iOS 16.0+
- Xcode 16+
- No third-party dependencies — all crypto via CommonCrypto

### Build

Open `TrueMonClient-iOS/TrueMonClient.xcodeproj` in Xcode, select your target device, and build.

---

## Architecture

### truemonitor.py

- **TrueNASClient** - REST API client: authentication, endpoint auto-detection, format caching, data parsing for CPU, memory, network, temperature, pools, and system alerts
- **BroadcastServer** - TCP server that encrypts and streams stats to connected TrueMonClient instances after every poll. Requires HMAC auth handshake. Uses exponential backoff instead of IP banning for failed auth.
- **TrueMonitorApp** - tkinter GUI with threaded background polling and thread-safe UI updates via `root.after()`

### truemonclient.py

- **MonitorClient** - TCP client that connects to TrueMonitor's broadcast server, performs HMAC auth handshake, decrypts incoming packets, and feeds data to the UI. Auto-reconnects on disconnect.
- **TrueMonClientApp** - tkinter GUI driven by received data instead of direct API polling

### TrueMonClient iOS

- **KeyDerivation** - PBKDF2-HMAC-SHA256 wrapper via CommonCrypto (100k iterations, constant salt)
- **FernetDecryptor** - Fernet token decryption: base64url decode → HMAC-SHA256 verify → AES-128-CBC decrypt
- **MonitorConnection** - NWConnection TCP client with TCP keepalive, 4-byte length-prefix framing, HMAC auth handshake, and async callbacks
- **DataModule** - `@MainActor` singleton managing connection lifecycle, data watchdog, auto-reconnect, 60-point history buffers, alert evaluation, and Keychain passphrase storage
- **DisplayModule** - UI-only state (selected view, scene lifecycle hooks); sleeps when screen is off while DataModule keeps running
- **BackgroundAudioService** - Silent audio loop (AVAudioSession `.playback`) that prevents iOS from suspending the app when the screen is off
- **Views** - SwiftUI cards (CPU, Memory, Network, Temperature, Pool) using Swift Charts for live graphs; glass hamburger menu for navigation

---

## License

MIT
