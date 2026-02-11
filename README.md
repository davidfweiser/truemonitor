# TrueMonitor

A real-time monitoring dashboard for TrueNAS systems. Built with Python and tkinter, TrueMonitor provides a dark-themed GUI that displays system metrics, storage pool health, and alerts from your TrueNAS server.

## Features

### Monitor Tab
- **CPU Usage** - Real-time percentage with color-coded progress bar and load average
- **Memory Usage** - Used/total with percentage bar
- **Network I/O** - Scrolling line graph showing receive (green) and transmit (blue) speeds with auto-scaling Y-axis
- **CPU Temperature** - Scrolling line graph with color-coded temperature zones (green/yellow/red), threshold lines at 60°C and 80°C
- **Storage Pools** - Dynamic cards for each ZFS pool showing capacity percentage, used/total/free space, and color-coded progress bars (green <70%, yellow <85%, red >=85%)
- **Disk Health Indicators** - Each pool card displays small colored rectangles for every disk in the pool. Green indicates a healthy disk, red indicates errors (read/write/checksum errors or non-ONLINE status). Hover over a rectangle to see the drive name.

### Alerts Tab
- Automatic alerts for configurable CPU temperature threshold, CPU usage >95%, and memory usage >95%
- Pulls system alerts directly from TrueNAS (critical, warning, info levels)
- Popup dialogs with warning sounds for critical and warning alerts
- Color-coded alert log with timestamps
- Persistent alert history saved to disk
- Alert tab flashes when new alerts arrive

### Settings Tab
- **Connection**: IP address/hostname, API key or username/password authentication
- **Poll Interval**: Configurable refresh rate (minimum 2 seconds)
- **CPU Temp Alert Threshold**: Dropdown selector from 40°C to 96°C, saves immediately on change
- **Demo Mode**: Preview the dashboard layout with simulated data

## Requirements

- Python 3.8+
- tkinter (included with Python on Windows and macOS; install `python3-tk` on Linux)

### Python Packages

```
pip install -r requirements.txt
```

Dependencies:
- `requests` - HTTP client for TrueNAS REST API
- `cryptography` - Fernet encryption for stored credentials

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/truemonitor.git
cd truemonitor
pip install -r requirements.txt
```

## Usage

```bash
python3 truemonitor.py
```

1. Go to the **Settings** tab
2. Enter your TrueNAS IP address or hostname
3. Enter an API key **or** username and password
4. Set the poll interval and CPU temperature alert threshold
5. Click **Save & Connect**

The dashboard will connect and begin displaying real-time metrics on the Monitor tab.

### Demo Mode

Click **Demo Mode** in the Settings tab to preview the dashboard with simulated data. This is useful for seeing the layout without connecting to a TrueNAS server.

## Cross-Platform Support

TrueMonitor runs on Linux, Windows, and macOS.

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| GUI | tkinter | tkinter | tkinter |
| Alert sound | paplay/aplay | winsound | afplay |
| Encryption key source | /etc/machine-id | Home directory | Home directory |
| Config location | ~/.config/truemonitor/ | ~/.config/truemonitor/ | ~/.config/truemonitor/ |

## TrueNAS API Compatibility

TrueMonitor auto-detects the correct API format for your TrueNAS version. It tries multiple reporting endpoint and payload formats, then caches whichever one works. Tested with:

- TrueNAS SCALE 25.10.x
- TrueNAS SCALE 24.10.x

Authentication supports both API key (Bearer token) and basic username/password.

## Configuration Files

All configuration is stored in `~/.config/truemonitor/`:

| File | Purpose |
|------|---------|
| `config.json` | Connection settings, credentials (encrypted), alert thresholds |
| `alerts.log` | Persistent alert history |
| `debug.log` | API debug output (cleared on each launch) |

### Credential Security

Passwords and API keys are encrypted at rest using Fernet symmetric encryption. The encryption key is derived from your machine ID and username, so the config file cannot be decrypted on a different machine or by a different user.

## Architecture

TrueMonitor is a single-file application with two main classes:

- **TrueNASClient** - REST API client that handles authentication, endpoint auto-detection, format caching, and data parsing for CPU, memory, network, temperature, pools, and system alerts
- **TrueMonitorApp** - tkinter GUI with threaded background polling. Uses `root.after()` for thread-safe UI updates from the polling thread

## License

MIT
