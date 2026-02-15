# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TrueMonitor is a real-time TrueNAS monitoring dashboard built with Python and tkinter. It has two apps:
- **truemonitor.py** — Main dashboard that connects to TrueNAS via REST API, displays system metrics (CPU, memory, network, temperature, ZFS pools), and optionally broadcasts stats over TCP
- **truemonclient.py** — Remote client that receives broadcast stats and displays the same dashboard without needing direct TrueNAS API access

## Running

```bash
pip install -r requirements.txt
python3 truemonitor.py      # Main dashboard
python3 truemonclient.py    # Remote client
```

No build step, test suite, or linter is configured.

## Architecture

Both apps are single-file tkinter applications (~2400 and ~1600 lines respectively). There is significant code duplication between them (UI builders, utility functions, encryption helpers).

### Key Classes

**truemonitor.py:**
- `TrueNASClient` — REST API client for TrueNAS v2.0 endpoints. Auto-detects reporting endpoint format via trial-and-error with caching.
- `BroadcastServer` — TCP server that encrypts stats with Fernet and sends to connected clients (4-byte length prefix + encrypted JSON)
- `TrueMonitorApp` — Main tkinter app. Background polling thread calls `fetch_all_stats()`, then marshals UI updates via `root.after()` → `_refresh(stats)`

**truemonclient.py:**
- `MonitorClient` — TCP client that connects to BroadcastServer, decrypts received packets, auto-reconnects on disconnect
- `TrueMonClientApp` — Same UI as TrueMonitorApp but data-driven from MonitorClient instead of API polling

### Threading Model

All network/API work runs in daemon threads. UI updates are marshaled to the main thread via `root.after()`. Shared data structures (client lists, alert queues) are protected by `threading.Lock`.

### Encryption

- **Credential storage:** Fernet encryption keyed from SHA256(username + machine-id), stored in `~/.config/truemonitor/config.json`
- **Broadcast wire format:** `[4-byte BE length][Fernet-encrypted JSON]` with key derived via PBKDF2-HMAC-SHA256 (100k iterations, constant salt)

### Config & Data Paths

- TrueMonitor: `~/.config/truemonitor/{config.json, alerts.log, debug.log}`
- TrueMonClient: `~/.config/truemonclient/{config.json, alerts.log, debug.log}`

### Color Scheme

Dark theme defined in `COLORS` dict at top of each file. Card-based layout with canvas-drawn scrolling graphs for network I/O and temperature.
