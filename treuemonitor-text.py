#!/usr/bin/env python3
"""TrueMonitor v0.4 — Interactive Text Mode

Connects to TrueNAS using the same API and credentials as truemonitor.py.
Reads saved settings from ~/.config/truemonitor/config.json automatically,
or accepts command-line arguments to override them.

Usage:
    python3 treuemonitor-text.py
    python3 treuemonitor-text.py --host 192.168.1.100 --api-key YOUR_KEY
    python3 treuemonitor-text.py --host 192.168.1.100 --username admin --password secret

Keys — Main Menu:
    1    Settings
    2    Alerts
    3    Monitor
    4    Quit

Keys — Settings:
    Tab / Down   Next field
    Shift+Tab / Up   Previous field
    Enter        Next field (or Save & Connect on last item)
    Backspace    Delete character
    Left / Right Move cursor in field
    S            Save & Connect (from anywhere in the form)
    ESC          Cancel, back to menu

Keys — Alerts:
    ESC          Back to menu
    C            Clear all alerts

Keys — Monitor / any view:
    ESC          Back to menu
"""

import curses
import json
import threading
import time
import os
import sys
import argparse
import base64
import hashlib
import hmac as hmac_mod
import socket
import struct
import getpass
from datetime import datetime, timedelta, timezone
from collections import deque

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import ssl
try:
    import websocket as _websocket
except ImportError:
    print("ERROR: 'websocket-client' package is required. Install it with:")
    print("  pip install websocket-client")
    raise SystemExit(1)

APP_VERSION = "0.5"

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "truemonitor")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
DEBUG_LOG   = os.path.join(CONFIG_DIR, "debug.log")
ALERT_LOG   = os.path.join(CONFIG_DIR, "alerts.log")


# ---------------------------------------------------------------------------
# Crypto helpers (shared with truemonitor.py)
# ---------------------------------------------------------------------------

def debug(msg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(DEBUG_LOG, "a") as f:
        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")


def _get_encryption_key():
    seed = getpass.getuser()
    try:
        with open("/etc/machine-id") as f:
            seed += f.read().strip()
    except Exception:
        seed += os.path.expanduser("~")
    key_bytes = hashlib.sha256(seed.encode()).digest()
    return base64.urlsafe_b64encode(key_bytes)


def _encrypt(plaintext):
    if not plaintext:
        return ""
    f = Fernet(_get_encryption_key())
    return f.encrypt(plaintext.encode()).decode()


def _decrypt(ciphertext):
    if not ciphertext:
        return ""
    try:
        f = Fernet(_get_encryption_key())
        return f.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception):
        return ciphertext


# ---------------------------------------------------------------------------
# Broadcast server (same protocol as truemonitor.py)
# ---------------------------------------------------------------------------

BROADCAST_DEFAULT_PORT = 7337
BROADCAST_DEFAULT_KEY  = "truemonitor"
_AUTH_MAGIC            = b"TRUEMON_AUTH\n"
_BACKOFF_DELAYS        = [5, 30, 300]


def _derive_broadcast_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=b"truemonitor_broadcast_v1", iterations=100_000)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def _derive_broadcast_key_raw(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=b"truemonitor_broadcast_v1", iterations=100_000)
    return kdf.derive(passphrase.encode())


class BroadcastServer:
    """TCP server — encrypts and streams stats to connected TrueMonClient instances."""

    def __init__(self, port: int, passphrase: str):
        self.port       = port
        self.passphrase = passphrase
        self._clients   = []
        self._lock      = threading.Lock()
        self._running   = False
        self._server_sock = None
        self._auth_failures: dict = {}
        self._sec_lock  = threading.Lock()
        # Optional callback: on_security_event(level, ip, message)
        self.on_security_event = None
        # Broadcast a clear-alerts signal on next send_stats call.
        self._clear_alerts_at: float = 0.0
        # Optional callback: on_client_clear_alerts() — called when a client
        # sends a clear_alerts command so the server can clear its own display.
        self.on_client_clear_alerts = None

    def _emit_security(self, level: str, ip: str, message: str):
        cb = self.on_security_event
        if cb:
            try:
                cb(level, ip, message)
            except Exception:
                pass

    def _get_fernet(self):
        return Fernet(_derive_broadcast_key(self.passphrase))

    def start(self):
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        with self._lock:
            for c in list(self._clients):
                try:
                    c.close()
                except Exception:
                    pass
            self._clients.clear()

    @property
    def client_count(self):
        with self._lock:
            return len(self._clients)

    def _accept_loop(self):
        # Retry binding in case the previous server socket hasn't fully closed yet.
        for attempt in range(10):
            if not self._running:
                return
            try:
                self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._server_sock.bind(("0.0.0.0", self.port))
                self._server_sock.listen(10)
                self._server_sock.settimeout(1.0)
                break
            except Exception as e:
                debug(f"BroadcastServer bind attempt {attempt + 1} failed: {e}")
                try:
                    self._server_sock.close()
                except Exception:
                    pass
                time.sleep(0.5)
        else:
            debug(f"BroadcastServer: could not bind port {self.port} after 10 attempts")
            return

        while self._running:
            try:
                conn, addr = self._server_sock.accept()
                ip = addr[0]
                if self._backoff_remaining(ip) > 0:
                    conn.close()
                    continue
                threading.Thread(target=self._authenticate,
                                 args=(conn, ip), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _authenticate(self, conn, ip):
        try:
            challenge = os.urandom(32)
            conn.sendall(_AUTH_MAGIC + challenge)
            conn.settimeout(5.0)
            response = b""
            while len(response) < 32:
                chunk = conn.recv(32 - len(response))
                if not chunk:
                    break
                response += chunk
        except Exception:
            conn.close()
            return
        if len(response) != 32:
            conn.close()
            return
        raw_key  = _derive_broadcast_key_raw(self.passphrase)
        expected = hmac_mod.new(raw_key, challenge, hashlib.sha256).digest()
        if hmac_mod.compare_digest(response, expected):
            conn.settimeout(10.0)
            # Aggressive TCP keepalive so dead connections are detected quickly.
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                if hasattr(socket, "TCP_KEEPIDLE"):
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
                if hasattr(socket, "TCP_KEEPINTVL"):
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
                if hasattr(socket, "TCP_KEEPCNT"):
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except Exception:
                pass
            with self._lock:
                self._clients.append(conn)
            self._emit_security("info", ip, f"Authenticated client from {ip}")
            # Read commands sent back from this client (e.g. clear_alerts).
            threading.Thread(
                target=self._read_client_commands,
                args=(conn, ip),
                daemon=True,
            ).start()
        else:
            conn.close()
            with self._sec_lock:
                count, _ = self._auth_failures.get(ip, (0, None))
                self._auth_failures[ip] = (count + 1, datetime.now())
            self._emit_security("warning", ip, f"Wrong shared key from {ip}")

    def _backoff_remaining(self, ip):
        with self._sec_lock:
            entry = self._auth_failures.get(ip)
            if not entry:
                return 0
            count, last = entry
            delay   = _BACKOFF_DELAYS[min(count - 1, len(_BACKOFF_DELAYS) - 1)]
            elapsed = (datetime.now() - last).total_seconds()
            if delay - elapsed <= 0:
                del self._auth_failures[ip]
                return 0
            return delay - elapsed

    @staticmethod
    def _recvn_from(conn, n: int):
        """Receive exactly n bytes from conn; return None on EOF/error, re-raise timeout."""
        data = b""
        while len(data) < n:
            try:
                chunk = conn.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                raise
            except Exception:
                return None
        return data

    def _read_client_commands(self, conn, ip: str):
        """Read plain-JSON command frames sent back from an authenticated client."""
        debug(f"BroadcastServer: command reader started for {ip}")
        while self._running:
            try:
                header = self._recvn_from(conn, 4)
                if header is None:
                    break
                length = struct.unpack(">I", header)[0]
                if length == 0 or length > 65_536:
                    debug(f"BroadcastServer: bad command frame length {length} from {ip}")
                    break
                data = self._recvn_from(conn, length)
                if data is None:
                    break
                try:
                    cmd = json.loads(data.decode())
                except Exception as e:
                    debug(f"BroadcastServer: command parse error from {ip}: {e}")
                    break
                debug(f"BroadcastServer: received command {cmd} from {ip}")
                if cmd.get("cmd") == "clear_alerts":
                    self.request_clear_alerts()
                    if self.on_client_clear_alerts:
                        try:
                            self.on_client_clear_alerts()
                        except Exception:
                            pass
            except socket.timeout:
                continue  # No command yet — keep waiting
            except Exception:
                break
        debug(f"BroadcastServer: command reader ended for {ip}")

    def request_clear_alerts(self):
        """Schedule a clear_alerts_at timestamp in the next broadcast."""
        self._clear_alerts_at = time.time()

    def send_stats(self, stats: dict):
        clear_at = self._clear_alerts_at
        if clear_at:
            self._clear_alerts_at = 0.0
            stats = dict(stats)
            stats["clear_alerts_at"] = clear_at
        if not self._clients:
            return
        try:
            payload   = json.dumps(stats).encode()
            encrypted = self._get_fernet().encrypt(payload)
            message   = struct.pack(">I", len(encrypted)) + encrypted
        except Exception as e:
            debug(f"BroadcastServer encrypt error: {e}")
            return
        dead = []
        with self._lock:
            for c in list(self._clients):
                try:
                    c.sendall(message)
                except Exception:
                    dead.append(c)
            for c in dead:
                try:
                    c.close()
                except Exception:
                    pass
                try:
                    self._clients.remove(c)
                except ValueError:
                    pass


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                data = json.load(f)
            for key in ("password", "api_key"):
                if data.get(f"{key}_encrypted") and data.get(key):
                    data[key] = _decrypt(data[key])
                    data.pop(f"{key}_encrypted", None)
            return data
        except Exception:
            pass
    return {}


def save_config(config):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    save_data = dict(config)
    for key in ("password", "api_key"):
        if save_data.get(key):
            save_data[key] = _encrypt(save_data[key])
            save_data[f"{key}_encrypted"] = True
    with open(CONFIG_FILE, "w") as f:
        json.dump(save_data, f, indent=2)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def format_bytes(val, per_second=False):
    if val is None:
        return "N/A"
    suffix = "/s" if per_second else ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(val) < 1024.0:
            return f"{val:.1f} {unit}{suffix}"
        val /= 1024.0
    return f"{val:.1f} PB{suffix}"


def _bar(pct, width=20):
    filled = max(0, min(width, int(pct / 100 * width)))
    return "[" + "=" * filled + " " * (width - filled) + "]"


# ---------------------------------------------------------------------------
# TrueNAS WebSocket JSON-RPC 2.0 client
# ---------------------------------------------------------------------------

class TrueNASClient:
    def __init__(self, host, api_key="", username="", password=""):
        h = host.rstrip("/")
        for prefix in ("https://", "http://"):
            if h.startswith(prefix):
                h = h[len(prefix):]
        self.host     = h
        self.api_key  = api_key
        self.username = username
        self.password = password
        self._ws      = None
        self._id      = 0
        self._working_report_format = None
        self._working_iface = None

    def _connect(self):
        ws_url  = f"wss://{self.host}/api/current"
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE
        ws = _websocket.WebSocket(sslopt={"context": ssl_ctx})
        ws.settimeout(30)
        ws.connect(ws_url)
        if self.api_key:
            ok = self._rpc_on(ws, "auth.login_with_api_key", [self.api_key])
        else:
            ok = self._rpc_on(ws, "auth.login", [self.username, self.password])
        if not ok:
            ws.close()
            raise RuntimeError("Authentication failed")
        self._ws = ws

    def _rpc_on(self, ws, method, params=None):
        self._id += 1
        msg_id = self._id
        req = {"jsonrpc": "2.0", "id": msg_id, "method": method,
               "params": params if params is not None else []}
        ws.send(json.dumps(req))
        while True:
            raw  = ws.recv()
            resp = json.loads(raw)
            if resp.get("id") != msg_id:
                continue  # skip notifications / other messages
            if "error" in resp:
                err = resp["error"]
                raise RuntimeError(f"RPC error: {err.get('message', err)}")
            return resp.get("result")

    def _call(self, method, params=None):
        for attempt in range(2):
            try:
                if self._ws is None:
                    self._connect()
                return self._rpc_on(self._ws, method, params)
            except RuntimeError:
                raise  # RPC application error — don't reconnect
            except Exception:
                self._ws = None
                if attempt == 0:
                    continue
                raise

    def close(self):
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None

    def test_connection(self):
        return self._call("system.info")

    def get_system_info(self):
        return self._call("system.info")

    def get_interfaces(self):
        return self._call("interface.query")

    def get_alerts(self):
        return self._call("alert.list")

    def get_pools(self):
        return self._call("pool.query")

    def get_reporting_data(self, graphs):
        now   = datetime.now(timezone.utc)
        start = now - timedelta(seconds=120)

        def _attempts():
            return [
                ("reporting.get_data", [
                    graphs,
                    {
                        "start": start.strftime("%Y-%m-%dT%H:%M:%S"),
                        "end":   now.strftime("%Y-%m-%dT%H:%M:%S"),
                        "aggregate": True,
                    },
                ]),
                ("reporting.get_data", [
                    graphs,
                    {"unit": "MINUTE", "page": 0, "aggregate": True},
                ]),
                ("reporting.get_data", [graphs]),
                ("reporting.get_data", [
                    graphs,
                    {
                        "start": int(start.timestamp()),
                        "end":   int(now.timestamp()),
                        "aggregate": True,
                    },
                ]),
            ]

        if self._working_report_format is not None:
            idx = self._working_report_format
            try:
                method, params = _attempts()[idx]
                return self._call(method, params)
            except Exception:
                self._working_report_format = None

        last_err = None
        for i, (method, params) in enumerate(_attempts()):
            try:
                debug(f" reporting attempt {i}: {method}")
                result = self._call(method, params)
                self._working_report_format = i
                debug(f" reporting OK via {method} (cached as #{i})")
                return result
            except Exception as e:
                debug(f" reporting attempt {i} failed: {e}")
                last_err = e
        raise last_err

    def fetch_all_stats(self):
        stats = {
            "cpu_percent": None, "memory_used": None, "memory_total": None,
            "memory_percent": None, "cpu_temp": None,
            "net_rx": None, "net_tx": None, "net_iface": None,
            "hostname": "N/A", "version": "N/A", "uptime": "N/A",
            "loadavg": [0, 0, 0],
        }

        try:
            info = self.get_system_info()
            stats["hostname"]     = info.get("hostname", "N/A")
            stats["version"]      = info.get("version",  "N/A")
            stats["uptime"]       = info.get("uptime",   "N/A")
            stats["loadavg"]      = info.get("loadavg",  [0, 0, 0])
            stats["memory_total"] = info.get("physmem",  0)
        except Exception as e:
            debug(f" system/info error: {e}")

        try:
            graphs = [{"name": "cpu"}, {"name": "memory"}, {"name": "cputemp"}]
            report = self.get_reporting_data(graphs)
            for item in (report if isinstance(report, list) else []):
                if not isinstance(item, dict):
                    continue
                name   = item.get("name", "")
                data   = item.get("data", [])
                legend = item.get("legend", [])
                latest = None
                for row in reversed(data):
                    if row and any(v is not None for v in row[1:]):
                        latest = row
                        break
                if latest is None:
                    continue

                if name == "cpu":
                    if "cpu" in legend:
                        idx = legend.index("cpu")
                        val = latest[idx] if idx < len(latest) else None
                        if val is not None:
                            stats["cpu_percent"] = round(float(val), 1)
                    elif "idle" in legend:
                        idx  = legend.index("idle")
                        idle = latest[idx] if idx < len(latest) else None
                        if idle is not None:
                            stats["cpu_percent"] = round(100.0 - idle, 1)

                elif name == "memory":
                    total = stats["memory_total"] or 0
                    if total:
                        used = None
                        if "available" in legend:
                            idx = legend.index("available")
                            val = latest[idx] if idx < len(latest) else None
                            if val is not None:
                                used = total - float(val)
                        elif "used" in legend:
                            idx = legend.index("used")
                            val = latest[idx] if idx < len(latest) else None
                            if val is not None:
                                used = val if val > 100 else total * val / 100
                        elif "free" in legend:
                            idx = legend.index("free")
                            val = latest[idx] if idx < len(latest) else None
                            if val is not None:
                                free = val if val > 100 else total * val / 100
                                used = total - free
                        if used is not None:
                            stats["memory_used"]    = used
                            stats["memory_percent"] = round(used / total * 100, 1)

                elif name == "cputemp":
                    if "cpu" in legend:
                        idx = legend.index("cpu")
                        val = latest[idx] if idx < len(latest) else None
                        if val is not None and val > 0:
                            stats["cpu_temp"] = round(float(val), 1)
                    else:
                        temps = [v for v in latest[1:] if v is not None and v > 0]
                        if temps:
                            stats["cpu_temp"] = round(sum(temps) / len(temps), 1)
        except Exception as e:
            debug(f" reporting error: {e}")

        try:
            if self._working_iface:
                iface_names = [self._working_iface]
            else:
                interfaces  = self.get_interfaces()
                iface_names = [i.get("name", "") for i in interfaces
                               if isinstance(i, dict)
                               and i.get("name", "") not in ("lo", "")]
            for iface_name in iface_names:
                try:
                    net_report = self.get_reporting_data(
                        [{"name": "interface", "identifier": iface_name}])
                    for item in (net_report if isinstance(net_report, list) else []):
                        if not isinstance(item, dict):
                            continue
                        data   = item.get("data", [])
                        legend = item.get("legend", [])
                        if not data:
                            continue
                        latest = None
                        for row in reversed(data):
                            if row and any(v is not None for v in row[1:]):
                                latest = row
                                break
                        if latest:
                            stats["net_iface"] = iface_name
                            self._working_iface = iface_name
                            if "received" in legend:
                                idx = legend.index("received")
                                if idx < len(latest) and latest[idx] is not None:
                                    stats["net_rx"] = abs(float(latest[idx]))
                            if "sent" in legend:
                                idx = legend.index("sent")
                                if idx < len(latest) and latest[idx] is not None:
                                    stats["net_tx"] = abs(float(latest[idx]))
                            if stats["net_rx"] is None and len(latest) > 1:
                                stats["net_rx"] = abs(float(latest[1])) if latest[1] else 0
                            if stats["net_tx"] is None and len(latest) > 2:
                                stats["net_tx"] = abs(float(latest[2])) if latest[2] else 0
                            break
                except Exception as e:
                    debug(f" net {iface_name} error: {e}")
        except Exception as e:
            debug(f" network error: {e}")

        stats["pools"] = []
        try:
            for p in self.get_pools():
                if not isinstance(p, dict):
                    continue
                topology  = p.get("topology", {})
                total     = p.get("size")
                allocated = p.get("allocated")
                free      = p.get("free")
                disks = []
                vdev_map = {}
                for topo_key in ("data", "cache", "log", "spare"):
                    vdev_list = []
                    for vdev in topology.get(topo_key, []):
                        if not isinstance(vdev, dict):
                            continue
                        vtype   = vdev.get("type", "STRIPE").upper()
                        vstatus = vdev.get("status", "ONLINE")
                        children = vdev.get("children", [])
                        child_list = []
                        if children:
                            for ch in children:
                                if not isinstance(ch, dict):
                                    continue
                                ch_stats = ch.get("stats", {})
                                errs = ((ch_stats.get("read_errors", 0) or 0)
                                        + (ch_stats.get("write_errors", 0) or 0)
                                        + (ch_stats.get("checksum_errors", 0) or 0))
                                cst = ch.get("status", "ONLINE")
                                child_list.append({
                                    "name":   ch.get("disk") or ch.get("name", "?"),
                                    "status": cst,
                                    "errors": errs,
                                })
                                disks.append({"name": child_list[-1]["name"],
                                              "has_error": errs > 0 or cst not in ("ONLINE", "")})
                        else:
                            v_stats = vdev.get("stats", {})
                            errs = ((v_stats.get("read_errors", 0) or 0)
                                    + (v_stats.get("write_errors", 0) or 0)
                                    + (v_stats.get("checksum_errors", 0) or 0))
                            dname = vdev.get("disk") or vdev.get("name", "?")
                            child_list.append({
                                "name":   dname,
                                "status": vstatus,
                                "errors": errs,
                            })
                            disks.append({"name": dname,
                                          "has_error": errs > 0 or vstatus not in ("ONLINE", "")})
                        vdev_list.append({
                            "type":   vtype,
                            "status": vstatus,
                            "disks":  child_list,
                        })
                    vdev_map[topo_key] = vdev_list
                if total and allocated is not None:
                    pct = round(allocated / total * 100, 1) if total > 0 else 0
                    stats["pools"].append({
                        "name":      p.get("name", "unknown"),
                        "used":      allocated,
                        "available": free or (total - allocated),
                        "total":     total,
                        "percent":   pct,
                        "disks":     disks,
                        "topology":  vdev_map,
                    })
        except Exception as e:
            debug(f" pool error: {e}")

        stats["system_alerts"] = []
        try:
            for alert in self.get_alerts():
                if not isinstance(alert, dict):
                    continue
                aid   = (alert.get("uuid") or alert.get("id") or
                         alert.get("klass", "") + ":" + alert.get("level", ""))
                level = alert.get("level", "INFO").upper()
                sev   = ("critical" if level in ("CRITICAL", "ERROR")
                          else "warning" if level == "WARNING" else "info")
                msg   = alert.get("formatted", "") or alert.get("text", "")
                if not msg:
                    msg = alert.get("klass", "") or "Unknown TrueNAS alert"
                stats["system_alerts"].append({"id": aid, "severity": sev, "message": msg})
        except Exception as e:
            debug(f" system alerts error: {e}")

        return stats


# ---------------------------------------------------------------------------
# Shared application state
# ---------------------------------------------------------------------------

class AppState:
    def __init__(self):
        self.lock    = threading.Lock()
        self.stats   = None
        self.alerts  = deque(maxlen=200)
        self.last_updated = None
        self.last_error   = None
        self.current_view  = "menu"
        self.unread_alerts = 0
        self.alert_scroll  = 0  # lines scrolled up from bottom (0 = newest at top)
        self._temp_alert_active = False
        self._cpu_alert_active  = False
        self._mem_alert_active  = False
        self._seen_truenas_alerts = set()
        self._connect_alert_times: dict = {}  # "ip:level" → last datetime
        self.broadcast_server: BroadcastServer | None = None

    def start_broadcast(self, port: int, passphrase: str):
        if self.broadcast_server:
            self.broadcast_server.stop()
        self.broadcast_server = BroadcastServer(port, passphrase)
        self.broadcast_server.on_security_event = self._on_broadcast_security_event
        self.broadcast_server.on_client_clear_alerts = self._do_clear_alerts_local
        self.broadcast_server.start()

    def _on_broadcast_security_event(self, level: str, ip: str, message: str):
        """Rate-limited alert for broadcast auth events (runs on worker thread)."""
        if level == "info" and not message.startswith("Authenticated"):
            return
        now = datetime.now()
        key = f"{ip}:{level}"
        with self.lock:
            last = self._connect_alert_times.get(key)
            if last and (now - last).total_seconds() < 300:
                return
            self._connect_alert_times[key] = now
        self.add_alert(level, message)

    def stop_broadcast(self):
        if self.broadcast_server:
            self.broadcast_server.stop()
            self.broadcast_server = None

    def add_alert(self, severity, message):
        ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {"time": ts, "severity": severity, "message": message}
        with self.lock:
            self.alerts.append(entry)
            if self.current_view != "alerts":
                self.unread_alerts += 1
        prefix = {"critical": "CRITICAL", "warning": "WARNING",
                  "info": "INFO", "resolved": "RESOLVED"}.get(severity, "INFO")
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(ALERT_LOG, "a") as f:
                f.write(f"[{ts}] {prefix}: {message}\n")
        except Exception:
            pass

    def check_alerts(self, stats, temp_threshold):
        temp = stats.get("cpu_temp")
        if temp is not None:
            if temp > temp_threshold:
                if not self._temp_alert_active:
                    self._temp_alert_active = True
                    self.add_alert("critical",
                                   f"CPU temp {temp}°C exceeds threshold {temp_threshold}°C!")
            else:
                if self._temp_alert_active:
                    self._temp_alert_active = False
                    self.add_alert("resolved", f"CPU temp back to normal: {temp}°C")

        cpu = stats.get("cpu_percent")
        if cpu is not None:
            if cpu > 95:
                if not self._cpu_alert_active:
                    self._cpu_alert_active = True
                    self.add_alert("warning", f"CPU usage critically high: {cpu}%")
            else:
                if self._cpu_alert_active:
                    self._cpu_alert_active = False
                    self.add_alert("resolved", f"CPU usage back to normal: {cpu}%")

        mem_pct = stats.get("memory_percent")
        if mem_pct is not None:
            if mem_pct > 95:
                if not self._mem_alert_active:
                    self._mem_alert_active = True
                    self.add_alert("warning", f"Memory usage critically high: {mem_pct}%")
            else:
                if self._mem_alert_active:
                    self._mem_alert_active = False
                    self.add_alert("resolved", f"Memory usage back to normal: {mem_pct}%")

        current_ids = set()
        for alert in stats.get("system_alerts", []):
            aid = alert.get("id", "")
            current_ids.add(aid)
            if aid not in self._seen_truenas_alerts:
                self._seen_truenas_alerts.add(aid)
                self.add_alert(alert.get("severity", "info"),
                               f"[TrueNAS] {alert.get('message', '')}")
        for aid in self._seen_truenas_alerts - current_ids:
            self._seen_truenas_alerts.discard(aid)
            self.add_alert("resolved", "[TrueNAS] Alert cleared")

    def clear_alerts(self):
        """User-initiated clear: clears locally and tells all clients to clear."""
        self._do_clear_alerts_local()
        if self.broadcast_server:
            self.broadcast_server.request_clear_alerts()

    def _do_clear_alerts_local(self):
        """Clear alerts without triggering a broadcast (also used as client callback)."""
        with self.lock:
            self.alerts.clear()
            self.unread_alerts = 0
        try:
            with open(ALERT_LOG, "w") as f:
                f.write("")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Curses color pairs
# ---------------------------------------------------------------------------

C_ACCENT = 1   # cyan
C_GOOD   = 2   # green
C_WARN   = 3   # yellow
C_CRIT   = 4   # red
C_DIM    = 5   # white (use with A_DIM)
C_SEL    = 6   # black on cyan  (focused field / selected item)
C_BADGE  = 7   # white on red   (unread alert badge)
C_BLACK  = 8   # black on white (menu key numbers)


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_ACCENT, curses.COLOR_CYAN,  -1)
    curses.init_pair(C_GOOD,   curses.COLOR_GREEN,  -1)
    curses.init_pair(C_WARN,   curses.COLOR_YELLOW, -1)
    curses.init_pair(C_CRIT,   curses.COLOR_RED,    -1)
    curses.init_pair(C_DIM,    curses.COLOR_WHITE,  -1)
    curses.init_pair(C_SEL,    curses.COLOR_BLACK,  curses.COLOR_CYAN)
    curses.init_pair(C_BADGE,  curses.COLOR_WHITE,  curses.COLOR_RED)
    curses.init_pair(C_BLACK,  curses.COLOR_BLACK,  curses.COLOR_WHITE)


# ---------------------------------------------------------------------------
# Drawing primitives
# ---------------------------------------------------------------------------

def put(win, y, x, text, attr=0):
    my, mx = win.getmaxyx()
    if y < 0 or y >= my or x < 0 or x >= mx:
        return
    avail = mx - x
    if avail <= 0:
        return
    try:
        win.addstr(y, x, str(text)[:avail], attr)
    except curses.error:
        pass


def hline(win, y, attr=0):
    my, mx = win.getmaxyx()
    if 0 <= y < my:
        try:
            win.hline(y, 0, curses.ACS_HLINE, mx - 1, attr)
        except curses.error:
            pass


# ---------------------------------------------------------------------------
# Common header (rows 0-3)
# ---------------------------------------------------------------------------

CONTENT_ROW = 4


def draw_header(win, state, config, title=""):
    my, mx = win.getmaxyx()
    app_str = f" TrueMonitor v{APP_VERSION}"
    if title:
        app_str += f"  \u2014  {title}"
    put(win, 0, 0, app_str, curses.color_pair(C_ACCENT) | curses.A_BOLD)

    s = state.stats
    if s:
        info = (f" {s.get('hostname','N/A')}  |  {s.get('version','N/A')}"
                f"  |  Uptime: {s.get('uptime','N/A')}")
    else:
        info = f" {config.get('host', '?')}  —  connecting..."
    put(win, 1, 0, info, curses.color_pair(C_DIM) | curses.A_DIM)

    if state.last_updated:
        ts   = state.last_updated.strftime("%H:%M:%S")
        iv   = config.get("interval", 5)
        row2 = f" Updated: {ts}  |  Poll: {iv}s"
        if state.broadcast_server is not None:
            row2 += f"  |  Broadcast: {state.broadcast_server.client_count} client(s)"
        if state.last_error:
            row2 += f"  |  Error: {state.last_error[:50]}"
        put(win, 2, 0, row2, curses.color_pair(C_DIM) | curses.A_DIM)
    else:
        put(win, 2, 0, " Waiting for first poll...",
            curses.color_pair(C_DIM) | curses.A_DIM)

    hline(win, 3, curses.color_pair(C_DIM) | curses.A_DIM)


# ---------------------------------------------------------------------------
# Bottom hint bar
# ---------------------------------------------------------------------------

def draw_hint(win, text, attr=None):
    my, mx = win.getmaxyx()
    if attr is None:
        attr = curses.color_pair(C_DIM) | curses.A_DIM
    hline(win, my - 2, curses.color_pair(C_DIM) | curses.A_DIM)
    put(win, my - 1, 0, " " + text, attr)


# ---------------------------------------------------------------------------
# MENU view
# ---------------------------------------------------------------------------

MENU_ITEMS = [
    ("1", "Settings", "settings"),
    ("2", "Alerts",   "alerts"),
    ("3", "Monitor",  "monitor"),
    ("4", "Quit",     "quit"),
]


def draw_menu(win, state):
    my, mx = win.getmaxyx()
    row = CONTENT_ROW + 1

    # Quick stats bar
    s = state.stats
    if s:
        cpu  = s.get("cpu_percent")
        mp   = s.get("memory_percent")
        temp = s.get("cpu_temp")

        def _ca(v, hi, lo):
            if v is None:
                return curses.color_pair(C_DIM)
            return (curses.color_pair(C_CRIT) if v >= hi
                    else curses.color_pair(C_WARN) if v >= lo
                    else curses.color_pair(C_GOOD))

        put(win, row, 1, "CPU ", curses.color_pair(C_DIM))
        put(win, row, 5, f"{cpu:.1f}%" if cpu is not None else "N/A", _ca(cpu, 90, 70))
        put(win, row, 13, "Mem ", curses.color_pair(C_DIM))
        put(win, row, 17, f"{mp:.1f}%" if mp is not None else "N/A", _ca(mp, 90, 70))
        put(win, row, 25, "Temp ", curses.color_pair(C_DIM))
        put(win, row, 30,
            f"{temp:.1f}\u00b0C" if temp is not None else "N/A",
            _ca(temp, 80, 60))
    row += 2

    # Menu box
    box_w = 40
    box_x = max(2, (mx - box_w) // 2)
    acc   = curses.color_pair(C_ACCENT)

    put(win, row, box_x,
        "\u250c" + "\u2500" * (box_w - 2) + "\u2510", acc)
    row += 1
    put(win, row, box_x,
        "\u2502" + " Select an option ".center(box_w - 2) + "\u2502", acc)
    row += 1
    put(win, row, box_x,
        "\u251c" + "\u2500" * (box_w - 2) + "\u2524", acc)
    row += 1

    for key, label, view in MENU_ITEMS:
        if row >= my - 3:
            break

        disp = label
        if view == "alerts":
            count  = len(state.alerts)
            unread = state.unread_alerts
            disp   = f"Alerts  ({count} total"
            disp  += f", {unread} new" if unread > 0 else ""
            disp  += ")"

        put(win, row, box_x, "\u2502", acc)
        put(win, row, box_x + box_w - 1, "\u2502", acc)

        key_attr = curses.color_pair(C_BLACK) | curses.A_BOLD
        if view == "quit":
            lbl_attr = curses.color_pair(C_CRIT)
        elif view == "alerts" and state.unread_alerts > 0:
            lbl_attr = curses.color_pair(C_BADGE) | curses.A_BOLD
        else:
            lbl_attr = 0

        put(win, row, box_x + 3, f"{key}.", key_attr)
        put(win, row, box_x + 7, f" {disp}", lbl_attr)
        row += 1

    put(win, row, box_x,
        "\u2514" + "\u2500" * (box_w - 2) + "\u2518", acc)

    draw_hint(win, "Press a number key to select")


# ---------------------------------------------------------------------------
# SETTINGS form
# ---------------------------------------------------------------------------

# Field definitions — order matters (Tab moves down the list)
# type: "text" | "secret" | "toggle"
_FIELDS = [
    {"key": "host",              "label": "Host / IP",          "type": "text"},
    {"key": "api_key",           "label": "API Key",             "type": "secret"},
    {"key": "username",          "label": "Username",            "type": "text"},
    {"key": "password",          "label": "Password",            "type": "secret"},
    {"key": "interval",          "label": "Poll Interval (s)",   "type": "text"},
    {"key": "temp_threshold",    "label": "Temp Threshold (°C)", "type": "text"},
    # Broadcast section
    {"key": "broadcast_enabled", "label": "Enable Broadcast",    "type": "toggle"},
    {"key": "broadcast_port",    "label": "Broadcast Port",      "type": "text"},
    {"key": "broadcast_key",     "label": "Shared Key",          "type": "secret"},
]
_SAVE_IDX = len(_FIELDS)   # index after last field = Save button


class SettingsForm:
    """Holds editable state for the settings form."""

    def __init__(self, config):
        self.values = {
            "host":              config.get("host",              ""),
            "api_key":           config.get("api_key",           ""),
            "username":          config.get("username",          ""),
            "password":          config.get("password",          ""),
            "interval":          str(config.get("interval",          5)),
            "temp_threshold":    str(config.get("temp_threshold",    82)),
            # broadcast — toggle stores a bool, text fields store strings
            "broadcast_enabled": bool(config.get("broadcast_enabled", False)),
            "broadcast_port":    str(config.get("broadcast_port",    BROADCAST_DEFAULT_PORT)),
            "broadcast_key":     config.get("broadcast_key",    BROADCAST_DEFAULT_KEY),
        }
        # Cursor position for text/secret fields (not used for toggles)
        self.cursors = {k: len(str(v)) for k, v in self.values.items()
                        if not isinstance(v, bool)}
        self.focused   = 0
        self.show_secrets = {"api_key": False, "password": False, "broadcast_key": False}
        self.status    = ""
        self.status_ok = True

    def get_config(self):
        try:
            iv = max(2, int(self.values.get("interval", "5") or "5"))
        except ValueError:
            iv = 5
        try:
            tt = int(self.values.get("temp_threshold", "82") or "82")
            tt = max(40, min(96, tt))
        except ValueError:
            tt = 82
        try:
            bp = int(self.values.get("broadcast_port",
                                     str(BROADCAST_DEFAULT_PORT)) or str(BROADCAST_DEFAULT_PORT))
            bp = max(1024, min(65535, bp))
        except ValueError:
            bp = BROADCAST_DEFAULT_PORT
        return {
            "host":              self.values["host"].strip(),
            "api_key":           self.values["api_key"].strip(),
            "username":          self.values["username"].strip(),
            "password":          self.values["password"],
            "interval":          iv,
            "temp_threshold":    tt,
            "broadcast_enabled": self.values["broadcast_enabled"],
            "broadcast_port":    bp,
            "broadcast_key":     self.values["broadcast_key"].strip() or BROADCAST_DEFAULT_KEY,
        }

    def _total(self):
        return _SAVE_IDX + 1  # fields + save button

    def handle_key(self, key):
        """
        Process one keypress.
        Returns True if Save & Connect was requested.
        """
        total = self._total()

        if self.focused == _SAVE_IDX:
            if key in (curses.KEY_ENTER, 10, 13):
                return True
            elif key in (curses.KEY_UP, curses.KEY_BTAB):
                self.focused = _SAVE_IDX - 1
            elif key in (curses.KEY_DOWN, 9):
                self.focused = 0
            return False

        # On a text/secret/toggle field
        fld = _FIELDS[self.focused]
        k   = fld["key"]

        # Toggle fields: Space/Enter flips the bool; arrows navigate
        if fld["type"] == "toggle":
            if key in (32, curses.KEY_ENTER, 10, 13):   # Space or Enter → flip
                self.values[k] = not self.values[k]
            elif key in (curses.KEY_DOWN, 9):
                self.focused = (self.focused + 1) % total
            elif key in (curses.KEY_UP, curses.KEY_BTAB):
                self.focused = (self.focused - 1) % total
            return False

        val = self.values[k]
        cur = self.cursors[k]

        if key in (curses.KEY_DOWN, 9, curses.KEY_ENTER, 10, 13):
            self.focused = (self.focused + 1) % total
        elif key in (curses.KEY_UP, curses.KEY_BTAB):
            self.focused = (self.focused - 1) % total
        elif key == curses.KEY_LEFT:
            self.cursors[k] = max(0, cur - 1)
        elif key == curses.KEY_RIGHT:
            self.cursors[k] = min(len(val), cur + 1)
        elif key == curses.KEY_HOME:
            self.cursors[k] = 0
        elif key == curses.KEY_END:
            self.cursors[k] = len(val)
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if cur > 0:
                self.values[k]  = val[:cur - 1] + val[cur:]
                self.cursors[k] = cur - 1
        elif key == curses.KEY_DC:
            if cur < len(val):
                self.values[k] = val[:cur] + val[cur + 1:]
        elif 32 <= key <= 126:   # printable ASCII
            self.values[k]  = val[:cur] + chr(key) + val[cur:]
            self.cursors[k] = cur + 1

        return False


def draw_settings(win, state, config, form):
    my, mx = win.getmaxyx()
    acc    = curses.color_pair(C_ACCENT)
    dim    = curses.color_pair(C_DIM) | curses.A_DIM
    sel    = curses.color_pair(C_SEL) | curses.A_BOLD

    W     = min(64, mx - 4)
    box_x = max(2, (mx - W) // 2)
    INW   = W - 28   # inner width of each input box
    row   = CONTENT_ROW

    # ── box top ──────────────────────────────────────────
    put(win, row, box_x, "\u250c" + "\u2500" * (W - 2) + "\u2510", acc)
    row += 1
    put(win, row, box_x,
        "\u2502" + " Connection Settings ".center(W - 2) + "\u2502", acc)
    row += 1
    put(win, row, box_x, "\u251c" + "\u2500" * (W - 2) + "\u2524", acc)
    row += 1

    # ── field rows ───────────────────────────────────────
    cursor_screen_pos = None   # (y, x) where curses cursor should go

    for i, fld in enumerate(_FIELDS):
        if row >= my - 4:
            break

        k       = fld["key"]
        label   = fld["label"]
        focused = (form.focused == i)

        # Separator before credentials block
        if k == "username":
            inner = "\u2500" * 4 + " or use credentials " + "\u2500" * (W - 26)
            put(win, row, box_x,
                "\u251c" + inner[:W - 2] + "\u2524", acc)
            row += 1
            if row >= my - 4:
                break

        # Side borders
        put(win, row, box_x,           "\u2502", acc)
        put(win, row, box_x + W - 1,   "\u2502", acc)

        # Label
        lbl_attr = 0 if focused else dim
        put(win, row, box_x + 2, f"{label:<22}", lbl_attr)

        # Value rendering — differs by field type
        val = form.values[k]
        if fld["type"] == "toggle":
            input_x  = box_x + 25
            chk_attr = sel if focused else (curses.color_pair(C_GOOD) | curses.A_BOLD if val else dim)
            put(win, row, input_x, "[X]" if val else "[ ]", chk_attr)
            put(win, row, input_x + 4,
                "On" if val else "Off",
                curses.color_pair(C_GOOD) if val else dim)
            if focused:
                cursor_screen_pos = None   # no text cursor on toggles
        else:
            cur = form.cursors[k]
            if fld["type"] == "secret" and not form.show_secrets.get(k, False):
                display  = "*" * len(val)
                disp_cur = cur
            else:
                display  = val
                disp_cur = cur

            # Clip long values to fit; scroll so cursor is always visible
            visible_w = INW - 2
            if len(display) > visible_w:
                start    = max(0, disp_cur - visible_w + 1)
                display  = display[start:start + visible_w]
                disp_cur = disp_cur - start
            disp_cur = min(disp_cur, len(display))

            input_x  = box_x + 25
            box_attr = sel if focused else dim
            put(win, row, input_x,                   "[", box_attr)
            put(win, row, input_x + 1,
                f"{display:<{visible_w}}", sel if focused else 0)
            put(win, row, input_x + 1 + visible_w,   "]", box_attr)

            if focused:
                cursor_screen_pos = (row, input_x + 1 + disp_cur)

        row += 1

    # ── separator before poll/temp ────────────────────────
    if row < my - 4:
        put(win, row, box_x, "\u251c" + "\u2500" * (W - 2) + "\u2524", acc)
        row += 1

    # ── Save & Connect button ─────────────────────────────
    if row < my - 3:
        save_focused = (form.focused == _SAVE_IDX)
        save_label   = "  [ Save & Connect ]  "
        save_attr    = sel if save_focused else (curses.color_pair(C_GOOD) | curses.A_BOLD)
        center_x     = box_x + max(0, (W - len(save_label)) // 2)
        put(win, row, box_x,           "\u2502", acc)
        put(win, row, box_x + W - 1,   "\u2502", acc)
        put(win, row, center_x, save_label, save_attr)
        if save_focused:
            cursor_screen_pos = None   # hide text cursor on button
        row += 1

    # ── box bottom ────────────────────────────────────────
    if row < my - 2:
        put(win, row, box_x, "\u2514" + "\u2500" * (W - 2) + "\u2518", acc)
        row += 1

    # ── status message (after save attempt) ───────────────
    if form.status and row < my - 2:
        st_attr = (curses.color_pair(C_GOOD) | curses.A_BOLD if form.status_ok
                   else curses.color_pair(C_CRIT) | curses.A_BOLD)
        put(win, row, box_x + 2, form.status, st_attr)

    # Move the real cursor
    if cursor_screen_pos:
        curses.curs_set(1)
        try:
            win.move(*cursor_screen_pos)
        except curses.error:
            pass
    else:
        curses.curs_set(0)

    draw_hint(win,
              "Tab/\u2193  next field   \u2191/Shift+Tab  prev   "
              "S  save   ESC  cancel")


# ---------------------------------------------------------------------------
# MONITOR view
# ---------------------------------------------------------------------------

def _pct_attr(pct):
    if pct >= 90:
        return curses.color_pair(C_CRIT) | curses.A_BOLD
    if pct >= 70:
        return curses.color_pair(C_WARN)
    return curses.color_pair(C_GOOD)


def draw_monitor(win, state, config):
    my, mx = win.getmaxyx()
    row    = CONTENT_ROW
    dim    = curses.color_pair(C_DIM)

    if state.stats is None:
        put(win, row + 2, 2, "Waiting for data...", dim | curses.A_DIM)
        draw_hint(win, "ESC  \u2014  Back to menu")
        return

    s    = state.stats
    la   = s.get("loadavg", [0, 0, 0])
    la_s = "  ".join(f"{x:.2f}" for x in la) if la else "N/A"

    cpu = s.get("cpu_percent")
    if cpu is not None:
        marker = " !!" if cpu >= 90 else "  ~" if cpu >= 70 else "   "
        put(win, row, 0,  "  CPU Usage  ", dim)
        put(win, row, 13, f"{cpu:5.1f}%  ", 0)
        put(win, row, 21, _bar(cpu), _pct_attr(cpu))
        put(win, row, 43, f" {marker}  load: {la_s}", dim)
    else:
        put(win, row, 0, "  CPU Usage   N/A", dim)
    row += 1

    mp = s.get("memory_percent")
    mu = s.get("memory_used")
    mt = s.get("memory_total")
    if mp is not None and mt:
        marker = " !!" if mp >= 90 else "  ~" if mp >= 70 else "   "
        put(win, row, 0,  "  Memory     ", dim)
        put(win, row, 13, f"{mp:5.1f}%  ", 0)
        put(win, row, 21, _bar(mp), _pct_attr(mp))
        put(win, row, 43, f" {marker}  {format_bytes(mu)} / {format_bytes(mt)}", dim)
    else:
        put(win, row, 0, "  Memory      N/A", dim)
    row += 1

    rx    = s.get("net_rx") or 0
    tx    = s.get("net_tx") or 0
    iface = s.get("net_iface", "")
    put(win, row, 0,  "  Network    ", dim)
    put(win, row, 13, "down ", curses.color_pair(C_GOOD))
    put(win, row, 18, f"{format_bytes(rx, per_second=True):<14}", curses.color_pair(C_GOOD))
    put(win, row, 32, "  up ", curses.color_pair(C_ACCENT))
    put(win, row, 37, f"{format_bytes(tx, per_second=True):<14}", curses.color_pair(C_ACCENT))
    if iface:
        put(win, row, 51, f"[{iface}]", dim | curses.A_DIM)
    row += 1

    temp           = s.get("cpu_temp")
    temp_threshold = config.get("temp_threshold", 82)
    if temp is not None:
        if temp >= 80:
            t_attr, t_label = curses.color_pair(C_CRIT) | curses.A_BOLD, "HOT!"
        elif temp >= 60:
            t_attr, t_label = curses.color_pair(C_WARN), "Warm"
        else:
            t_attr, t_label = curses.color_pair(C_GOOD), "Normal"
        put(win, row, 0,  "  CPU Temp   ", dim)
        put(win, row, 13, f"{temp:.1f}\u00b0C", t_attr)
        put(win, row, 21, f"  ({t_label})", t_attr)
        if temp >= temp_threshold:
            put(win, row, 33, "  \u26a0 ALERT",
                curses.color_pair(C_CRIT) | curses.A_BOLD)
    else:
        put(win, row, 0, "  CPU Temp    N/A", dim)
    row += 1

    pools = s.get("pools", [])
    if pools and row < my - 4:
        row += 1
        put(win, row, 0, "  STORAGE POOLS",
            curses.color_pair(C_ACCENT) | curses.A_BOLD)
        row += 1
        hline(win, row, dim | curses.A_DIM)
        row += 1

        for pool in pools:
            if row >= my - 3:
                break
            name  = pool.get("name", "?")
            pct   = pool.get("percent", 0)
            used  = pool.get("used", 0)
            total = pool.get("total", 0)
            avail = pool.get("available", 0)
            marker = "  !!" if pct >= 85 else "   ~" if pct >= 70 else "    "
            put(win, row, 0,  f"  Pool: {name:<14}", curses.color_pair(C_ACCENT))
            put(win, row, 22, f" {pct:5.1f}%  ", 0)
            put(win, row, 31, _bar(pct, 16), _pct_attr(pct))
            put(win, row, 49,
                f"{marker}  {format_bytes(used)} / {format_bytes(total)}"
                f"  ({format_bytes(avail)} free)", dim)
            row += 1

            if row < my - 3:
                disks = pool.get("disks", [])
                if disks:
                    put(win, row, 4, "Disks: ", dim | curses.A_DIM)
                    dx = 11
                    for d in disks:
                        flag = "ERR" if d["has_error"] else "ok"
                        tag  = f"{d['name']}[{flag}] "
                        attr = (curses.color_pair(C_CRIT) | curses.A_BOLD
                                if d["has_error"] else curses.color_pair(C_GOOD))
                        put(win, row, dx, tag, attr)
                        dx += len(tag)
                    row += 1

    draw_hint(win, "ESC  \u2014  Back to menu")


# ---------------------------------------------------------------------------
# ALERTS view
# ---------------------------------------------------------------------------

_SEV_ATTR = {
    "critical": lambda: curses.color_pair(C_CRIT)   | curses.A_BOLD,
    "warning":  lambda: curses.color_pair(C_WARN)   | curses.A_BOLD,
    "info":     lambda: curses.color_pair(C_ACCENT),
    "resolved": lambda: curses.color_pair(C_GOOD),
}
_SEV_LABEL = {
    "critical": "CRITICAL", "warning": "WARNING",
    "info":     "INFO",     "resolved": "RESOLVED",
}


def draw_alerts(win, state):
    my, mx = win.getmaxyx()
    dim    = curses.color_pair(C_DIM) | curses.A_DIM

    draw_hint(win, "ESC \u2014 Back     C \u2014 Clear     \u2191\u2193 \u2014 Scroll",
              curses.color_pair(C_ACCENT) | curses.A_BOLD)

    visible = my - CONTENT_ROW - 2
    with state.lock:
        alert_list = list(state.alerts)

    if not alert_list:
        put(win, CONTENT_ROW + 2, 4, "No alerts.", dim)
        return

    total = len(alert_list)
    # Clamp scroll so we can't scroll past the oldest alert
    state.alert_scroll = max(0, min(state.alert_scroll, max(0, total - visible)))
    scroll = state.alert_scroll

    # alert_list is oldest→newest; show newest at top with scroll offset
    # scroll=0 → last `visible` entries; scroll=N → entries shifted N older
    start = max(0, total - visible - scroll)
    end   = max(0, total - scroll)
    display = list(reversed(alert_list[start:end]))

    for i, a in enumerate(display):
        row = CONTENT_ROW + i
        if row >= my - 2:
            break
        if "time" in a:
            sev   = a.get("severity", "info")
            label = _SEV_LABEL.get(sev, "INFO")
            sattr = _SEV_ATTR.get(sev, lambda: 0)()
            ts_s  = f" [{a['time']}] "
            put(win, row, 0,          ts_s,          dim)
            put(win, row, len(ts_s),  f"{label}: ",  sattr)
            put(win, row, len(ts_s) + len(label) + 2, a.get("message", ""), 0)
        elif "raw" in a:
            put(win, row, 1, a["raw"], dim)

    # Scroll indicator
    if total > visible:
        shown_from = total - end + 1
        shown_to   = total - start
        put(win, my - 2, mx - 24,
            f" {shown_from}-{shown_to} of {total} ", dim)


# ---------------------------------------------------------------------------
# Polling thread
# ---------------------------------------------------------------------------

def poll_loop(client, state, config, stop_event):
    interval       = config.get("interval", 5)
    temp_threshold = config.get("temp_threshold", 82)

    while not stop_event.is_set():
        try:
            stats = client.fetch_all_stats()
            state.check_alerts(stats, temp_threshold)
            with state.lock:
                state.stats        = stats
                state.last_updated = datetime.now()
                state.last_error   = None
            if state.broadcast_server:
                state.broadcast_server.send_stats(stats)
        except Exception as e:
            with state.lock:
                state.last_error = str(e)
            debug(f"poll error: {e}")
        stop_event.wait(interval)


# ---------------------------------------------------------------------------
# Main curses loop
# ---------------------------------------------------------------------------

def run_ui(stdscr, conn, state, config):
    """
    conn is a dict: {"client": ..., "stop_event": ..., "poll_thread": ...}
    It is mutated when Save & Connect reconnects.
    """
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(200)
    init_colors()

    form = SettingsForm(config)

    VIEW_TITLES = {
        "menu":     "Main Menu",
        "settings": "Settings",
        "alerts":   "Alerts",
        "monitor":  "Monitor",
    }

    while True:
        key  = stdscr.getch()
        view = state.current_view

        # ── Settings view: all keys go to the form ──────────────────────
        if view == "settings":
            if key == 27:   # ESC — cancel
                state.current_view = "menu"
                form = SettingsForm(config)  # discard edits
            elif key in (ord("s"), ord("S")) and form.focused != _SAVE_IDX:
                # S shortcut: jump to save
                form.focused = _SAVE_IDX
            else:
                save_requested = form.handle_key(key)
                if save_requested:
                    new_cfg = form.get_config()
                    if not new_cfg["host"]:
                        form.status    = "Error: Host is required."
                        form.status_ok = False
                    elif not new_cfg["api_key"] and not (new_cfg["username"] and new_cfg["password"]):
                        form.status    = "Error: API key or username+password required."
                        form.status_ok = False
                    else:
                        form.status    = "Connecting..."
                        form.status_ok = True

                        # Render the "Connecting…" message immediately
                        stdscr.erase()
                        draw_header(stdscr, state, config, "Settings")
                        draw_settings(stdscr, state, config, form)
                        stdscr.refresh()

                        # Stop old poll thread
                        conn["stop_event"].set()
                        conn["poll_thread"].join(timeout=3)

                        # Save config
                        config.update(new_cfg)
                        save_config(config)

                        # Start/stop broadcast server per new settings
                        if new_cfg.get("broadcast_enabled"):
                            state.start_broadcast(new_cfg["broadcast_port"],
                                                   new_cfg["broadcast_key"])
                        else:
                            state.stop_broadcast()

                        # Try connecting
                        new_client = TrueNASClient(
                            host=new_cfg["host"],
                            api_key=new_cfg.get("api_key", ""),
                            username=new_cfg.get("username", ""),
                            password=new_cfg.get("password", ""),
                        )
                        try:
                            info = new_client.test_connection()
                            host = info.get("hostname", new_cfg["host"])
                            form.status    = f"Connected to {host}"
                            form.status_ok = True

                            # Start new poll thread
                            new_stop   = threading.Event()
                            new_thread = threading.Thread(
                                target=poll_loop,
                                args=(new_client, state, config, new_stop),
                                daemon=True,
                            )
                            new_thread.start()
                            conn["client"]      = new_client
                            conn["stop_event"]  = new_stop
                            conn["poll_thread"] = new_thread

                            # Go to monitor after a moment
                            time.sleep(0.8)
                            state.current_view = "monitor"
                            form = SettingsForm(config)

                        except Exception as e:
                            form.status    = f"Connection failed: {e}"
                            form.status_ok = False
                            # Restart old-style poll with updated config if possible
                            new_stop   = threading.Event()
                            new_thread = threading.Thread(
                                target=poll_loop,
                                args=(new_client, state, config, new_stop),
                                daemon=True,
                            )
                            new_thread.start()
                            conn["stop_event"]  = new_stop
                            conn["poll_thread"] = new_thread

        # ── All other views: number/ESC navigation ──────────────────────
        else:
            if key == ord("4"):
                break   # Quit
            elif key == ord("1"):
                form = SettingsForm(config)   # fresh form with current config
                state.current_view = "settings"
            elif key == ord("2"):
                with state.lock:
                    state.current_view  = "alerts"
                    state.unread_alerts = 0
                state.alert_scroll = 0
            elif key == ord("3"):
                state.current_view = "monitor"
            elif key == 27:   # ESC from any view → menu
                state.current_view = "menu"

            # Alerts-specific
            if view == "alerts":
                if key in (ord("c"), ord("C")):
                    state.clear_alerts()
                    state.alert_scroll = 0
                elif key == curses.KEY_UP:
                    state.alert_scroll += 1
                elif key == curses.KEY_DOWN:
                    state.alert_scroll = max(0, state.alert_scroll - 1)

        # ── Render ──────────────────────────────────────────────────────
        stdscr.erase()
        view  = state.current_view
        title = VIEW_TITLES.get(view, "")
        draw_header(stdscr, state, config, title)

        if view == "menu":
            curses.curs_set(0)
            draw_menu(stdscr, state)
        elif view == "settings":
            draw_settings(stdscr, state, config, form)
        elif view == "monitor":
            curses.curs_set(0)
            draw_monitor(stdscr, state, config)
        elif view == "alerts":
            curses.curs_set(0)
            draw_alerts(stdscr, state)

        stdscr.refresh()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=f"TrueMonitor v{APP_VERSION} — Interactive Text Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "If no arguments are given, settings are read from\n"
            f"  {CONFIG_FILE}\n"
            "(saved by truemonitor.py). CLI args override saved settings.\n\n"
            "Keys: 1=Settings  2=Alerts  3=Monitor  4=Quit  ESC=Menu"
        ),
    )
    parser.add_argument("--host",           metavar="IP_OR_HOST")
    parser.add_argument("--api-key",        metavar="KEY")
    parser.add_argument("--username",       metavar="USER")
    parser.add_argument("--password",       metavar="PASS")
    parser.add_argument("--interval",       type=int, metavar="SECS")
    parser.add_argument("--temp-threshold", type=int, metavar="TEMP")
    args = parser.parse_args()

    config = load_config()
    if args.host:           config["host"]          = args.host
    if args.api_key:        config["api_key"]        = args.api_key
    if args.username:       config["username"]       = args.username
    if args.password:       config["password"]       = args.password
    if args.interval:       config["interval"]       = max(2, args.interval)
    if args.temp_threshold: config["temp_threshold"] = args.temp_threshold

    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(DEBUG_LOG, "w") as f:
        f.write("")

    # If we have credentials try connecting; otherwise drop straight to settings
    has_creds = (config.get("host") and
                 (config.get("api_key") or
                  (config.get("username") and config.get("password"))))

    client = None
    if has_creds:
        client = TrueNASClient(
            host=config["host"],
            api_key=config.get("api_key", ""),
            username=config.get("username", ""),
            password=config.get("password", ""),
        )
        print(f"TrueMonitor v{APP_VERSION} — Text Mode")
        print(f"Connecting to {config['host']}...")
        try:
            info = client.test_connection()
            print(f"Connected to {info.get('hostname', config['host'])}")
            time.sleep(0.3)
        except Exception as e:
            print(f"Connection failed: {e}  (opening settings)")
            time.sleep(1)
            client = TrueNASClient(
                host=config.get("host", ""),
                api_key=config.get("api_key", ""),
                username=config.get("username", ""),
                password=config.get("password", ""),
            )

    if client is None:
        # No config at all — create a placeholder client and open settings
        client = TrueNASClient(host=config.get("host", "localhost"))

    state      = AppState()

    # Load persisted alert history from log file
    try:
        if os.path.exists(ALERT_LOG):
            with open(ALERT_LOG) as f:
                for line in f:
                    line = line.rstrip("\n")
                    if line:
                        state.alerts.append({"raw": line})
    except Exception:
        pass

    # Auto-start broadcast server if it was enabled in the saved config
    if config.get("broadcast_enabled"):
        state.start_broadcast(
            config.get("broadcast_port", BROADCAST_DEFAULT_PORT),
            config.get("broadcast_key", BROADCAST_DEFAULT_KEY),
        )

    stop_event = threading.Event()

    poll_thread = threading.Thread(
        target=poll_loop, args=(client, state, config, stop_event), daemon=True)
    poll_thread.start()

    if not has_creds:
        state.current_view = "settings"

    conn = {"client": client, "stop_event": stop_event, "poll_thread": poll_thread}

    try:
        curses.wrapper(run_ui, conn, state, config)
    finally:
        conn["stop_event"].set()
        conn["poll_thread"].join(timeout=3)


if __name__ == "__main__":
    main()
