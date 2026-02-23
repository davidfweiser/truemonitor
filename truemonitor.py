#!/usr/bin/env python3
"""TrueMonitor - Real-time TrueNAS Monitoring Dashboard"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import threading
import time
import os
import random
import subprocess
import base64
import hashlib
import getpass
from datetime import datetime, timedelta, timezone
from collections import deque

import socket
import struct
import hmac as hmac_mod
import tkinter.font as tkfont
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

FONT_SCALES = {"Small": 0.85, "Medium": 1.0, "Large": 1.15}

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
DEBUG_LOG = os.path.join(CONFIG_DIR, "debug.log")
ALERT_LOG = os.path.join(CONFIG_DIR, "alerts.log")

def debug(msg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(DEBUG_LOG, "a") as f:
        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")

def _get_encryption_key():
    """Derive a Fernet key from machine-specific data."""
    # Combine machine ID + username for a machine-local key
    seed = getpass.getuser()
    try:
        with open("/etc/machine-id") as f:
            seed += f.read().strip()
    except Exception:
        seed += os.path.expanduser("~")
    key_bytes = hashlib.sha256(seed.encode()).digest()
    return base64.urlsafe_b64encode(key_bytes)


def _encrypt(plaintext):
    """Encrypt a string, return base64-encoded ciphertext."""
    if not plaintext:
        return ""
    f = Fernet(_get_encryption_key())
    return f.encrypt(plaintext.encode()).decode()


def _decrypt(ciphertext):
    """Decrypt a base64-encoded ciphertext, return plaintext."""
    if not ciphertext:
        return ""
    try:
        f = Fernet(_get_encryption_key())
        return f.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception):
        return ciphertext  # fallback: treat as plaintext (old config)


BROADCAST_DEFAULT_PORT = 7337
BROADCAST_DEFAULT_KEY = "truemonitor"


def _derive_broadcast_key(passphrase: str) -> bytes:
    """Derive a Fernet-compatible key from a shared passphrase."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"truemonitor_broadcast_v1",
        iterations=100_000,
    )
    key_bytes = kdf.derive(passphrase.encode())
    return base64.urlsafe_b64encode(key_bytes)


def _derive_broadcast_key_raw(passphrase: str) -> bytes:
    """Derive the raw 32-byte key (used for HMAC auth handshake)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"truemonitor_broadcast_v1",
        iterations=100_000,
    )
    return kdf.derive(passphrase.encode())


# Auth handshake magic sent by server after a client connects
_AUTH_MAGIC = b"TRUEMON_AUTH\n"

# Exponential backoff delays (seconds) indexed by failure count (0-based).
# After the Nth wrong-key attempt the IP must wait this long before the
# server will accept a new connection from it.  No permanent ban — the
# backoff resets once enough time has passed with no new failures.
_BACKOFF_DELAYS = [5, 30, 300]   # 5 s, 30 s, 5 min


class BroadcastServer:
    """TCP server that encrypts and streams stats to connected TrueMonClient instances.

    Protocol:
      1. Client connects.
      2. Server sends _AUTH_MAGIC (13 bytes) + 32-byte random challenge.
      3. Client must respond within 5 s with 32-byte HMAC-SHA256(challenge, raw_key).
      4. Server verifies HMAC. Success → stream stats.
         Failure → exponential backoff (5s / 30s / 5min), never a permanent ban.
    """

    def __init__(self, port: int, passphrase: str):
        self.port = port
        self.passphrase = passphrase
        self._clients = []          # authenticated sockets
        self._lock = threading.Lock()
        self._running = False
        self._server_sock = None
        self._thread = None

        # ip → (failure_count, last_failure_time)
        self._auth_failures: dict[str, tuple] = {}
        self._sec_lock = threading.Lock()

        # Optional callback: on_security_event(level, ip, message)
        # level: "info" | "warning" | "critical"
        self.on_security_event = None

        # Broadcast a clear-alerts signal on next send_stats call.
        self._clear_alerts_at: float = 0.0
        # Optional callback: on_client_clear_alerts() — called when a client
        # sends a clear_alerts command so the server can clear its own display.
        self.on_client_clear_alerts = None

    def _get_fernet(self):
        return Fernet(_derive_broadcast_key(self.passphrase))

    def _get_raw_key(self) -> bytes:
        return _derive_broadcast_key_raw(self.passphrase)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

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

    # ------------------------------------------------------------------
    # Accept loop
    # ------------------------------------------------------------------

    def _accept_loop(self):
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind(("0.0.0.0", self.port))
            self._server_sock.listen(10)
            self._server_sock.settimeout(1.0)
            debug(f"BroadcastServer listening on port {self.port}")
            while self._running:
                try:
                    conn, addr = self._server_sock.accept()
                    ip = addr[0]
                    # Enforce backoff: silently drop connections arriving too soon
                    wait = self._backoff_remaining(ip)
                    if wait > 0:
                        debug(f"BroadcastServer: backoff {wait:.0f}s remaining for {ip}")
                        conn.close()
                        continue
                    # Each new connection gets its own auth thread
                    t = threading.Thread(
                        target=self._authenticate_client,
                        args=(conn, ip),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as e:
            debug(f"BroadcastServer error: {e}")

    # ------------------------------------------------------------------
    # Auth handshake
    # ------------------------------------------------------------------

    def _authenticate_client(self, conn: socket.socket, ip: str):
        """Run the HMAC challenge/response handshake for one client."""
        self._emit("info", ip, f"Connection from {ip}")
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

        raw_key = self._get_raw_key()
        expected = hmac_mod.new(raw_key, challenge, hashlib.sha256).digest()

        if hmac_mod.compare_digest(response, expected):
            # Authenticated
            self._emit("info", ip, f"Authenticated from {ip}")
            conn.settimeout(10.0)
            # Aggressive TCP keepalive so dead connections (sleeping phone) are
            # detected quickly and removed from the client list.
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
            # Read commands sent back from this client (e.g. clear_alerts).
            threading.Thread(
                target=self._read_client_commands,
                args=(conn, ip),
                daemon=True,
            ).start()
        else:
            # Wrong key
            self._record_failure(ip, conn)

    def _record_failure(self, ip: str, conn: socket.socket):
        """Apply exponential backoff on a wrong-key attempt (no permanent ban)."""
        conn.close()
        with self._sec_lock:
            count, _ = self._auth_failures.get(ip, (0, None))
            count += 1
            self._auth_failures[ip] = (count, datetime.now())

        delay = _BACKOFF_DELAYS[min(count - 1, len(_BACKOFF_DELAYS) - 1)]
        self._emit("warning", ip,
                   f"Wrong shared key from {ip} — retry in {delay}s")

    def _backoff_remaining(self, ip: str) -> float:
        """Return seconds the IP must still wait, or 0 if it may connect."""
        with self._sec_lock:
            entry = self._auth_failures.get(ip)
            if not entry:
                return 0
            count, last = entry
            delay = _BACKOFF_DELAYS[min(count - 1, len(_BACKOFF_DELAYS) - 1)]
            elapsed = (datetime.now() - last).total_seconds()
            remaining = delay - elapsed
            if remaining <= 0:
                # Backoff expired — clear the record so the slate is clean
                del self._auth_failures[ip]
                return 0
            return remaining

    def _emit(self, level: str, ip: str, message: str):
        debug(f"BroadcastServer [{level}] {message}")
        if self.on_security_event:
            self.on_security_event(level, ip, message)

    # ------------------------------------------------------------------
    # Client command back-channel
    # ------------------------------------------------------------------

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

    def _read_client_commands(self, conn: socket.socket, ip: str):
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

    # ------------------------------------------------------------------
    # Stats broadcast
    # ------------------------------------------------------------------

    def send_stats(self, stats: dict):
        """Encrypt stats dict and send to all authenticated clients."""
        clear_at = self._clear_alerts_at
        if clear_at:
            self._clear_alerts_at = 0.0
            stats = dict(stats)
            stats["clear_alerts_at"] = clear_at
            debug(f"BroadcastServer: broadcasting clear_alerts_at to {len(self._clients)} client(s)")
        if not self._clients:
            return
        try:
            payload = json.dumps(stats).encode()
            encrypted = self._get_fernet().encrypt(payload)
            header = struct.pack(">I", len(encrypted))
            message = header + encrypted
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


COLORS = {
    "bg": "#1a1a2e",
    "card": "#16213e",
    "card_border": "#0f3460",
    "text": "#e0e0e0",
    "text_dim": "#888899",
    "accent": "#4fc3f7",
    "good": "#66bb6a",
    "warning": "#ffa726",
    "critical": "#ef5350",
    "input_bg": "#0f3460",
    "button": "#533483",
    "button_hover": "#6a42a0",
}


def format_bytes(val, per_second=False):
    if val is None:
        return "N/A"
    suffix = "/s" if per_second else ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(val) < 1024.0:
            return f"{val:.1f} {unit}{suffix}"
        val /= 1024.0
    return f"{val:.1f} PB{suffix}"


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

    # --- public helpers ---
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

        # WebSocket JSON-RPC format: params = [graphs_list, query_dict]
        # (two separate positional args — confirmed from api.truenas.com/v25.10)
        def _attempts():
            query_iso = {
                "start": start.strftime("%Y-%m-%dT%H:%M:%S"),
                "end":   now.strftime("%Y-%m-%dT%H:%M:%S"),
                "aggregate": True,
            }
            return [
                # reporting.get_data — two-arg WebSocket format
                ("reporting.get_data",        [graphs, query_iso]),
                # reporting.netdata_get_data — same signature (underscore, not dot)
                ("reporting.netdata_get_data", [graphs, query_iso]),
                # unit-based query fallback
                ("reporting.get_data",        [graphs, {"unit": "HOUR", "page": 1, "aggregate": True}]),
                # graphs only
                ("reporting.get_data",        [graphs]),
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
                continue

        raise last_err

    def fetch_all_stats(self):
        stats = {
            "cpu_percent": None,
            "memory_used": None,
            "memory_total": None,
            "memory_percent": None,
            "cpu_temp": None,
            "net_rx": None,
            "net_tx": None,
            "net_iface": None,
            "hostname": "N/A",
            "version": "N/A",
            "uptime": "N/A",
            "loadavg": [0, 0, 0],
        }

        # System info
        try:
            info = self.get_system_info()
            debug(f" system/info keys: {list(info.keys())}")
            stats["hostname"] = info.get("hostname", "N/A")
            stats["version"] = info.get("version", "N/A")
            stats["uptime"] = info.get("uptime", "N/A")
            stats["loadavg"] = info.get("loadavg", [0, 0, 0])
            stats["memory_total"] = info.get("physmem", 0)
        except Exception as e:
            debug(f" system/info error: {e}")

        # Reporting data — CPU, Memory, CPU temperature
        try:
            graphs = [
                {"name": "cpu"},
                {"name": "memory"},
                {"name": "cputemp"},
            ]
            report = self.get_reporting_data(graphs)
            debug(f" reporting response type: {type(report)}")
            if isinstance(report, list):
                for item in report:
                    debug(f" report item keys: {list(item.keys()) if isinstance(item, dict) else item}")
                    if isinstance(item, dict):
                        debug(f"   name={item.get('name')} legend={item.get('legend')}")
                        data = item.get("data", [])
                        debug(f"   data rows: {len(data)}, last row: {data[-1] if data else 'empty'}")
            elif isinstance(report, dict):
                debug(f" reporting dict keys: {list(report.keys())}")
                debug(f" reporting response: {json.dumps(report, default=str)[:500]}")

            items = report if isinstance(report, list) else []
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = item.get("name", "")
                data = item.get("data", [])
                legend = item.get("legend", [])

                latest = None
                for row in reversed(data):
                    if row and any(v is not None for v in row[1:]):
                        latest = row
                        break
                if latest is None:
                    continue

                if name == "cpu":
                    # v25+: legend=['time','cpu','cpu0',...] where 'cpu' is overall %
                    if "cpu" in legend:
                        idx = legend.index("cpu")
                        val = latest[idx] if idx < len(latest) else None
                        if val is not None:
                            stats["cpu_percent"] = round(float(val), 1)
                    elif "idle" in legend:
                        idx = legend.index("idle")
                        idle = latest[idx] if idx < len(latest) else None
                        if idle is not None:
                            stats["cpu_percent"] = round(100.0 - idle, 1)

                elif name == "memory":
                    total = stats["memory_total"] or 0
                    if total:
                        used = None
                        # v25+: legend=['time','available'] in bytes
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
                            stats["memory_used"] = used
                            stats["memory_percent"] = round(
                                used / total * 100, 1
                            )

                elif name == "cputemp":
                    # v25+: last field 'cpu' is the overall avg
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

        # Network — try all non-loopback interfaces until one has data
        try:
            if self._working_iface:
                iface_names = [self._working_iface]
            else:
                interfaces = self.get_interfaces()
                iface_names = [i.get("name", "") for i in interfaces
                               if isinstance(i, dict) and i.get("name", "")
                               not in ("lo", "")]
                debug(f" interfaces: {iface_names}")
            for iface_name in iface_names:
                try:
                    net_report = self.get_reporting_data(
                        [{"name": "interface", "identifier": iface_name}]
                    )
                    for item in (net_report if isinstance(net_report, list) else []):
                        if not isinstance(item, dict):
                            continue
                        data = item.get("data", [])
                        legend = item.get("legend", [])
                        debug(f" net {iface_name}: legend={legend}, rows={len(data)}")
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
                            break  # found an interface with data
                except Exception as e:
                    debug(f" net {iface_name} error: {e}")
                    continue
        except Exception as e:
            debug(f" network error: {e}")

        # Pool capacity
        stats["pools"] = []
        try:
            pools = self.get_pools()
            for p in pools:
                if not isinstance(p, dict):
                    continue
                topology = p.get("topology", {})
                # Total size and allocated come from top-level pool fields
                total = p.get("size")
                allocated = p.get("allocated")
                free = p.get("free")
                # Extract disk info from topology
                disks = []
                for topo_key in ("data", "cache", "log", "spare"):
                    vdevs = topology.get(topo_key, [])
                    if not isinstance(vdevs, list):
                        continue
                    for vdev in vdevs:
                        if not isinstance(vdev, dict):
                            continue
                        children = vdev.get("children", [])
                        # If no children, the vdev itself is the disk
                        members = children if children else [vdev]
                        for member in members:
                            if not isinstance(member, dict):
                                continue
                            disk_name = member.get("disk") or member.get("name", "")
                            if not disk_name:
                                continue
                            m_stats = member.get("stats", {})
                            read_err = m_stats.get("read_errors", 0) or 0
                            write_err = m_stats.get("write_errors", 0) or 0
                            cksum_err = m_stats.get("checksum_errors", 0) or 0
                            status = member.get("status", "ONLINE")
                            has_error = (read_err + write_err + cksum_err > 0
                                         or status not in ("ONLINE", ""))
                            disks.append({
                                "name": disk_name,
                                "has_error": has_error,
                            })

                # Parse vdev structure for drive map
                vdev_map = {}
                for topo_key in ("data", "cache", "log", "spare", "special", "dedup"):
                    vdevs = topology.get(topo_key, [])
                    if not isinstance(vdevs, list) or not vdevs:
                        continue
                    vdev_list = []
                    for vdev in vdevs:
                        if not isinstance(vdev, dict):
                            continue
                        vtype = vdev.get("type", "STRIPE")
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
                                child_list.append({
                                    "name": ch.get("disk") or ch.get("name", "?"),
                                    "status": ch.get("status", "ONLINE"),
                                    "errors": errs,
                                })
                        else:
                            # Single-disk vdev (no children, vdev IS the disk)
                            v_stats = vdev.get("stats", {})
                            errs = ((v_stats.get("read_errors", 0) or 0)
                                    + (v_stats.get("write_errors", 0) or 0)
                                    + (v_stats.get("checksum_errors", 0) or 0))
                            child_list.append({
                                "name": vdev.get("disk") or vdev.get("name", "?"),
                                "status": vstatus,
                                "errors": errs,
                            })
                        vdev_list.append({
                            "type": vtype,
                            "status": vstatus,
                            "disks": child_list,
                        })
                    vdev_map[topo_key] = vdev_list

                if total and allocated is not None:
                    pct = round(allocated / total * 100, 1) if total > 0 else 0
                    stats["pools"].append({
                        "name": p.get("name", "unknown"),
                        "used": allocated,
                        "available": free or (total - allocated),
                        "total": total,
                        "percent": pct,
                        "disks": disks,
                        "topology": vdev_map,
                    })
        except Exception as e:
            debug(f" pool error: {e}")

        # System alerts from TrueNAS
        stats["system_alerts"] = []
        try:
            alerts = self.get_alerts()
            if isinstance(alerts, list):
                for alert in alerts:
                    if not isinstance(alert, dict):
                        continue
                    alert_id = (alert.get("uuid") or alert.get("id") or
                                alert.get("klass", "") + ":" + alert.get("level", ""))
                    level = alert.get("level", "INFO").upper()
                    if level in ("CRITICAL", "ERROR"):
                        severity = "critical"
                    elif level == "WARNING":
                        severity = "warning"
                    else:
                        severity = "info"
                    msg = alert.get("formatted", "") or alert.get("text", "")
                    klass = alert.get("klass", "")
                    if not msg:
                        msg = klass or "Unknown TrueNAS alert"
                    stats["system_alerts"].append({
                        "id": alert_id,
                        "severity": severity,
                        "message": msg,
                    })
        except Exception as e:
            debug(f" system alerts error: {e}")

        debug(f" final stats: {stats}")
        return stats


# ---------------------------------------------------------------------------
# Tooltip helper
# ---------------------------------------------------------------------------
class _Tooltip:
    """Lightweight tooltip that shows on mouse hover."""

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self._tw = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, event=None):
        x = self.widget.winfo_rootx() + self.widget.winfo_width() // 2
        y = self.widget.winfo_rooty() - 24
        tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(
            tw, text=self.text, bg="#333344", fg="#e0e0e0",
            font=("Helvetica", 9), padx=6, pady=2, relief="solid", bd=1,
        )
        lbl.pack()
        self._tw = tw

    def _hide(self, event=None):
        if self._tw:
            self._tw.destroy()
            self._tw = None


# ---------------------------------------------------------------------------
# GUI application
# ---------------------------------------------------------------------------
class TrueMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TrueMonitor")
        self.config = self._load_config()
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        import sys as _sys
        if _sys.platform == "darwin":
            self._base_w = min(675, int(sw * 0.675))
            self._base_h = min(525, int(sh * 0.66))
        else:
            self._base_w = min(900, int(sw * 0.90))
            self._base_h = min(700, int(sh * 0.88))
        saved_geo = self.config.get("window_geometry")
        if saved_geo:
            try:
                self.root.geometry(saved_geo)
            except Exception:
                self.root.geometry(f"{self._base_w}x{self._base_h}")
        else:
            self.root.geometry(f"{self._base_w}x{self._base_h}")
        self.root.minsize(min(560, sw - 80), min(400, sh - 80))
        self.root.configure(bg=COLORS["bg"])

        self.client = None
        self.polling = False
        self.demo_mode = False
        self.poll_thread = None
        self.broadcast_server = None
        self.net_history_rx = []
        self.net_history_tx = []
        self.temp_history = []
        self.HISTORY_LEN = 60
        self.alerts = deque(maxlen=200)
        self._temp_alert_active = False
        self._cpu_alert_active = False
        self._mem_alert_active = False
        self._seen_truenas_alerts = set()
        self._connect_alert_times: dict = {}  # ip → last alert datetime
        self.pool_cards = {}
        self._pool_count = 0
        self._font_scale = FONT_SCALES.get(
            self.config.get("font_size", "Medium"), 1.0)

        self._setup_styles()
        self._build_ui()

        if self.config.get("host"):
            self._populate_settings()
            self._connect()

        self._start_broadcast_server_if_enabled()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # --- config persistence ---
    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                # Decrypt sensitive fields
                needs_resave = False
                for key in ("password", "api_key"):
                    if data.get(f"{key}_encrypted") and data.get(key):
                        data[key] = _decrypt(data[key])
                        del data[f"{key}_encrypted"]
                    elif data.get(key):
                        # Plaintext detected — flag for re-save encrypted
                        needs_resave = True
                if needs_resave:
                    self.config = data
                    self._save_config()
                return data
            except Exception:
                pass
        return {}

    def _save_config(self):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        # Encrypt sensitive fields before saving
        save_data = dict(self.config)
        for key in ("password", "api_key"):
            if save_data.get(key):
                save_data[key] = _encrypt(save_data[key])
                save_data[f"{key}_encrypted"] = True
        with open(CONFIG_FILE, "w") as f:
            json.dump(save_data, f, indent=2)

    def _sf(self, base_size):
        """Return a font size scaled by the current font scale factor."""
        return max(6, int(round(base_size * self._font_scale)))

    # --- ttk styles ---
    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")

        s.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        s.configure(
            "TNotebook.Tab",
            background=COLORS["card"],
            foreground=COLORS["text"],
            padding=[18, 8],
            font=("Helvetica", self._sf(11)),
        )
        s.map(
            "TNotebook.Tab",
            background=[("selected", COLORS["card_border"])],
            foreground=[("selected", COLORS["accent"])],
        )

        for name, opts in {
            "Card.TLabel": {"bg": COLORS["card"], "fg": COLORS["text"],
                            "font": ("Helvetica", self._sf(11))},
            "CardTitle.TLabel": {"bg": COLORS["card"], "fg": COLORS["accent"],
                                 "font": ("Helvetica", self._sf(12), "bold")},
            "CardValue.TLabel": {"bg": COLORS["card"], "fg": COLORS["text"],
                                  "font": ("Helvetica", self._sf(28), "bold")},
            "CardSub.TLabel": {"bg": COLORS["card"], "fg": COLORS["text_dim"],
                                "font": ("Helvetica", self._sf(10))},
            "Status.TLabel": {"bg": COLORS["bg"], "fg": COLORS["text_dim"],
                               "font": ("Helvetica", self._sf(10))},
            "StatusOK.TLabel": {"bg": COLORS["bg"], "fg": COLORS["good"],
                                 "font": ("Helvetica", self._sf(10))},
            "StatusErr.TLabel": {"bg": COLORS["bg"], "fg": COLORS["critical"],
                                  "font": ("Helvetica", self._sf(10))},
            "Settings.TLabel": {"bg": COLORS["bg"], "fg": COLORS["text"],
                                 "font": ("Helvetica", self._sf(11))},
            "SettingsH.TLabel": {"bg": COLORS["bg"], "fg": COLORS["accent"],
                                  "font": ("Helvetica", self._sf(14), "bold")},
        }.items():
            s.configure(name, background=opts["bg"], foreground=opts["fg"],
                        font=opts["font"])

        s.configure(
            "Horizontal.TProgressbar",
            background=COLORS["accent"],
            troughcolor=COLORS["input_bg"],
            borderwidth=0,
            thickness=20,
        )
        s.configure(
            "Settings.TCombobox",
            fieldbackground=COLORS["input_bg"],
            background=COLORS["card"],
            foreground=COLORS["text"],
            arrowcolor=COLORS["text"],
            selectbackground=COLORS["input_bg"],
            selectforeground=COLORS["text"],
        )
        s.map(
            "Settings.TCombobox",
            fieldbackground=[("readonly", COLORS["input_bg"])],
            foreground=[("readonly", COLORS["text"])],
            selectbackground=[("readonly", COLORS["input_bg"])],
            selectforeground=[("readonly", COLORS["text"])],
        )
        self.root.option_add("*TCombobox*Listbox.background", COLORS["input_bg"])
        self.root.option_add("*TCombobox*Listbox.foreground", COLORS["text"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", COLORS["card_border"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", COLORS["text"])
        self.root.option_add("*TCombobox*Listbox.font", ("Helvetica", self._sf(11)))

        for color_name, color_val in (("green", COLORS["good"]),
                                       ("yellow", COLORS["warning"]),
                                       ("red", COLORS["critical"])):
            s.configure(
                f"Pool{color_name}.Horizontal.TProgressbar",
                background=color_val,
                troughcolor=COLORS["input_bg"],
                borderwidth=0,
                thickness=16,
            )

    # --- UI construction ---
    def _build_ui(self):
        self._main_frame = tk.Frame(self.root, bg=COLORS["bg"])
        self._main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        main = self._main_frame

        # header
        hdr = tk.Frame(main, bg=COLORS["bg"])
        hdr.pack(fill=tk.X, pady=(0, 8))
        tk.Label(
            hdr, text="TrueMonitor", bg=COLORS["bg"], fg=COLORS["accent"],
            font=("Helvetica", self._sf(20), "bold"),
        ).pack(side=tk.LEFT)
        tk.Label(
            hdr, text=f"v{APP_VERSION}", bg=COLORS["bg"], fg=COLORS["text_dim"],
            font=("Helvetica", self._sf(9)),
        ).pack(side=tk.LEFT, padx=(6, 0), pady=(6, 0))
        self.status_lbl = ttk.Label(hdr, text="Disconnected",
                                    style="Status.TLabel")
        self.status_lbl.pack(side=tk.RIGHT, padx=10)

        # tabs
        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.mon_frame = tk.Frame(self.notebook, bg=COLORS["bg"])
        self.alert_frame = tk.Frame(self.notebook, bg=COLORS["bg"])
        self.set_frame = tk.Frame(self.notebook, bg=COLORS["bg"])
        self.notebook.add(self.mon_frame, text="  Monitor  ")
        self.notebook.add(self.alert_frame, text="  Alerts  ")
        self.notebook.add(self.set_frame, text="  Settings  ")

        self._build_monitor()
        self._build_alerts_tab()
        self._build_settings()

        # footer
        footer_frame = tk.Frame(main, bg=COLORS["bg"])
        footer_frame.pack(fill=tk.X, pady=(6, 0))
        self.footer = tk.Label(footer_frame, text="", bg=COLORS["bg"],
                               fg=COLORS["text_dim"], font=("Helvetica", self._sf(9)))
        self.footer.pack(side=tk.LEFT)

    def _make_card(self, parent, title, row, col):
        f = tk.Frame(
            parent, bg=COLORS["card"],
            highlightbackground=COLORS["card_border"], highlightthickness=1,
            padx=18, pady=14,
        )
        f.grid(row=row, column=col, padx=16, pady=16, sticky="nsew")

        ttk.Label(f, text=title, style="CardTitle.TLabel").pack(anchor="w")
        val = ttk.Label(f, text="--", style="CardValue.TLabel")
        val.pack(anchor="w", pady=(10, 4))
        sub = ttk.Label(f, text="", style="CardSub.TLabel")
        sub.pack(anchor="w")

        bar = bar_var = None
        if title in ("CPU Usage", "Memory"):
            bar_var = tk.DoubleVar(value=0)
            bar = ttk.Progressbar(
                f, variable=bar_var, maximum=100,
                style="Horizontal.TProgressbar", length=220,
            )
            bar.pack(fill=tk.X, pady=(10, 0))

        return {"frame": f, "value": val, "sub": sub,
                "bar": bar, "bar_var": bar_var}

    def _build_monitor(self):
        # info bar
        info_f = tk.Frame(
            self.mon_frame, bg=COLORS["card"],
            highlightbackground=COLORS["card_border"], highlightthickness=1,
            padx=14, pady=8,
        )
        info_f.pack(fill=tk.X, padx=8, pady=(8, 0))
        self.info_lbl = tk.Label(
            info_f, text="Connect to TrueNAS to begin monitoring",
            bg=COLORS["card"], fg=COLORS["text"], font=("Helvetica", self._sf(10)),
        )
        self.info_lbl.pack(anchor="w")

        # metric cards
        self.grid = tk.Frame(self.mon_frame, bg=COLORS["bg"])
        self.grid.pack(fill=tk.BOTH, expand=True, pady=8)
        self.grid.columnconfigure(0, weight=1)
        self.grid.columnconfigure(1, weight=1)
        self.grid.rowconfigure(0, weight=1)
        self.grid.rowconfigure(1, weight=1)

        self.cpu_card = self._make_card(self.grid, "CPU Usage", 0, 0)
        self.mem_card = self._make_card(self.grid, "Memory", 0, 1)
        self._build_net_graph(self.grid, 1, 0)
        self._build_temp_graph(self.grid, 1, 1)

    def _build_net_graph(self, parent, row, col):
        f = tk.Frame(
            parent, bg=COLORS["card"],
            highlightbackground=COLORS["card_border"], highlightthickness=1,
            padx=18, pady=14,
        )
        f.grid(row=row, column=col, padx=16, pady=16, sticky="nsew")

        # Title row
        hdr = tk.Frame(f, bg=COLORS["card"])
        hdr.pack(fill=tk.X)
        ttk.Label(hdr, text="Network", style="CardTitle.TLabel").pack(
            side=tk.LEFT)

        # Legend (right side of title)
        leg = tk.Frame(hdr, bg=COLORS["card"])
        leg.pack(side=tk.RIGHT)
        tk.Label(leg, text="\u25cf", fg=COLORS["good"], bg=COLORS["card"],
                 font=("Helvetica", self._sf(10))).pack(side=tk.LEFT)
        tk.Label(leg, text="In ", fg=COLORS["text_dim"], bg=COLORS["card"],
                 font=("Helvetica", self._sf(9))).pack(side=tk.LEFT)
        tk.Label(leg, text="\u25cf", fg=COLORS["accent"], bg=COLORS["card"],
                 font=("Helvetica", self._sf(10))).pack(side=tk.LEFT)
        tk.Label(leg, text="Out", fg=COLORS["text_dim"], bg=COLORS["card"],
                 font=("Helvetica", self._sf(9))).pack(side=tk.LEFT)

        # Current speed labels
        speed_f = tk.Frame(f, bg=COLORS["card"])
        speed_f.pack(fill=tk.X, pady=(6, 4))
        self.net_rx_lbl = tk.Label(
            speed_f, text="\u2193 --", bg=COLORS["card"], fg=COLORS["good"],
            font=("Helvetica", self._sf(14), "bold"))
        self.net_rx_lbl.pack(side=tk.LEFT, padx=(0, 16))
        self.net_tx_lbl = tk.Label(
            speed_f, text="\u2191 --", bg=COLORS["card"], fg=COLORS["accent"],
            font=("Helvetica", self._sf(14), "bold"))
        self.net_tx_lbl.pack(side=tk.LEFT)
        self.net_iface_lbl = tk.Label(
            speed_f, text="", bg=COLORS["card"], fg=COLORS["text_dim"],
            font=("Helvetica", self._sf(9)))
        self.net_iface_lbl.pack(side=tk.RIGHT)

        # Canvas for the graph
        self.net_canvas = tk.Canvas(
            f, bg="#0a1628", highlightthickness=0, height=120)
        self.net_canvas.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        # Y-axis scale label
        self.net_scale_lbl = tk.Label(
            f, text="", bg=COLORS["card"], fg=COLORS["text_dim"],
            font=("Helvetica", self._sf(8)))
        self.net_scale_lbl.pack(anchor="e")

    def _draw_net_graph(self):
        c = self.net_canvas
        c.delete("all")

        w = c.winfo_width()
        h = c.winfo_height()
        if w < 10 or h < 10:
            return

        pad_bottom = 2
        graph_h = h - pad_bottom
        n = self.HISTORY_LEN

        # Find the max value for Y-axis scaling
        all_vals = self.net_history_rx + self.net_history_tx
        max_val = max(all_vals) if all_vals else 1
        if max_val <= 0:
            max_val = 1

        # Draw horizontal grid lines
        for i in range(1, 4):
            y = int(graph_h * i / 4)
            c.create_line(0, y, w, y, fill="#1a2a4a", dash=(2, 4))

        # Draw data lines
        def draw_line(data, color):
            if len(data) < 2:
                return
            points = []
            count = len(data)
            for i, val in enumerate(data):
                x = int(w * i / (n - 1)) if n > 1 else 0
                y = graph_h - int((val / max_val) * (graph_h - 4)) - 2
                y = max(2, min(graph_h - 2, y))
                points.append(x)
                points.append(y)
            if len(points) >= 4:
                c.create_line(points, fill=color, width=2, smooth=True)

        draw_line(self.net_history_rx, COLORS["good"])
        draw_line(self.net_history_tx, COLORS["accent"])

        # Scale label
        self.net_scale_lbl.config(text=f"Peak: {format_bytes(max_val, per_second=True)}")

    def _build_temp_graph(self, parent, row, col):
        f = tk.Frame(
            parent, bg=COLORS["card"],
            highlightbackground=COLORS["card_border"], highlightthickness=1,
            padx=18, pady=14,
        )
        f.grid(row=row, column=col, padx=16, pady=16, sticky="nsew")

        # Title row
        hdr = tk.Frame(f, bg=COLORS["card"])
        hdr.pack(fill=tk.X)
        ttk.Label(hdr, text="CPU Temperature", style="CardTitle.TLabel").pack(
            side=tk.LEFT)

        # Current temp and status
        temp_f = tk.Frame(f, bg=COLORS["card"])
        temp_f.pack(fill=tk.X, pady=(6, 4))
        self.temp_val_lbl = tk.Label(
            temp_f, text="--", bg=COLORS["card"], fg=COLORS["text"],
            font=("Helvetica", self._sf(28), "bold"))
        self.temp_val_lbl.pack(side=tk.LEFT)
        self.temp_status_lbl = tk.Label(
            temp_f, text="", bg=COLORS["card"], fg=COLORS["text_dim"],
            font=("Helvetica", self._sf(11)))
        self.temp_status_lbl.pack(side=tk.LEFT, padx=(12, 0))
        self.temp_range_lbl = tk.Label(
            temp_f, text="", bg=COLORS["card"], fg=COLORS["text_dim"],
            font=("Helvetica", self._sf(9)))
        self.temp_range_lbl.pack(side=tk.RIGHT)

        # Canvas for the graph
        self.temp_canvas = tk.Canvas(
            f, bg="#0a1628", highlightthickness=0, height=120)
        self.temp_canvas.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

    def _draw_temp_graph(self):
        c = self.temp_canvas
        c.delete("all")

        w = c.winfo_width()
        h = c.winfo_height()
        if w < 10 or h < 10:
            return

        pad = 2
        graph_h = h - pad
        n = self.HISTORY_LEN

        if not self.temp_history:
            return

        # Fixed scale: 20-100 C
        t_min = 20
        t_max = 100
        t_range = t_max - t_min

        # Draw temperature zone backgrounds
        def y_for_temp(t):
            return int(graph_h - ((t - t_min) / t_range) * (graph_h - 4) - 2)

        # Hot zone (80+)
        y_hot = y_for_temp(80)
        c.create_rectangle(0, 0, w, y_hot, fill="#2a1015", outline="")
        # Warm zone (60-80)
        y_warm = y_for_temp(60)
        c.create_rectangle(0, y_hot, w, y_warm, fill="#2a2010", outline="")

        # Threshold lines
        c.create_line(0, y_hot, w, y_hot, fill=COLORS["critical"], dash=(3, 3))
        c.create_text(w - 4, y_hot - 8, text="80\u00b0C", fill=COLORS["critical"],
                      font=("Helvetica", self._sf(7)), anchor="e")
        c.create_line(0, y_warm, w, y_warm, fill=COLORS["warning"], dash=(3, 3))
        c.create_text(w - 4, y_warm - 8, text="60\u00b0C", fill=COLORS["warning"],
                      font=("Helvetica", self._sf(7)), anchor="e")

        # Draw the temperature line
        points = []
        for i, val in enumerate(self.temp_history):
            x = int(w * i / (n - 1)) if n > 1 else 0
            y = y_for_temp(val)
            y = max(2, min(graph_h - 2, y))
            points.append(x)
            points.append(y)

        if len(points) >= 4:
            # Determine line color from latest temp
            latest = self.temp_history[-1]
            col = (COLORS["good"] if latest < 60
                   else COLORS["warning"] if latest < 80
                   else COLORS["critical"])
            c.create_line(points, fill=col, width=2, smooth=True)

        # Range label
        lo = min(self.temp_history)
        hi = max(self.temp_history)
        self.temp_range_lbl.config(text=f"Low: {lo:.0f}\u00b0C  High: {hi:.0f}\u00b0C")

    def _build_pool_cards(self, pools):
        """Dynamically create pool capacity cards in the monitor grid."""
        import math
        # Remove existing pool card widgets
        for card in self.pool_cards.values():
            card["frame"].destroy()
        self.pool_cards = {}

        num_pools = len(pools)
        if num_pools == 0:
            return

        self._pool_count = num_pools
        pool_rows = math.ceil(num_pools / 2)

        # Add row weights for pool rows (rows 2+)
        for r in range(pool_rows):
            self.grid.rowconfigure(2 + r, weight=1)

        for i, pool in enumerate(pools):
            row = 2 + i // 2
            col = i % 2
            name = pool.get("name", "unknown")

            f = tk.Frame(
                self.grid, bg=COLORS["card"],
                highlightbackground=COLORS["card_border"], highlightthickness=1,
                padx=18, pady=14,
            )
            f.grid(row=row, column=col, padx=16, pady=16, sticky="nsew")

            title_row = tk.Frame(f, bg=COLORS["card"])
            title_row.pack(fill=tk.X)
            ttk.Label(title_row, text=f"Pool: {name}", style="CardTitle.TLabel").pack(
                side=tk.LEFT)
            topo = pool.get("topology", {})
            import sys as _sys
            _map_bg = "#ffffff" if _sys.platform == "win32" else COLORS["button"]
            _map_hover = "#e0e0e0" if _sys.platform == "win32" else COLORS["button_hover"]
            map_btn = tk.Button(
                title_row, text="Drive Map", bg=_map_bg,
                fg="#000000", activebackground=_map_hover,
                activeforeground="#000000",
                font=("Helvetica", self._sf(8)), relief="flat", padx=8, pady=2,
                command=lambda n=name, t=topo: self._show_drive_map(n, t),
            )
            map_btn.pack(side=tk.RIGHT)

            val_lbl = ttk.Label(f, text="--", style="CardValue.TLabel")
            val_lbl.pack(anchor="w", pady=(8, 2))

            sub_lbl = ttk.Label(f, text="", style="CardSub.TLabel")
            sub_lbl.pack(anchor="w")

            bar_var = tk.DoubleVar(value=0)
            bar = ttk.Progressbar(
                f, variable=bar_var, maximum=100,
                style="Poolgreen.Horizontal.TProgressbar", length=220,
            )
            bar.pack(fill=tk.X, pady=(10, 0))

            # Disk health indicator row
            disk_frame = tk.Frame(f, bg=COLORS["card"])
            disk_frame.pack(anchor="w", pady=(8, 0))
            disk_label = tk.Label(
                disk_frame, text="Disks:", bg=COLORS["card"],
                fg=COLORS["text_dim"], font=("Helvetica", self._sf(9)),
            )
            disk_label.pack(side=tk.LEFT, padx=(0, 6))

            disk_rects = []
            disks = pool.get("disks", [])
            for disk in disks:
                color = COLORS["critical"] if disk["has_error"] else COLORS["good"]
                img = tk.PhotoImage(width=14, height=20)
                img.put(color, to=(0, 0, 14, 20))
                rect = tk.Label(disk_frame, image=img, bd=0, highlightthickness=0)
                rect._img = img  # prevent garbage collection
                rect.pack(side=tk.LEFT, padx=2)
                _Tooltip(rect, disk["name"])
                disk_rects.append(rect)

            self.pool_cards[name] = {
                "frame": f, "value": val_lbl, "sub": sub_lbl,
                "bar": bar, "bar_var": bar_var,
                "disk_frame": disk_frame, "disk_rects": disk_rects,
                "topology": topo, "map_btn": map_btn,
            }

        # Resize window to fit pool content
        pool_rows_total = math.ceil(num_pools / 2)
        sh = self.root.winfo_screenheight()
        sw = self.root.winfo_screenwidth()
        max_h = int(sh * 0.92)
        self.root.update_idletasks()
        needed_h = self.root.winfo_reqheight() + 40
        new_height = min(max(needed_h, self._base_h + pool_rows_total * 210), max_h)
        cur_geo = self.root.geometry()
        try:
            cur_parts = cur_geo.split("x")
            width = int(cur_parts[0])
            cur_h = int(cur_parts[1].split("+")[0])
        except (ValueError, IndexError):
            width = self._base_w
            cur_h = 0
        if new_height > cur_h:
            self.root.geometry(f"{width}x{new_height}")
        self.root.minsize(min(560, sw - 80), min(400, sh - 80))

    def _show_drive_map(self, pool_name, topology):
        """Open a popup window showing the vdev/drive layout of a pool."""
        win = tk.Toplevel(self.root)
        win.title(f"Drive Map - {pool_name}")
        win.configure(bg=COLORS["bg"])
        win.minsize(400, 200)

        # Header
        tk.Label(
            win, text=f"Pool: {pool_name}", bg=COLORS["bg"],
            fg=COLORS["accent"], font=("Helvetica", self._sf(16), "bold"),
            padx=16, pady=12,
        ).pack(anchor="w")

        # Scrollable content
        canvas = tk.Canvas(win, bg=COLORS["bg"], highlightthickness=0)
        scrollbar = tk.Scrollbar(win, orient=tk.VERTICAL, command=canvas.yview)
        content = tk.Frame(canvas, bg=COLORS["bg"])

        content.bind("<Configure>",
                     lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=content, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=16, pady=(0, 16))
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        if not topology:
            tk.Label(
                content, text="No topology data available",
                bg=COLORS["bg"], fg=COLORS["text_dim"],
                font=("Helvetica", self._sf(11)),
            ).pack(pady=20)
            return

        group_labels = {
            "data": "Data VDevs",
            "cache": "Cache (L2ARC)",
            "log": "Log (SLOG)",
            "spare": "Hot Spares",
            "special": "Special VDevs",
            "dedup": "Dedup VDevs",
        }

        for group_key in ("data", "cache", "log", "spare", "special", "dedup"):
            vdevs = topology.get(group_key, [])
            if not vdevs:
                continue

            # Group header
            group_frame = tk.Frame(content, bg=COLORS["bg"])
            group_frame.pack(fill=tk.X, pady=(8, 4), padx=4)

            tk.Label(
                group_frame, text=group_labels.get(group_key, group_key),
                bg=COLORS["bg"], fg=COLORS["accent"],
                font=("Helvetica", self._sf(12), "bold"),
            ).pack(anchor="w")

            for vi, vdev in enumerate(vdevs):
                vtype = vdev.get("type", "DISK")
                vstatus = vdev.get("status", "ONLINE")
                vdisks = vdev.get("disks", [])

                # Vdev container
                vdev_frame = tk.Frame(
                    content, bg=COLORS["card"],
                    highlightbackground=COLORS["card_border"],
                    highlightthickness=1, padx=12, pady=8,
                )
                vdev_frame.pack(fill=tk.X, padx=12, pady=4)

                # Vdev header row
                vhdr = tk.Frame(vdev_frame, bg=COLORS["card"])
                vhdr.pack(fill=tk.X)

                # Vdev type label with icon
                type_color = COLORS["accent"]
                if vtype == "MIRROR":
                    type_icon = "\u2194"  # ↔
                elif vtype.startswith("RAIDZ"):
                    type_icon = "\u2726"  # ✦
                elif vtype == "STRIPE":
                    type_icon = "\u2502"  # │
                else:
                    type_icon = "\u25cb"  # ○

                tk.Label(
                    vhdr, text=f" {type_icon}  {vtype}",
                    bg=COLORS["card"], fg=type_color,
                    font=("Helvetica", self._sf(11), "bold"),
                ).pack(side=tk.LEFT)

                # Status badge
                st_color = COLORS["good"] if vstatus == "ONLINE" else COLORS["critical"]
                tk.Label(
                    vhdr, text=vstatus, bg=COLORS["card"], fg=st_color,
                    font=("Helvetica", self._sf(9)),
                ).pack(side=tk.RIGHT)

                # Disk grid
                disk_grid = tk.Frame(vdev_frame, bg=COLORS["card"])
                disk_grid.pack(fill=tk.X, pady=(6, 0))

                for di, disk in enumerate(vdisks):
                    dname = disk.get("name", "?")
                    dstatus = disk.get("status", "ONLINE")
                    derrors = disk.get("errors", 0)

                    has_err = derrors > 0 or dstatus not in ("ONLINE", "")
                    disk_bg = "#1a2a1a" if not has_err else "#5c1a1a"
                    border_col = COLORS["good"] if not has_err else COLORS["critical"]

                    disk_box = tk.Frame(
                        disk_grid, bg=disk_bg,
                        highlightbackground=border_col, highlightthickness=2,
                        padx=8, pady=4,
                    )
                    disk_box.pack(side=tk.LEFT, padx=4, pady=2)

                    # Drive name
                    name_fg = "#ffffff" if has_err else COLORS["text"]
                    tk.Label(
                        disk_box, text=dname, bg=disk_bg,
                        fg=name_fg,
                        font=("Helvetica", self._sf(10), "bold"),
                    ).pack()

                    # Status line
                    status_text = dstatus
                    if derrors > 0:
                        status_text += f" ({derrors} err)"
                    st_col = COLORS["good"] if not has_err else COLORS["critical"]
                    tk.Label(
                        disk_box, text=status_text, bg=disk_bg,
                        fg=st_col, font=("Helvetica", self._sf(7)),
                    ).pack()

                    # Draw connecting line between disks in mirror/raidz
                    if di < len(vdisks) - 1 and vtype in ("MIRROR", "RAIDZ1", "RAIDZ2", "RAIDZ3"):
                        conn = tk.Label(
                            disk_grid, text="\u2500\u2500",
                            bg=COLORS["card"], fg=COLORS["card_border"],
                            font=("Helvetica", self._sf(8)),
                        )
                        conn.pack(side=tk.LEFT)

        # Close button
        tk.Button(
            win, text="Close", bg=COLORS["button"], fg="#000000",
            activebackground=COLORS["button_hover"],
            activeforeground="#000000",
            font=("Helvetica", self._sf(10)), relief="flat", padx=20, pady=6,
            command=win.destroy,
        ).pack(pady=(0, 12))

        # Size window based on content
        win.update_idletasks()
        w = max(500, content.winfo_reqwidth() + 60)
        h = min(700, content.winfo_reqheight() + 120)
        win.geometry(f"{w}x{h}")

    def _build_alerts_tab(self):
        # Header
        hdr = tk.Frame(self.alert_frame, bg=COLORS["bg"], pady=8, padx=12)
        hdr.pack(fill=tk.X)
        ttk.Label(hdr, text="Alert Log", style="SettingsH.TLabel").pack(
            side=tk.LEFT)
        self.alert_count_lbl = tk.Label(
            hdr, text="0 alerts", bg=COLORS["bg"], fg=COLORS["text_dim"],
            font=("Helvetica", self._sf(10)))
        self.alert_count_lbl.pack(side=tk.LEFT, padx=(12, 0))

        import sys as _sys
        _clr_bg = "#ffffff" if _sys.platform == "win32" else COLORS["card"]
        _clr_hover = "#e0e0e0" if _sys.platform == "win32" else COLORS["card_border"]
        clear_btn = tk.Button(
            hdr, text="Clear All", bg=_clr_bg, fg="#000000",
            activebackground=_clr_hover,
            activeforeground="#000000",
            font=("Helvetica", self._sf(10)), relief="flat", padx=14, pady=4,
            command=self._clear_alerts)
        clear_btn.pack(side=tk.RIGHT)

        # Scrollable alert list
        list_frame = tk.Frame(self.alert_frame, bg=COLORS["bg"], padx=12)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.alert_listbox = tk.Text(
            list_frame, bg=COLORS["card"], fg=COLORS["text"],
            font=("Courier", self._sf(10)), relief="flat", bd=8,
            wrap=tk.WORD, state=tk.DISABLED,
            yscrollcommand=scrollbar.set,
            highlightbackground=COLORS["card_border"], highlightthickness=1)
        self.alert_listbox.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.alert_listbox.yview)

        # Configure text tags for severity colors
        self.alert_listbox.tag_configure("critical",
                                         foreground=COLORS["critical"])
        self.alert_listbox.tag_configure("warning",
                                         foreground=COLORS["warning"])
        self.alert_listbox.tag_configure("info",
                                         foreground=COLORS["accent"])
        self.alert_listbox.tag_configure("resolved",
                                         foreground=COLORS["good"])
        self.alert_listbox.tag_configure("timestamp",
                                         foreground=COLORS["text_dim"])

        # Load previous alerts from log file
        self._load_alerts_from_file()

    def _load_alerts_from_file(self):
        if not os.path.exists(ALERT_LOG):
            return
        try:
            with open(ALERT_LOG) as f:
                lines = f.readlines()
            self.alert_listbox.config(state=tk.NORMAL)
            for line in lines:
                line = line.rstrip("\n")
                if not line:
                    continue
                # Determine severity tag from the line
                tag = "info"
                for key, sev in (("CRITICAL:", "critical"), ("WARNING:", "warning"),
                                 ("RESOLVED:", "resolved"), ("INFO:", "info")):
                    if key in line:
                        tag = sev
                        break
                self.alert_listbox.insert(tk.END, line + "\n", tag)
                self.alerts.append({"raw": line})
            self.alert_listbox.config(state=tk.DISABLED)
            count = len(self.alerts)
            self.alert_count_lbl.config(
                text=f"{count} alert{'s' if count != 1 else ''}")
        except Exception:
            pass

    def _add_alert(self, severity, message, popup=False, sound=False):
        """Add an alert to the log. severity: critical, warning, info, resolved"""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {"time": ts, "severity": severity, "message": message}
        self.alerts.append(entry)

        # Persist to log file
        prefix = {"critical": "CRITICAL", "warning": "WARNING",
                  "info": "INFO", "resolved": "RESOLVED"}.get(severity, "INFO")
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(ALERT_LOG, "a") as f:
                f.write(f"[{ts}] {prefix}: {message}\n")
        except Exception:
            pass

        # Update the text widget
        self.alert_listbox.config(state=tk.NORMAL)
        self.alert_listbox.insert(
            "1.0", f"[{ts}] ", "timestamp")
        self.alert_listbox.insert(
            "1.end", f"{prefix}: ", severity)
        self.alert_listbox.insert(
            "1.end", f"{message}\n", "")
        self.alert_listbox.config(state=tk.DISABLED)

        # Update count
        count = len(self.alerts)
        self.alert_count_lbl.config(text=f"{count} alert{'s' if count != 1 else ''}")

        # Flash the Alerts tab
        if severity in ("critical", "warning"):
            self.notebook.tab(1, text="  Alerts *  ")

        # Sound
        if sound:
            self._play_warning_sound()

        # Popup
        if popup:
            icon = "warning" if severity == "warning" else "error"
            title = "TrueMonitor Alert"
            messagebox.showwarning(title, f"{prefix}: {message}")

    def _play_warning_sound(self):
        """Play a system warning sound (cross-platform)."""
        import sys
        def _sound():
            platform = sys.platform
            try:
                if platform == "win32":
                    # Windows: use built-in winsound module
                    import winsound
                    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
                    return
                elif platform == "darwin":
                    # macOS: use afplay with system alert sound
                    subprocess.run(
                        ["afplay", "/System/Library/Sounds/Sosumi.aiff"],
                        timeout=3, capture_output=True)
                    return
                else:
                    # Linux: try paplay (PulseAudio)
                    result = subprocess.run(
                        ["paplay", "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"],
                        timeout=3, capture_output=True)
                    if result.returncode == 0:
                        return
                    # Linux fallback: aplay
                    subprocess.run(
                        ["aplay", "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"],
                        timeout=3, capture_output=True)
                    return
            except Exception:
                pass
            # Last resort: terminal bell
            try:
                print("\a", end="", flush=True)
            except Exception:
                pass
        threading.Thread(target=_sound, daemon=True).start()

    def _clear_alerts(self):
        """User-initiated clear: clears locally and tells all clients to clear."""
        self._do_clear_alerts_local()
        if self.broadcast_server:
            self.broadcast_server.request_clear_alerts()

    def _do_clear_alerts_local(self):
        """Clear alerts display and log without triggering a broadcast."""
        self.alerts.clear()
        self.alert_listbox.config(state=tk.NORMAL)
        self.alert_listbox.delete("1.0", tk.END)
        self.alert_listbox.config(state=tk.DISABLED)
        self.alert_count_lbl.config(text="0 alerts")
        self.notebook.tab(1, text="  Alerts  ")
        try:
            with open(ALERT_LOG, "w") as f:
                f.write("")
        except Exception:
            pass

    def _on_client_clear_alerts(self):
        """Called (on worker thread) when a client sends clear_alerts command."""
        self.root.after(0, self._do_clear_alerts_local)

    def _check_alerts(self, stats):
        """Check stats and fire alerts as needed."""
        # --- CPU Temperature threshold (configurable) ---
        try:
            temp_limit = int(self.temp_threshold_var.get())
        except (ValueError, TypeError):
            temp_limit = self.config.get("temp_threshold", 82)
        temp = stats.get("cpu_temp")
        if temp is not None:
            if temp > temp_limit:
                if not self._temp_alert_active:
                    self._temp_alert_active = True
                    self._add_alert(
                        "critical",
                        f"CPU temperature is {temp}\u00b0C (above {temp_limit}\u00b0C threshold)!",
                        popup=True, sound=True)
            else:
                if self._temp_alert_active:
                    self._temp_alert_active = False
                    self._add_alert(
                        "resolved",
                        f"CPU temperature back to normal: {temp}\u00b0C")

        # --- CPU usage > 95% ---
        cpu = stats.get("cpu_percent")
        if cpu is not None:
            if cpu > 95:
                if not self._cpu_alert_active:
                    self._cpu_alert_active = True
                    self._add_alert(
                        "warning",
                        f"CPU usage critically high: {cpu}%",
                        popup=True, sound=True)
            else:
                if self._cpu_alert_active:
                    self._cpu_alert_active = False
                    self._add_alert(
                        "resolved",
                        f"CPU usage back to normal: {cpu}%")

        # --- Memory usage > 95% ---
        mem_pct = stats.get("memory_percent")
        if mem_pct is not None:
            if mem_pct > 95:
                if not self._mem_alert_active:
                    self._mem_alert_active = True
                    self._add_alert(
                        "warning",
                        f"Memory usage critically high: {mem_pct}%",
                        popup=True, sound=True)
            else:
                if self._mem_alert_active:
                    self._mem_alert_active = False
                    self._add_alert(
                        "resolved",
                        f"Memory usage back to normal: {mem_pct}%")

        # --- TrueNAS system alerts ---
        self._process_system_alerts(stats.get("system_alerts", []))

    def _process_system_alerts(self, alerts):
        """Process TrueNAS system alerts from stats dict."""
        try:
            current_ids = set()
            for alert in alerts:
                alert_id = alert.get("id", "")
                current_ids.add(alert_id)

                if alert_id in self._seen_truenas_alerts:
                    continue

                self._seen_truenas_alerts.add(alert_id)

                severity = alert.get("severity", "info")
                msg = alert.get("message", "Unknown TrueNAS alert")

                show_popup = severity in ("critical", "warning")
                self._add_alert(
                    severity,
                    f"[TrueNAS] {msg}",
                    popup=show_popup, sound=show_popup)

            # Check for dismissed/resolved alerts
            resolved = self._seen_truenas_alerts - current_ids
            for alert_id in resolved:
                self._seen_truenas_alerts.discard(alert_id)
                self._add_alert("resolved", "[TrueNAS] Alert cleared")

        except Exception as e:
            debug(f" truenas alerts error: {e}")

    def _build_settings(self):
        c = tk.Frame(self.set_frame, bg=COLORS["bg"], padx=28, pady=20)
        c.pack(fill=tk.BOTH, expand=True)

        ttk.Label(c, text="Connection Settings",
                  style="SettingsH.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 18))

        fields = [
            ("IP Address / Hostname:", False),
            ("API Key:", True),
        ]
        self.host_var = tk.StringVar()
        self.apikey_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.interval_var = tk.StringVar(value="5")
        self.temp_threshold_var = tk.StringVar(
            value=str(self.config.get("temp_threshold", 82)))

        entry_kw = dict(
            bg=COLORS["input_bg"], fg=COLORS["text"],
            insertbackground=COLORS["text"], font=("Helvetica", self._sf(11)),
            relief="flat", bd=5,
        )

        r = 1
        ttk.Label(c, text="IP Address / Hostname:",
                  style="Settings.TLabel").grid(row=r, column=0,
                                                sticky="w", pady=6)
        tk.Entry(c, textvariable=self.host_var, width=42,
                 **entry_kw).grid(row=r, column=1, sticky="ew",
                                  pady=6, padx=(10, 0))

        r = 2
        ttk.Label(c, text="API Key:",
                  style="Settings.TLabel").grid(row=r, column=0,
                                                sticky="w", pady=6)
        tk.Entry(c, textvariable=self.apikey_var, width=42, show="*",
                 **entry_kw).grid(row=r, column=1, sticky="ew",
                                  pady=6, padx=(10, 0))

        r = 3
        tk.Label(c, text="--- or use credentials ---", bg=COLORS["bg"],
                 fg=COLORS["text_dim"],
                 font=("Helvetica", self._sf(10))).grid(row=r, column=0,
                                              columnspan=2, pady=14)

        r = 4
        ttk.Label(c, text="Username:",
                  style="Settings.TLabel").grid(row=r, column=0,
                                                sticky="w", pady=6)
        tk.Entry(c, textvariable=self.user_var, width=42,
                 **entry_kw).grid(row=r, column=1, sticky="ew",
                                  pady=6, padx=(10, 0))

        r = 5
        ttk.Label(c, text="Password:",
                  style="Settings.TLabel").grid(row=r, column=0,
                                                sticky="w", pady=6)
        tk.Entry(c, textvariable=self.pass_var, width=42, show="*",
                 **entry_kw).grid(row=r, column=1, sticky="ew",
                                  pady=6, padx=(10, 0))

        r = 6
        ttk.Label(c, text="Poll Interval (seconds):",
                  style="Settings.TLabel").grid(row=r, column=0,
                                                sticky="w", pady=6)
        tk.Entry(c, textvariable=self.interval_var, width=8,
                 **entry_kw).grid(row=r, column=1, sticky="w",
                                  pady=6, padx=(10, 0))

        r = 7
        tk.Label(c, text="--- alert thresholds ---", bg=COLORS["bg"],
                 fg=COLORS["text_dim"],
                 font=("Helvetica", self._sf(10))).grid(row=r, column=0,
                                              columnspan=2, pady=14)

        r = 8
        ttk.Label(c, text="CPU Temp Alert (\u00b0C):",
                  style="Settings.TLabel").grid(row=r, column=0,
                                                sticky="w", pady=6)
        temp_values = [str(t) for t in range(40, 97)]
        self.temp_combo = ttk.Combobox(
            c, textvariable=self.temp_threshold_var, values=temp_values,
            width=6, state="readonly", style="Settings.TCombobox",
            font=("Helvetica", self._sf(11)),
        )
        self.temp_combo.grid(row=r, column=1, sticky="w", pady=6, padx=(10, 0))
        self.temp_combo.bind("<<ComboboxSelected>>", self._on_temp_threshold_change)

        r = 9
        tk.Label(c, text="--- broadcast to clients ---", bg=COLORS["bg"],
                 fg=COLORS["text_dim"],
                 font=("Helvetica", self._sf(10))).grid(row=r, column=0,
                                              columnspan=2, pady=14)

        r = 10
        self.broadcast_enabled_var = tk.BooleanVar(
            value=self.config.get("broadcast_enabled", False))
        ttk.Label(c, text="Enable Broadcast:",
                  style="Settings.TLabel").grid(row=r, column=0, sticky="w", pady=6)
        tk.Checkbutton(
            c, variable=self.broadcast_enabled_var,
            bg=COLORS["bg"], fg=COLORS["text"],
            activebackground=COLORS["bg"], activeforeground=COLORS["text"],
            selectcolor=COLORS["input_bg"],
        ).grid(row=r, column=1, sticky="w", pady=6, padx=(10, 0))

        r = 11
        self.broadcast_port_var = tk.StringVar(
            value=str(self.config.get("broadcast_port", BROADCAST_DEFAULT_PORT)))
        ttk.Label(c, text="Broadcast Port:",
                  style="Settings.TLabel").grid(row=r, column=0, sticky="w", pady=6)
        tk.Entry(c, textvariable=self.broadcast_port_var, width=8,
                 **entry_kw).grid(row=r, column=1, sticky="w", pady=6, padx=(10, 0))

        r = 12
        self.broadcast_key_var = tk.StringVar(
            value=self.config.get("broadcast_key", BROADCAST_DEFAULT_KEY))
        ttk.Label(c, text="Shared Key:",
                  style="Settings.TLabel").grid(row=r, column=0, sticky="w", pady=6)
        bkey_row = tk.Frame(c, bg=COLORS["bg"])
        bkey_row.grid(row=r, column=1, sticky="ew", pady=6, padx=(10, 0))
        self._bkey_entry = tk.Entry(
            bkey_row, textvariable=self.broadcast_key_var, width=30, show="*",
            **entry_kw)
        self._bkey_entry.pack(side=tk.LEFT)
        self._bkey_show = False
        def _toggle_bkey():
            self._bkey_show = not self._bkey_show
            self._bkey_entry.config(show="" if self._bkey_show else "*")
        tk.Button(
            bkey_row, text="Show", bg=COLORS["card"], fg=COLORS["text"],
            activebackground=COLORS["card_border"], activeforeground=COLORS["text"],
            font=("Helvetica", self._sf(9)), relief="flat", padx=8, pady=2,
            command=_toggle_bkey,
        ).pack(side=tk.LEFT, padx=(6, 0))

        self.broadcast_status_lbl = tk.Label(
            c, text="", bg=COLORS["bg"], fg=COLORS["text_dim"],
            font=("Helvetica", self._sf(9)))
        self.broadcast_status_lbl.grid(row=13, column=0, columnspan=2,
                                       sticky="w", pady=(2, 0))

        r = 14
        tk.Label(c, text="--- display ---", bg=COLORS["bg"],
                 fg=COLORS["text_dim"],
                 font=("Helvetica", self._sf(10))).grid(row=r, column=0,
                                              columnspan=2, pady=14)

        r = 15
        self.font_size_var = tk.StringVar(
            value=self.config.get("font_size", "Medium"))
        ttk.Label(c, text="Font Size:",
                  style="Settings.TLabel").grid(row=r, column=0,
                                                sticky="w", pady=6)
        self.font_combo = ttk.Combobox(
            c, textvariable=self.font_size_var,
            values=["Small", "Medium", "Large"],
            width=8, state="readonly", style="Settings.TCombobox",
            font=("Helvetica", self._sf(11)),
        )
        self.font_combo.grid(row=r, column=1, sticky="w", pady=6, padx=(10, 0))
        self.font_combo.bind("<<ComboboxSelected>>", self._on_font_size_change)

        c.columnconfigure(1, weight=1)

        # buttons
        bf = tk.Frame(c, bg=COLORS["bg"])
        bf.grid(row=16, column=0, columnspan=2, pady=26, sticky="w")

        self.conn_btn = tk.Button(
            bf, text="Save & Connect", bg="#ffffff",
            fg="#000000", activebackground="#e0e0e0",
            activeforeground="#000000", font=("Helvetica", self._sf(11), "bold"),
            relief="flat", padx=22, pady=8, command=self._on_save,
        )
        self.conn_btn.pack(side=tk.LEFT, padx=(0, 14))

        self.disc_btn = tk.Button(
            bf, text="Disconnect", bg="#ffffff", fg="#000000",
            activebackground="#e0e0e0", activeforeground="#000000",
            font=("Helvetica", self._sf(11)), relief="flat", padx=22, pady=8,
            command=self._disconnect, state=tk.DISABLED,
        )
        self.disc_btn.pack(side=tk.LEFT)

        self.demo_btn = tk.Button(
            bf, text="Demo Mode", bg=COLORS["warning"], fg="#1a1a2e",
            activebackground="#ffb74d", activeforeground="#1a1a2e",
            font=("Helvetica", self._sf(11), "bold"), relief="flat", padx=22, pady=8,
            command=self._toggle_demo,
        )
        self.demo_btn.pack(side=tk.LEFT, padx=(14, 0))

    def _populate_settings(self):
        self.host_var.set(self.config.get("host", ""))
        self.apikey_var.set(self.config.get("api_key", ""))
        self.user_var.set(self.config.get("username", ""))
        self.pass_var.set(self.config.get("password", ""))
        self.interval_var.set(str(self.config.get("interval", 5)))
        self.temp_threshold_var.set(str(self.config.get("temp_threshold", 82)))
        self.font_size_var.set(self.config.get("font_size", "Medium"))
        self.broadcast_enabled_var.set(self.config.get("broadcast_enabled", False))
        self.broadcast_port_var.set(str(self.config.get("broadcast_port", BROADCAST_DEFAULT_PORT)))
        self.broadcast_key_var.set(self.config.get("broadcast_key", BROADCAST_DEFAULT_KEY))
        self._update_broadcast_status()

    def _on_font_size_change(self, event=None):
        """Save the font size and rebuild the UI."""
        size_name = self.font_size_var.get()
        self.config["font_size"] = size_name
        self._save_config()
        self._font_scale = FONT_SCALES.get(size_name, 1.0)

        # Preserve state
        was_polling = self.polling
        was_demo = self.demo_mode
        conn_state = self.disc_btn.cget("state") if hasattr(self, 'disc_btn') else tk.DISABLED

        # Rebuild UI
        self._main_frame.destroy()
        self.pool_cards = {}
        self._pool_count = 0
        self._setup_styles()
        self._build_ui()

        # Restore settings fields
        self._populate_settings()

        # Restore connection state
        if was_demo:
            self.demo_btn.config(text="Stop Demo", bg=COLORS["critical"])
            self.conn_btn.config(state=tk.DISABLED)
            self.status_lbl.config(text="Demo Mode", style="StatusOK.TLabel")
        elif self.client and was_polling:
            self.conn_btn.config(text="Reconnect")
            self.disc_btn.config(state=tk.NORMAL)
            self.status_lbl.config(text="Connected", style="StatusOK.TLabel")

        # Switch to settings tab
        self.notebook.select(2)

    def _on_temp_threshold_change(self, event=None):
        """Save the temperature threshold immediately when changed."""
        try:
            val = int(self.temp_threshold_var.get())
        except ValueError:
            return
        self.config["temp_threshold"] = val
        self._save_config()
        # Reset the alert state so it re-evaluates with the new threshold
        self._temp_alert_active = False

    # --- broadcast server management ---
    def _start_broadcast_server_if_enabled(self):
        if self.broadcast_server:
            self.broadcast_server.stop()
            self.broadcast_server = None
        if self.config.get("broadcast_enabled", False):
            port = self.config.get("broadcast_port", BROADCAST_DEFAULT_PORT)
            key = self.config.get("broadcast_key", BROADCAST_DEFAULT_KEY)
            self.broadcast_server = BroadcastServer(port, key)
            self.broadcast_server.on_security_event = self._on_broadcast_security_event
            self.broadcast_server.on_client_clear_alerts = self._on_client_clear_alerts
            self.broadcast_server.start()
        self._update_broadcast_status()

    def _on_broadcast_security_event(self, level: str, ip: str, message: str):
        """Callback from BroadcastServer for connection/auth events — runs on a worker thread.

        Rules:
        - "Connection from X" (raw TCP) is skipped — too noisy on reconnects.
        - All other events (authenticated, wrong key) are shown at most once
          per IP per level per 5 minutes so a sleeping phone reconnecting
          repeatedly doesn't flood the alert log.
        """
        if level == "info" and not message.startswith("Authenticated"):
            return

        # Per-IP, per-level cooldown (5 minutes)
        now = datetime.now()
        key = f"{ip}:{level}"
        last = self._connect_alert_times.get(key)
        if last and (now - last).total_seconds() < 300:
            return
        self._connect_alert_times[key] = now

        self.root.after(0, lambda: self._add_alert(level, message, popup=False, sound=False))

    def _update_broadcast_status(self):
        if not hasattr(self, "broadcast_status_lbl"):
            return
        if self.broadcast_server:
            port = self.config.get("broadcast_port", BROADCAST_DEFAULT_PORT)
            n = self.broadcast_server.client_count
            self.broadcast_status_lbl.config(
                text=f"Broadcasting on port {port}  |  {n} client{'s' if n != 1 else ''} connected",
                fg=COLORS["good"])
        else:
            self.broadcast_status_lbl.config(
                text="Broadcast disabled", fg=COLORS["text_dim"])

    # --- connection management ---
    def _on_save(self):
        host = self.host_var.get().strip()
        api_key = self.apikey_var.get().strip()
        user = self.user_var.get().strip()
        pw = self.pass_var.get().strip()
        iv = self.interval_var.get().strip()

        if not host:
            messagebox.showerror("Error", "Please enter an IP address or hostname.")
            return
        if not api_key and not (user and pw):
            messagebox.showerror("Error",
                                 "Provide an API key or username & password.")
            return
        try:
            iv_val = max(2, int(iv))
        except ValueError:
            iv_val = 5

        try:
            temp_thresh = max(1, int(self.temp_threshold_var.get().strip()))
        except ValueError:
            temp_thresh = 82

        try:
            bcast_port = max(1024, min(65535, int(self.broadcast_port_var.get().strip())))
        except ValueError:
            bcast_port = BROADCAST_DEFAULT_PORT
        bcast_key = self.broadcast_key_var.get().strip() or BROADCAST_DEFAULT_KEY

        self.config = {
            "host": host, "api_key": api_key,
            "username": user, "password": pw,
            "interval": iv_val,
            "temp_threshold": temp_thresh,
            "font_size": self.font_size_var.get(),
            "broadcast_enabled": self.broadcast_enabled_var.get(),
            "broadcast_port": bcast_port,
            "broadcast_key": bcast_key,
        }
        self._save_config()
        self._start_broadcast_server_if_enabled()
        self._connect()

    def _connect(self):
        self._disconnect()
        c = self.config
        self.client = TrueNASClient(
            host=c["host"], api_key=c.get("api_key", ""),
            username=c.get("username", ""), password=c.get("password", ""),
        )
        self.status_lbl.config(text="Connecting...", style="Status.TLabel")

        def _test():
            try:
                info = self.client.test_connection()
                self.root.after(0, lambda: self._connected(info))
            except Exception as e:
                self.root.after(0, lambda msg=str(e): self._conn_error(msg))

        threading.Thread(target=_test, daemon=True).start()

    def _connected(self, info):
        name = info.get("hostname", "TrueNAS")
        self.status_lbl.config(text=f"Connected to {name}",
                               style="StatusOK.TLabel")
        self.conn_btn.config(text="Reconnect")
        self.disc_btn.config(state=tk.NORMAL)
        self.notebook.select(0)
        self._start_polling()

    def _conn_error(self, err):
        self.status_lbl.config(text="Connection failed",
                               style="StatusErr.TLabel")
        messagebox.showerror("Connection Error",
                             f"Could not connect to TrueNAS:\n\n{err}")

    def _disconnect(self):
        self.polling = False
        if self.poll_thread and self.poll_thread.is_alive():
            self.poll_thread.join(timeout=3)
        self.client = None
        self.status_lbl.config(text="Disconnected", style="Status.TLabel")
        self.conn_btn.config(text="Save & Connect")
        self.disc_btn.config(state=tk.DISABLED)
        self._reset_cards()

    def _reset_cards(self):
        for card in (self.cpu_card, self.mem_card):
            card["value"].config(text="--")
            card["sub"].config(text="")
            if card["bar_var"]:
                card["bar_var"].set(0)
        self.net_history_rx.clear()
        self.net_history_tx.clear()
        self.net_rx_lbl.config(text="\u2193 --")
        self.net_tx_lbl.config(text="\u2191 --")
        self.net_iface_lbl.config(text="")
        self.net_canvas.delete("all")
        self.net_scale_lbl.config(text="")
        self.temp_history.clear()
        self.temp_val_lbl.config(text="--", fg=COLORS["text"])
        self.temp_status_lbl.config(text="")
        self.temp_range_lbl.config(text="")
        self.temp_canvas.delete("all")
        self._temp_alert_active = False
        self._cpu_alert_active = False
        self._mem_alert_active = False
        # Don't clear _seen_truenas_alerts — persistent TrueNAS alerts
        # would otherwise re-appear in the log after every reconnect.
        self.notebook.tab(1, text="  Alerts  ")
        for card in self.pool_cards.values():
            card["frame"].destroy()
        self.pool_cards = {}
        self._pool_count = 0
        # Reset window size back to default
        self.root.geometry(f"{self._base_w}x{self._base_h}")
        self.info_lbl.config(text="Connect to TrueNAS to begin monitoring")
        self.footer.config(text="")

    # --- polling loop ---
    def _start_polling(self):
        self.polling = True
        self.poll_thread = threading.Thread(target=self._poll, daemon=True)
        self.poll_thread.start()

    def _poll(self):
        while self.polling and self.client:
            try:
                stats = self.client.fetch_all_stats()
                self.root.after(0, lambda s=stats: self._refresh(s))
                if self.broadcast_server:
                    self.broadcast_server.send_stats(stats)
                    self.root.after(0, self._update_broadcast_status)
            except Exception as e:
                self.root.after(
                    0, lambda msg=str(e): self.footer.config(
                        text=f"Poll error: {msg}", fg=COLORS["critical"]))
            time.sleep(self.config.get("interval", 5))

    # --- UI refresh ---
    def _refresh(self, s):
        now = datetime.now().strftime("%H:%M:%S")
        self.footer.config(text=f"Last updated: {now}",
                           fg=COLORS["text_dim"])

        # info bar
        host = s.get("hostname", "N/A")
        ver = s.get("version", "N/A")
        up = s.get("uptime", "N/A")
        la = s.get("loadavg", [0, 0, 0])
        la_s = ", ".join(f"{x:.2f}" for x in la) if la else "N/A"
        self.info_lbl.config(
            text=f"{host}  |  {ver}  |  Uptime: {up}  |  Load: {la_s}")

        # CPU
        cpu = s.get("cpu_percent")
        if cpu is not None:
            col = (COLORS["good"] if cpu < 70
                   else COLORS["warning"] if cpu < 90
                   else COLORS["critical"])
            self.cpu_card["value"].config(text=f"{cpu}%", foreground=col)
            self.cpu_card["bar_var"].set(cpu)
            self.cpu_card["sub"].config(text=f"Load avg: {la_s}")
        else:
            self.cpu_card["value"].config(text="N/A",
                                          foreground=COLORS["text_dim"])

        # Memory
        mu = s.get("memory_used")
        mt = s.get("memory_total")
        mp = s.get("memory_percent")
        if mu is not None and mt:
            col = (COLORS["good"] if mp < 70
                   else COLORS["warning"] if mp < 90
                   else COLORS["critical"])
            self.mem_card["value"].config(text=f"{mp}%", foreground=col)
            self.mem_card["bar_var"].set(mp or 0)
            self.mem_card["sub"].config(
                text=f"{format_bytes(mu)} / {format_bytes(mt)}")
        else:
            self.mem_card["value"].config(text="N/A",
                                          foreground=COLORS["text_dim"])
            if mt:
                self.mem_card["sub"].config(
                    text=f"Total: {format_bytes(mt)}")

        # Network
        rx = s.get("net_rx")
        tx = s.get("net_tx")
        iface = s.get("net_iface", "")
        rx_val = float(rx) if rx is not None else 0.0
        tx_val = float(tx) if tx is not None else 0.0
        self.net_history_rx.append(rx_val)
        self.net_history_tx.append(tx_val)
        if len(self.net_history_rx) > self.HISTORY_LEN:
            self.net_history_rx = self.net_history_rx[-self.HISTORY_LEN:]
        if len(self.net_history_tx) > self.HISTORY_LEN:
            self.net_history_tx = self.net_history_tx[-self.HISTORY_LEN:]

        rx_s = format_bytes(rx_val, per_second=True)
        tx_s = format_bytes(tx_val, per_second=True)
        self.net_rx_lbl.config(text=f"\u2193 {rx_s}")
        self.net_tx_lbl.config(text=f"\u2191 {tx_s}")
        self.net_iface_lbl.config(text=iface)
        self._draw_net_graph()

        # Temperature
        temp = s.get("cpu_temp")
        if temp is not None:
            self.temp_history.append(temp)
            if len(self.temp_history) > self.HISTORY_LEN:
                self.temp_history = self.temp_history[-self.HISTORY_LEN:]
            col = (COLORS["good"] if temp < 60
                   else COLORS["warning"] if temp < 80
                   else COLORS["critical"])
            label = ("Normal" if temp < 60
                     else "Warm" if temp < 80
                     else "Hot!")
            self.temp_val_lbl.config(text=f"{temp}\u00b0C", fg=col)
            self.temp_status_lbl.config(text=label, fg=col)
            self._draw_temp_graph()
        else:
            self.temp_val_lbl.config(text="N/A", fg=COLORS["text_dim"])
            self.temp_status_lbl.config(text="")

        # Pool capacity
        pools = s.get("pools", [])
        if pools:
            # Build cards if pool count changed or disk count changed
            rebuild = len(pools) != self._pool_count
            if not rebuild:
                for pool in pools:
                    card = self.pool_cards.get(pool.get("name", ""))
                    if card and len(card.get("disk_rects", [])) != len(pool.get("disks", [])):
                        rebuild = True
                        break
            if rebuild:
                self._build_pool_cards(pools)
            # Update each pool card
            for pool in pools:
                name = pool.get("name", "unknown")
                card = self.pool_cards.get(name)
                if not card:
                    continue
                pct = pool.get("percent", 0)
                used = pool.get("used", 0)
                total = pool.get("total", 0)
                avail = pool.get("available", 0)

                # Color coding
                if pct < 70:
                    col = COLORS["good"]
                    bar_style = "Poolgreen.Horizontal.TProgressbar"
                elif pct < 85:
                    col = COLORS["warning"]
                    bar_style = "Poolyellow.Horizontal.TProgressbar"
                else:
                    col = COLORS["critical"]
                    bar_style = "Poolred.Horizontal.TProgressbar"

                card["value"].config(text=f"{pct}%", foreground=col)
                card["bar_var"].set(pct)
                card["bar"].config(style=bar_style)
                card["sub"].config(
                    text=f"{format_bytes(used)} / {format_bytes(total)}  "
                         f"({format_bytes(avail)} free)")

                # Update disk indicator colors
                disks = pool.get("disks", [])
                for i, rect in enumerate(card.get("disk_rects", [])):
                    if i < len(disks):
                        disk_col = COLORS["critical"] if disks[i]["has_error"] else COLORS["good"]
                        rect._img.put(disk_col, to=(0, 0, 14, 20))

                # Update stored topology for drive map button
                topo = pool.get("topology", {})
                if topo:
                    card["topology"] = topo
                    card["map_btn"].config(
                        command=lambda n=name, t=topo: self._show_drive_map(n, t))

        # Check alert conditions
        self._check_alerts(s)

    # --- demo mode ---
    def _toggle_demo(self):
        if self.demo_mode:
            self._stop_demo()
        else:
            self._start_demo()

    def _start_demo(self):
        self._disconnect()
        self.demo_mode = True
        self.polling = True
        self.demo_btn.config(text="Stop Demo", bg=COLORS["critical"])
        self.status_lbl.config(text="Demo Mode", style="StatusOK.TLabel")
        self.conn_btn.config(state=tk.DISABLED)
        self.notebook.select(0)
        self._demo_cpu = 35.0
        self._demo_mem = 55.0
        self._demo_temp = 42.0
        self._demo_rx = 25_000_000.0
        self._demo_tx = 8_000_000.0
        self.poll_thread = threading.Thread(target=self._demo_poll, daemon=True)
        self.poll_thread.start()

    def _stop_demo(self):
        self.demo_mode = False
        self.polling = False
        if self.poll_thread and self.poll_thread.is_alive():
            self.poll_thread.join(timeout=3)
        self.demo_btn.config(text="Demo Mode", bg=COLORS["warning"])
        self.conn_btn.config(state=tk.NORMAL)
        self.status_lbl.config(text="Disconnected", style="Status.TLabel")
        self._reset_cards()

    def _demo_poll(self):
        while self.polling and self.demo_mode:
            self._demo_cpu = max(1, min(99, self._demo_cpu + random.uniform(-8, 8)))
            self._demo_mem = max(20, min(95, self._demo_mem + random.uniform(-3, 3)))
            self._demo_temp = max(30, min(88, self._demo_temp + random.uniform(-4, 4)))
            self._demo_rx = max(0, self._demo_rx + random.uniform(-5_000_000, 5_000_000))
            self._demo_tx = max(0, self._demo_tx + random.uniform(-2_000_000, 2_000_000))

            mem_total = 34_359_738_368  # 32 GB
            mem_used = mem_total * self._demo_mem / 100

            # Simulated pool data
            demo_pools = [
                {"name": "tank",
                 "total": 8 * 1024**4,        # 8 TB
                 "used": int(5.2 * 1024**4),   # 5.2 TB
                 "available": int(2.8 * 1024**4),
                 "percent": 65.0,
                 "disks": [
                     {"name": "sda", "has_error": False},
                     {"name": "sdb", "has_error": False},
                     {"name": "sdc", "has_error": False},
                     {"name": "sdd", "has_error": False},
                 ],
                 "topology": {
                     "data": [
                         {"type": "MIRROR", "status": "ONLINE", "disks": [
                             {"name": "sda", "status": "ONLINE", "errors": 0},
                             {"name": "sdb", "status": "ONLINE", "errors": 0},
                         ]},
                         {"type": "MIRROR", "status": "ONLINE", "disks": [
                             {"name": "sdc", "status": "ONLINE", "errors": 0},
                             {"name": "sdd", "status": "ONLINE", "errors": 0},
                         ]},
                     ],
                 }},
                {"name": "fast-storage",
                 "total": 2 * 1024**4,         # 2 TB
                 "used": int(1.6 * 1024**4),   # 1.6 TB
                 "available": int(0.4 * 1024**4),
                 "percent": 80.0,
                 "disks": [
                     {"name": "nvme0n1", "has_error": False},
                     {"name": "nvme1n1", "has_error": True},
                 ],
                 "topology": {
                     "data": [
                         {"type": "MIRROR", "status": "ONLINE", "disks": [
                             {"name": "nvme0n1", "status": "ONLINE", "errors": 0},
                             {"name": "nvme1n1", "status": "DEGRADED", "errors": 3},
                         ]},
                     ],
                     "cache": [
                         {"type": "STRIPE", "status": "ONLINE", "disks": [
                             {"name": "nvme2n1", "status": "ONLINE", "errors": 0},
                         ]},
                     ],
                 }},
                {"name": "backup",
                 "total": 16 * 1024**4,        # 16 TB
                 "used": int(14.5 * 1024**4),  # 14.5 TB
                 "available": int(1.5 * 1024**4),
                 "percent": 90.6,
                 "disks": [
                     {"name": "sde", "has_error": False},
                     {"name": "sdf", "has_error": False},
                     {"name": "sdg", "has_error": False},
                     {"name": "sdh", "has_error": False},
                     {"name": "sdi", "has_error": False},
                     {"name": "sdj", "has_error": False},
                 ],
                 "topology": {
                     "data": [
                         {"type": "RAIDZ2", "status": "ONLINE", "disks": [
                             {"name": "sde", "status": "ONLINE", "errors": 0},
                             {"name": "sdf", "status": "ONLINE", "errors": 0},
                             {"name": "sdg", "status": "ONLINE", "errors": 0},
                             {"name": "sdh", "status": "ONLINE", "errors": 0},
                             {"name": "sdi", "status": "ONLINE", "errors": 0},
                             {"name": "sdj", "status": "ONLINE", "errors": 0},
                         ]},
                     ],
                     "spare": [
                         {"type": "DISK", "status": "ONLINE", "disks": [
                             {"name": "sdk", "status": "ONLINE", "errors": 0},
                         ]},
                     ],
                 }},
            ]

            stats = {
                "cpu_percent": round(self._demo_cpu, 1),
                "memory_used": mem_used,
                "memory_total": mem_total,
                "memory_percent": round(self._demo_mem, 1),
                "cpu_temp": round(self._demo_temp, 1),
                "net_rx": self._demo_rx,
                "net_tx": self._demo_tx,
                "net_iface": "eno1",
                "hostname": "truenas-demo",
                "version": "TrueNAS-SCALE-24.10",
                "uptime": "14 days, 7:32:15",
                "loadavg": [
                    round(self._demo_cpu / 25, 2),
                    round(self._demo_cpu / 30, 2),
                    round(self._demo_cpu / 40, 2),
                ],
                "pools": demo_pools,
            }
            self.root.after(0, lambda s=stats: self._refresh(s))
            if self.broadcast_server:
                self.broadcast_server.send_stats(stats)
                self.root.after(0, self._update_broadcast_status)
            time.sleep(2)

    def _on_close(self):
        self.config["window_geometry"] = self.root.geometry()
        self._save_config()
        self.polling = False
        self.demo_mode = False
        if self.broadcast_server:
            self.broadcast_server.stop()
            self.broadcast_server = None
        self.root.destroy()


def main():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(DEBUG_LOG, "w") as f:
        f.write("")
    import sys
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    TrueMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
