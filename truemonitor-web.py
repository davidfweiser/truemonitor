#!/usr/bin/env python3
"""TrueMonitor Web - Real-time TrueNAS Monitoring Dashboard (Web Interface)"""

import json
import threading
import time
import os
import sys
import random
import base64
import hashlib
import getpass
import socket
import struct
import hmac as hmac_mod
import ssl
import queue
import signal
import ipaddress
import webbrowser
from datetime import datetime, timedelta, timezone
from collections import deque

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

try:
    import websocket as _websocket
except ImportError:
    print("ERROR: 'websocket-client' package is required. Install it with:")
    print("  pip install websocket-client")
    raise SystemExit(1)

try:
    from flask import (Flask, Response, request, jsonify, stream_with_context,
                       session, redirect, url_for)
except ImportError:
    print("ERROR: 'flask' package is required. Install it with:")
    print("  pip install flask")
    raise SystemExit(1)

APP_VERSION = "0.8.1"
WEB_DEFAULT_HOST = "0.0.0.0"
WEB_DEFAULT_PORT = 8088  # HTTPS is always this + 1 (8089)

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "truemonitor")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
DEBUG_LOG = os.path.join(CONFIG_DIR, "debug.log")
ALERT_LOG = os.path.join(CONFIG_DIR, "alerts.log")
SSL_CERT = os.path.join(CONFIG_DIR, "truemonitor-web.crt")
SSL_KEY = os.path.join(CONFIG_DIR, "truemonitor-web.key")


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


BROADCAST_DEFAULT_PORT = 7337
BROADCAST_DEFAULT_KEY = "truemonitor"


def _derive_broadcast_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"truemonitor_broadcast_v1",
        iterations=100_000,
    )
    key_bytes = kdf.derive(passphrase.encode())
    return base64.urlsafe_b64encode(key_bytes)


def _derive_broadcast_key_raw(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"truemonitor_broadcast_v1",
        iterations=100_000,
    )
    return kdf.derive(passphrase.encode())


_AUTH_MAGIC = b"TRUEMON_AUTH\n"
_BACKOFF_DELAYS = [5, 30, 300]


# ---------------------------------------------------------------------------
# Broadcast server (identical to truemonitor.py)
# ---------------------------------------------------------------------------
class BroadcastServer:
    def __init__(self, port: int, passphrase: str):
        self.port = port
        self.passphrase = passphrase
        self._clients = []
        self._lock = threading.Lock()
        self._running = False
        self._server_sock = None
        self._thread = None
        self._auth_failures: dict = {}
        self._sec_lock = threading.Lock()
        self.on_security_event = None
        self._clear_alerts_at: float = 0.0
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

    def _authenticate_client(self, conn: socket.socket, ip: str):
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
            self._emit("info", ip, f"Authenticated from {ip}")
            conn.settimeout(10.0)
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
            threading.Thread(
                target=self._read_client_commands,
                args=(conn, ip),
                daemon=True,
            ).start()
        else:
            self._record_failure(ip, conn)

    def _record_failure(self, ip: str, conn: socket.socket):
        conn.close()
        with self._sec_lock:
            count, _ = self._auth_failures.get(ip, (0, None))
            count += 1
            self._auth_failures[ip] = (count, datetime.now())
        delay = _BACKOFF_DELAYS[min(count - 1, len(_BACKOFF_DELAYS) - 1)]
        self._emit("warning", ip, f"Wrong shared key from {ip} — retry in {delay}s")

    def _backoff_remaining(self, ip: str) -> float:
        with self._sec_lock:
            entry = self._auth_failures.get(ip)
            if not entry:
                return 0
            count, last = entry
            delay = _BACKOFF_DELAYS[min(count - 1, len(_BACKOFF_DELAYS) - 1)]
            elapsed = (datetime.now() - last).total_seconds()
            remaining = delay - elapsed
            if remaining <= 0:
                del self._auth_failures[ip]
                return 0
            return remaining

    def _emit(self, level: str, ip: str, message: str):
        debug(f"BroadcastServer [{level}] {message}")
        if self.on_security_event:
            self.on_security_event(level, ip, message)

    @staticmethod
    def _recvn_from(conn, n: int):
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
        while self._running:
            try:
                header = self._recvn_from(conn, 4)
                if header is None:
                    break
                length = struct.unpack(">I", header)[0]
                if length == 0 or length > 65_536:
                    break
                data = self._recvn_from(conn, length)
                if data is None:
                    break
                try:
                    cmd = json.loads(data.decode())
                except Exception:
                    break
                if cmd.get("cmd") == "clear_alerts":
                    self.request_clear_alerts()
                    if self.on_client_clear_alerts:
                        try:
                            self.on_client_clear_alerts()
                        except Exception:
                            pass
            except socket.timeout:
                continue
            except Exception:
                break

    def request_clear_alerts(self):
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
# TrueNAS WebSocket JSON-RPC 2.0 client (identical to truemonitor.py)
# ---------------------------------------------------------------------------
class TrueNASClient:
    def __init__(self, host, api_key="", username="", password=""):
        h = host.rstrip("/")
        for prefix in ("https://", "http://"):
            if h.startswith(prefix):
                h = h[len(prefix):]
        self.host = h
        self.api_key = api_key
        self.username = username
        self.password = password
        self._ws = None
        self._id = 0
        self._working_report_format = None
        self._working_iface = None

    def _connect(self):
        ws_url = f"wss://{self.host}/api/current"
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
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
            raw = ws.recv()
            resp = json.loads(raw)
            if resp.get("id") != msg_id:
                continue
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
                raise
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
        now = datetime.now(timezone.utc)
        start = now - timedelta(seconds=120)

        def _attempts():
            query_iso = {
                "start": start.strftime("%Y-%m-%dT%H:%M:%S"),
                "end": now.strftime("%Y-%m-%dT%H:%M:%S"),
                "aggregate": True,
            }
            return [
                ("reporting.get_data", [graphs, query_iso]),
                ("reporting.netdata_get_data", [graphs, query_iso]),
                ("reporting.get_data", [graphs, {"unit": "HOUR", "page": 1, "aggregate": True}]),
                ("reporting.get_data", [graphs]),
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
        try:
            info = self.get_system_info()
            stats["hostname"] = info.get("hostname", "N/A")
            stats["version"] = info.get("version", "N/A")
            stats["uptime"] = info.get("uptime", "N/A")
            stats["loadavg"] = info.get("loadavg", [0, 0, 0])
            stats["memory_total"] = info.get("physmem", 0)
        except Exception as e:
            debug(f" system/info error: {e}")

        try:
            graphs = [{"name": "cpu"}, {"name": "memory"}, {"name": "cputemp"}]
            report = self.get_reporting_data(graphs)
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
                interfaces = self.get_interfaces()
                iface_names = [i.get("name", "") for i in interfaces
                               if isinstance(i, dict) and i.get("name", "")
                               not in ("lo", "")]
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
                    continue
        except Exception as e:
            debug(f" network error: {e}")

        stats["pools"] = []
        try:
            pools = self.get_pools()
            for p in pools:
                if not isinstance(p, dict):
                    continue
                topology = p.get("topology", {})
                total = p.get("size")
                allocated = p.get("allocated")
                free = p.get("free")
                disks = []
                for topo_key in ("data", "cache", "log", "spare"):
                    vdevs = topology.get(topo_key, [])
                    if not isinstance(vdevs, list):
                        continue
                    for vdev in vdevs:
                        if not isinstance(vdev, dict):
                            continue
                        children = vdev.get("children", [])
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
                            disks.append({"name": disk_name, "has_error": has_error})
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
                            v_stats = vdev.get("stats", {})
                            errs = ((v_stats.get("read_errors", 0) or 0)
                                    + (v_stats.get("write_errors", 0) or 0)
                                    + (v_stats.get("checksum_errors", 0) or 0))
                            child_list.append({
                                "name": vdev.get("disk") or vdev.get("name", "?"),
                                "status": vstatus,
                                "errors": errs,
                            })
                        vdev_list.append({"type": vtype, "status": vstatus, "disks": child_list})
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

        stats["system_alerts"] = []
        try:
            alerts = self.get_alerts()
            if isinstance(alerts, list):
                for alert in alerts:
                    if not isinstance(alert, dict):
                        continue
                    if alert.get("dismissed", False):
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
# SSL certificate generation
# ---------------------------------------------------------------------------
def _ensure_ssl_cert():
    """Generate a self-signed certificate for HTTPS if one doesn't exist."""
    if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        try:
            with open(SSL_CERT, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            # Use it if valid for at least 30 more days
            expiry = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else \
                cert.not_valid_after.replace(tzinfo=timezone.utc)
            if expiry > datetime.now(timezone.utc) + timedelta(days=30):
                return SSL_CERT, SSL_KEY
        except Exception:
            pass

    os.makedirs(CONFIG_DIR, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "truemonitor")])
    san_list = [x509.DNSName("localhost")]
    try:
        san_list.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))
    except Exception:
        pass
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(SSL_CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(SSL_KEY, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    return SSL_CERT, SSL_KEY


# ---------------------------------------------------------------------------
# Login page template
# ---------------------------------------------------------------------------
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TrueMonitor &mdash; Sign In</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #1a1a2e; color: #e0e0e0; font-family: Helvetica, Arial, sans-serif;
       display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.box { background: #16213e; border: 1px solid #0f3460; border-radius: 6px;
       padding: 36px 40px; width: 320px; }
h1 { color: #4fc3f7; font-size: 22px; font-weight: bold; margin-bottom: 4px; }
.ver { color: #888899; font-size: 11px; margin-bottom: 28px; }
label { display: block; font-size: 13px; margin-bottom: 6px; }
input { width: 100%; background: #0f3460; color: #e0e0e0; border: none; border-radius: 3px;
        padding: 9px 12px; font-size: 13px; font-family: inherit; margin-bottom: 16px; }
input:focus { outline: 1px solid #4fc3f7; }
button { width: 100%; background: #fff; color: #000; border: none; border-radius: 3px;
         padding: 10px; font-size: 14px; font-weight: bold; cursor: pointer; font-family: inherit; }
button:hover { background: #e0e0e0; }
.err { color: #ef5350; font-size: 12px; margin-bottom: 14px; min-height: 18px; line-height: 1.4; }
button:disabled { opacity: 0.4; cursor: default; }
</style>
</head>
<body>
<div class="box">
  <h1>TrueMonitor</h1>
  <div class="ver">v{version}</div>
  <form method="post" action="/login">
    <label for="u">Username</label>
    <input id="u" name="username" type="text" autocomplete="username" autofocus {disabled}>
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password" {disabled}>
    <div class="err">{error}</div>
    <button type="submit" {disabled}>Sign In</button>
  </form>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Embedded HTML/CSS/JS template
# ---------------------------------------------------------------------------
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TrueMonitor</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;500;600;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

:root {
  --cyan: #00f0ff;
  --magenta: #ff00aa;
  --lime: #aaff00;
  --orange: #ff6600;
  --purple: #aa44ff;
  --blue: #3366ff;
  --pink: #ff44aa;
  --gold: #ffcc00;
  --good: #66bb6a;
  --warning: #ffa726;
  --critical: #ef5350;
  --bg-deep: #06080f;
  --bg-card: rgba(10, 18, 40, 0.65);
  --glass-border: rgba(255, 255, 255, 0.08);
  --text: #e8eaf6;
  --text-dim: rgba(200, 210, 240, 0.5);
  --input-bg: rgba(15, 25, 60, 0.8);
  --card-border: rgba(0, 240, 255, 0.1);
}

html, body {
  height: 100%;
  overflow: hidden;
  background: var(--bg-deep);
  font-family: 'Rajdhani', sans-serif;
  color: var(--text);
  font-size: 14px;
}

a { color: var(--cyan); }

/* === BACKGROUND LAYERS === */
.bg-layer {
  position: fixed; inset: 0; z-index: 0; pointer-events: none;
}

.bg-gradient {
  background:
    radial-gradient(ellipse 80% 60% at 20% 80%, rgba(0,240,255,0.07) 0%, transparent 60%),
    radial-gradient(ellipse 60% 50% at 80% 20%, rgba(255,0,170,0.06) 0%, transparent 60%),
    radial-gradient(ellipse 50% 40% at 50% 50%, rgba(170,68,255,0.04) 0%, transparent 50%);
}

.grid-floor {
  background-image:
    linear-gradient(rgba(0,240,255,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,240,255,0.03) 1px, transparent 1px);
  background-size: 60px 60px;
}

/* === FLOATING 3D SHAPES === */
.float-element {
  position: fixed;
  z-index: 2;
  pointer-events: none;
  animation: floatElement linear infinite;
  opacity: 0.06;
  will-change: transform;
}

@keyframes floatElement {
  0% { transform: translate(0, 0) rotate(0deg); }
  25% { transform: translate(var(--fx), var(--fy)) rotate(90deg); }
  50% { transform: translate(0, var(--fy2)) rotate(180deg); }
  75% { transform: translate(var(--fx2), 0) rotate(270deg); }
  100% { transform: translate(0, 0) rotate(360deg); }
}

.hex-shape {
  width: 80px; height: 92px;
  clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
}

.diamond-shape {
  width: 60px; height: 60px;
  clip-path: polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%);
}

.tri-shape {
  width: 70px; height: 60px;
  clip-path: polygon(50% 0%, 100% 100%, 0% 100%);
}

/* === SCANLINES === */
.scanlines {
  position: fixed; inset: 0; z-index: 100; pointer-events: none;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
}

.scan-beam {
  position: fixed; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent, rgba(0,240,255,0.08), transparent);
  z-index: 101; pointer-events: none;
  animation: scanBeam 6s linear infinite;
  will-change: transform;
}

@keyframes scanBeam {
  0% { transform: translateY(-2px); }
  100% { transform: translateY(100vh); }
}

/* === HEADER === */
#header {
  position: relative; z-index: 10;
  display: flex; align-items: center; padding: 12px 20px;
  border-bottom: 1px solid var(--card-border);
  background: rgba(6, 8, 15, 0.95);
  animation: slideInDown 0.6s cubic-bezier(0.16, 1, 0.3, 1) both;
}

@keyframes slideInDown {
  from { transform: translateY(-40px); opacity: 0; }
}

.logo {
  font-family: 'Orbitron', sans-serif;
  font-weight: 900;
  font-size: 22px;
  letter-spacing: 3px;
  background: linear-gradient(135deg, var(--cyan), var(--magenta), var(--lime));
  background-size: 300% 300%;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: gradientShift 4s ease infinite;
  filter: drop-shadow(0 0 15px rgba(0,240,255,0.3));
}

@keyframes gradientShift {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

.header-version {
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-dim);
  margin-left: 10px;
  margin-top: 4px;
}

#status-badge {
  margin-left: auto;
  padding: 4px 14px;
  border-radius: 20px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  letter-spacing: 1px;
  border: 1px solid var(--glass-border);
  background: rgba(10, 18, 40, 0.6);
  transition: all 0.3s ease;
}

#status-badge.ok { color: var(--lime); border-color: rgba(170,255,0,0.3); box-shadow: 0 0 15px rgba(170,255,0,0.1); }
#status-badge.err { color: var(--critical); border-color: rgba(239,83,80,0.3); }
#status-badge.connecting { color: var(--warning); border-color: rgba(255,167,38,0.3); }
#status-badge.demo { color: var(--gold); border-color: rgba(255,204,0,0.3); }

.live-dot {
  width: 8px; height: 8px;
  background: var(--lime);
  border-radius: 50%;
  margin-right: 12px;
  box-shadow: 0 0 10px var(--lime);
  animation: pulse 1.5s ease-in-out infinite;
  display: none;
}

.live-dot.on { display: block; }

@keyframes pulse {
  0%, 100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.4); opacity: 0.6; }
}

.header-logout {
  margin-left: 14px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--text-dim);
  text-decoration: none;
  opacity: 0.6;
  transition: opacity 0.2s;
}

.header-logout:hover { opacity: 1; color: var(--cyan); }

/* === TABS === */
#tab-bar {
  position: relative; z-index: 10;
  display: flex;
  background: rgba(8, 14, 32, 0.95);
  border-bottom: 1px solid var(--card-border);
}

.tab-btn {
  padding: 10px 28px;
  cursor: pointer;
  border: none;
  background: none;
  color: var(--text-dim);
  font-family: 'Orbitron', sans-serif;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 2px;
  text-transform: uppercase;
  transition: all 0.2s;
  position: relative;
}

.tab-btn:hover { color: var(--text); background: rgba(0,240,255,0.03); }

.tab-btn.active {
  color: var(--cyan);
}

.tab-btn.active::after {
  content: '';
  position: absolute;
  bottom: 0; left: 20%; right: 20%;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--cyan), transparent);
  box-shadow: 0 0 10px var(--cyan);
}

.tab-btn .badge {
  display: inline-block;
  background: var(--magenta);
  color: #fff;
  border-radius: 10px;
  padding: 1px 6px;
  font-size: 9px;
  margin-left: 6px;
  font-family: 'Share Tech Mono', monospace;
  box-shadow: 0 0 8px rgba(255,0,170,0.4);
}

/* === TAB PANELS === */
.tab-panel { display: none; }
.tab-panel.active { display: block; }

/* === MONITOR TAB === */
#tab-monitor {
  position: relative; z-index: 10;
  height: calc(100vh - 90px);
  overflow-y: auto;
  overflow-x: hidden;
  scrollbar-width: thin;
  scrollbar-color: rgba(0,240,255,0.2) transparent;
}

#tab-monitor::-webkit-scrollbar { width: 6px; }
#tab-monitor::-webkit-scrollbar-track { background: transparent; }
#tab-monitor::-webkit-scrollbar-thumb { background: rgba(0,240,255,0.2); border-radius: 3px; }

/* Info bar */
#info-bar {
  margin: 12px 16px 8px;
  padding: 10px 16px;
  background: rgba(10, 18, 40, 0.9);
  border: 1px solid var(--card-border);
  border-radius: 10px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  color: var(--text-dim);
  animation: cardEnter 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.1s both;
}

@keyframes cardEnter {
  from { transform: translateY(20px) scale(0.98); opacity: 0; }
}

/* Cards grid */
.cards-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
  padding: 8px 16px;
  perspective: 1200px;
}

.card {
  background: rgba(10, 18, 40, 0.85);
  border: 1px solid var(--glass-border);
  border-radius: 14px;
  padding: 18px 20px;
  position: relative;
  overflow: hidden;
  transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.4s ease;
  transform-style: preserve-3d;
}

.card::before {
  content: '';
  position: absolute; inset: 0;
  border-radius: 14px;
  padding: 1px;
  background: linear-gradient(135deg, rgba(255,255,255,0.08), transparent 40%, transparent 60%, rgba(255,255,255,0.04));
  -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  pointer-events: none;
}

.card:hover {
  box-shadow: 0 15px 40px rgba(0,0,0,0.3), 0 0 30px rgba(0,240,255,0.06);
}

.card-cpu { animation: cardEnter 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.15s both; }
.card-mem { animation: cardEnter 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.2s both; }
.card-net { animation: cardEnter 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.25s both; }
.card-temp { animation: cardEnter 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.3s both; }

.card-title {
  font-family: 'Orbitron', sans-serif;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 3px;
  text-transform: uppercase;
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.card-title .icon {
  width: 20px; height: 20px;
  border-radius: 6px;
  display: flex; align-items: center; justify-content: center;
  font-size: 10px;
}

.card-cpu .card-title { color: var(--cyan); }
.card-cpu .card-title .icon { background: rgba(0,240,255,0.15); color: var(--cyan); }
.card-mem .card-title { color: var(--magenta); }
.card-mem .card-title .icon { background: rgba(255,0,170,0.15); color: var(--magenta); }
.card-net .card-title { color: var(--lime); }
.card-net .card-title .icon { background: rgba(170,255,0,0.15); color: var(--lime); }
.card-temp .card-title { color: var(--orange); }
.card-temp .card-title .icon { background: rgba(255,102,0,0.15); color: var(--orange); }

.card-value {
  font-family: 'Orbitron', sans-serif;
  font-size: 32px;
  font-weight: 900;
  color: var(--text);
  margin-bottom: 4px;
  text-shadow: 0 0 20px rgba(0,240,255,0.2);
}

.card-sub {
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--text-dim);
  margin-bottom: 10px;
}

.progress-track {
  background: rgba(0,240,255,0.06);
  border-radius: 6px;
  height: 10px;
  overflow: hidden;
  margin-top: 8px;
}

.progress-fill {
  height: 100%;
  border-radius: 6px;
  transition: width 0.6s cubic-bezier(0.16, 1, 0.3, 1), background 0.4s;
  background: linear-gradient(90deg, var(--cyan), var(--blue));
  width: 0%;
  position: relative;
  box-shadow: 0 0 12px rgba(0,240,255,0.3);
}

.progress-fill::after {
  content: '';
  position: absolute;
  right: 0; top: 0; bottom: 0;
  width: 30px;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15));
  animation: barShine 2s ease-in-out infinite;
}

@keyframes barShine {
  0%, 100% { opacity: 0; }
  50% { opacity: 1; }
}

/* Graph card header */
.graph-header { display: flex; align-items: center; margin-bottom: 8px; }
.graph-header .card-title { margin-bottom: 0; flex: 1; }
.legend { display: flex; gap: 10px; font-family: 'Share Tech Mono', monospace; font-size: 10px; color: var(--text-dim); }
.legend-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
              margin-right: 3px; vertical-align: middle; }

/* Speed row */
.speed-row { display: flex; align-items: center; gap: 16px; margin-bottom: 8px; }
.speed-rx { font-family: 'Orbitron', sans-serif; font-size: 14px; font-weight: 700; color: var(--lime); }
.speed-tx { font-family: 'Orbitron', sans-serif; font-size: 14px; font-weight: 700; color: var(--cyan); }
.iface-lbl { font-family: 'Share Tech Mono', monospace; font-size: 10px; color: var(--text-dim); margin-left: auto; }

/* Canvases */
.graph-canvas { width: 100%; height: 100px; background: rgba(0,240,255,0.02);
                border-radius: 8px; display: block; }
.scale-lbl { text-align: right; font-family: 'Share Tech Mono', monospace;
             font-size: 9px; color: var(--text-dim); margin-top: 4px; }

/* Temp card */
.temp-row { display: flex; align-items: baseline; gap: 12px; margin-bottom: 8px; }
.temp-val { font-family: 'Orbitron', sans-serif; font-size: 32px; font-weight: 900; }
.temp-status { font-family: 'Share Tech Mono', monospace; font-size: 12px; }
.temp-range { font-family: 'Share Tech Mono', monospace; font-size: 10px; color: var(--text-dim); margin-left: auto; }

/* === POOL CARDS === */
#pool-section { padding: 6px 16px 16px; }

.pool-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}

.pool-card {
  background: rgba(10, 18, 40, 0.85);
  border: 1px solid rgba(170,68,255,0.12);
  border-radius: 14px;
  padding: 16px 18px;
  position: relative;
  overflow: hidden;
  transition: all 0.3s ease;
  animation: cardEnter 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.35s both;
}

.pool-card::before {
  content: '';
  position: absolute;
  top: -50%; left: -50%;
  width: 200%; height: 200%;
  background: radial-gradient(circle, rgba(170,68,255,0.04) 0%, transparent 60%);
  animation: poolGlow 6s ease-in-out infinite;
  pointer-events: none;
}

@keyframes poolGlow {
  0%, 100% { transform: translate(0, 0); }
  33% { transform: translate(10%, -10%); }
  66% { transform: translate(-10%, 10%); }
}

.pool-card:hover {
  border-color: rgba(170,68,255,0.25);
  box-shadow: 0 0 25px rgba(170,68,255,0.08);
}

.pool-title-row { display: flex; align-items: center; margin-bottom: 10px; }

.pool-name {
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 2px;
  color: var(--purple);
  flex: 1;
}

.map-btn {
  background: rgba(170,68,255,0.15);
  color: var(--purple);
  border: 1px solid rgba(170,68,255,0.2);
  border-radius: 6px;
  padding: 4px 12px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  cursor: pointer;
  transition: all 0.2s;
  letter-spacing: 1px;
}

.map-btn:hover {
  background: rgba(170,68,255,0.25);
  border-color: rgba(170,68,255,0.4);
  box-shadow: 0 0 15px rgba(170,68,255,0.15);
}

.pool-card .card-value {
  font-size: 24px;
}

.pool-card .card-sub {
  margin-bottom: 6px;
}

.pool-card .progress-track {
  background: rgba(170,68,255,0.06);
}

.pool-card .progress-fill {
  background: linear-gradient(90deg, var(--purple), var(--magenta));
  box-shadow: 0 0 12px rgba(170,68,255,0.3);
}

.disk-row { display: flex; align-items: center; gap: 4px; margin-top: 10px; flex-wrap: wrap; }
.disk-lbl { font-family: 'Share Tech Mono', monospace; font-size: 10px; color: var(--text-dim); margin-right: 4px; }
.disk-ind {
  width: 10px; height: 16px; border-radius: 3px; display: inline-block;
  cursor: default; position: relative; margin: 0 2px;
  animation: driveGlow 2s ease-in-out infinite;
}

.disk-ind:hover::after {
  content: attr(title); position: absolute; bottom: 22px; left: 50%;
  transform: translateX(-50%); background: rgba(10,18,40,0.95); color: var(--text);
  padding: 3px 8px; border-radius: 4px; font-family: 'Share Tech Mono', monospace;
  font-size: 10px; white-space: nowrap; z-index: 100; pointer-events: none;
  border: 1px solid var(--glass-border);
}

@keyframes driveGlow {
  0%, 100% { box-shadow: 0 0 3px currentColor; }
  50% { box-shadow: 0 0 8px currentColor; }
}

/* === ALERTS TAB === */
#tab-alerts {
  position: relative; z-index: 10;
  height: calc(100vh - 90px);
}

#alerts-header {
  display: flex; align-items: center; padding: 14px 20px; gap: 14px;
}

#alerts-header h2 {
  font-family: 'Orbitron', sans-serif;
  font-size: 14px;
  font-weight: 700;
  letter-spacing: 2px;
  color: var(--pink);
}

#alert-count-lbl {
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  color: var(--text-dim);
}

#clear-btn {
  margin-left: auto;
  background: rgba(255,68,170,0.1);
  color: var(--pink);
  border: 1px solid rgba(255,68,170,0.2);
  border-radius: 6px;
  padding: 5px 16px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 11px;
  cursor: pointer;
  letter-spacing: 1px;
  transition: all 0.2s;
}

#clear-btn:hover {
  background: rgba(255,68,170,0.2);
  border-color: rgba(255,68,170,0.4);
}

#alert-log {
  background: rgba(10, 18, 40, 0.9);
  border: 1px solid var(--glass-border);
  border-radius: 12px;
  margin: 0 16px 16px;
  padding: 12px;
  height: calc(100vh - 200px);
  overflow-y: auto;
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  line-height: 1.7;
  scrollbar-width: thin;
  scrollbar-color: rgba(255,68,170,0.2) transparent;
}

.alert-entry { padding: 3px 0; border-bottom: 1px solid rgba(255,255,255,0.03); }
.alert-ts { color: var(--text-dim); }
.alert-critical { color: var(--critical); text-shadow: 0 0 8px rgba(239,83,80,0.3); }
.alert-warning { color: var(--warning); }
.alert-info { color: var(--cyan); }
.alert-resolved { color: var(--lime); }

/* === SETTINGS TAB === */
#tab-settings {
  position: relative; z-index: 10;
  height: calc(100vh - 90px);
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: rgba(0,240,255,0.2) transparent;
}

#settings-panel {
  padding: 24px 32px;
  max-width: 650px;
}

.settings-section {
  font-family: 'Orbitron', sans-serif;
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 2px;
  color: var(--cyan);
  margin: 0 0 18px;
}

.settings-divider {
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-dim);
  margin: 20px 0 16px;
  text-align: center;
  border-top: 1px solid var(--card-border);
  padding-top: 12px;
  letter-spacing: 2px;
}

.settings-row {
  display: grid;
  grid-template-columns: 200px 1fr;
  gap: 12px;
  align-items: center;
  margin-bottom: 12px;
}

.settings-label {
  font-family: 'Rajdhani', sans-serif;
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
}

.settings-input {
  background: var(--input-bg);
  color: var(--text);
  border: 1px solid var(--glass-border);
  border-radius: 8px;
  padding: 8px 12px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  width: 100%;
  transition: all 0.2s;
}

.settings-input:focus {
  outline: none;
  border-color: rgba(0,240,255,0.3);
  box-shadow: 0 0 15px rgba(0,240,255,0.08);
}

.settings-select {
  background: var(--input-bg);
  color: var(--text);
  border: 1px solid var(--glass-border);
  border-radius: 8px;
  padding: 8px 12px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 12px;
  width: 130px;
}

.settings-note {
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-dim);
  margin-top: 2px;
}

#broadcast-status {
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-dim);
  margin: 4px 0 10px 200px;
}

.btn-row { display: flex; gap: 14px; margin-top: 28px; }

.btn-primary {
  background: linear-gradient(135deg, var(--cyan), var(--blue));
  color: #fff;
  border: none;
  border-radius: 8px;
  padding: 10px 24px;
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 1px;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: 0 0 20px rgba(0,240,255,0.2);
}

.btn-primary:hover { box-shadow: 0 0 30px rgba(0,240,255,0.4); transform: translateY(-1px); }
.btn-primary:disabled { opacity: 0.3; cursor: default; transform: none; box-shadow: none; }

.btn-secondary {
  background: rgba(255,255,255,0.08);
  color: var(--text);
  border: 1px solid var(--glass-border);
  border-radius: 8px;
  padding: 10px 24px;
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 1px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover { background: rgba(255,255,255,0.12); }
.btn-secondary:disabled { opacity: 0.3; cursor: default; }

.btn-demo {
  background: linear-gradient(135deg, var(--orange), var(--gold));
  color: #000;
  border: none;
  border-radius: 8px;
  padding: 10px 24px;
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 1px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-demo:hover { box-shadow: 0 0 20px rgba(255,102,0,0.3); }

.key-row { display: flex; gap: 8px; align-items: center; }

.key-show-btn {
  background: rgba(0,240,255,0.08);
  color: var(--cyan);
  border: 1px solid rgba(0,240,255,0.15);
  border-radius: 6px;
  padding: 7px 12px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  cursor: pointer;
  white-space: nowrap;
  transition: all 0.2s;
}

.key-show-btn:hover { background: rgba(0,240,255,0.15); }

/* === FOOTER === */
#footer {
  position: fixed; bottom: 0; left: 0; right: 0;
  z-index: 10;
  padding: 6px 20px;
  font-family: 'Share Tech Mono', monospace;
  font-size: 10px;
  color: var(--text-dim);
  background: rgba(6,8,15,0.95);
  border-top: 1px solid var(--card-border);
}

/* === DRIVE MAP MODAL === */
#modal-overlay {
  display: none; position: fixed; inset: 0;
  background: rgba(6,8,15,0.92);
  z-index: 1000;
  justify-content: center;
  align-items: flex-start;
  padding-top: 60px;
}

#modal-overlay.open { display: flex; }

#modal-box {
  background: rgba(10, 18, 40, 0.95);
  border: 1px solid rgba(0,240,255,0.15);
  border-radius: 16px;
  width: min(700px, 95vw);
  max-height: 80vh;
  overflow-y: auto;
  padding: 24px;
  box-shadow: 0 30px 80px rgba(0,0,0,0.5), 0 0 40px rgba(0,240,255,0.05);
  scrollbar-width: thin;
  scrollbar-color: rgba(170,68,255,0.3) transparent;
}

#modal-title {
  font-family: 'Orbitron', sans-serif;
  font-size: 15px;
  font-weight: 700;
  letter-spacing: 2px;
  color: var(--purple);
  margin-bottom: 18px;
}

.vdev-group-label {
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 2px;
  color: var(--cyan);
  margin: 14px 0 8px;
}

.vdev-box {
  background: rgba(170,68,255,0.04);
  border: 1px solid rgba(170,68,255,0.1);
  border-radius: 10px;
  padding: 12px 14px;
  margin-bottom: 8px;
}

.vdev-hdr { display: flex; align-items: center; margin-bottom: 10px; }
.vdev-type { font-family: 'Share Tech Mono', monospace; font-size: 12px; font-weight: bold; color: var(--cyan); flex: 1; }
.vdev-status { font-family: 'Share Tech Mono', monospace; font-size: 11px; }
.disk-cards { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.disk-card { border-radius: 6px; padding: 6px 12px; text-align: center; min-width: 70px; }
.disk-card-name { font-family: 'Share Tech Mono', monospace; font-size: 11px; font-weight: bold; }
.disk-card-status { font-family: 'Share Tech Mono', monospace; font-size: 10px; margin-top: 2px; }
.disk-connector { font-size: 14px; color: var(--text-dim); }

#modal-close {
  background: rgba(170,68,255,0.15);
  color: var(--purple);
  border: 1px solid rgba(170,68,255,0.2);
  border-radius: 8px;
  padding: 9px 22px;
  font-family: 'Orbitron', sans-serif;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 1px;
  cursor: pointer;
  margin-top: 18px;
  transition: all 0.2s;
}

#modal-close:hover {
  background: rgba(170,68,255,0.25);
  box-shadow: 0 0 15px rgba(170,68,255,0.15);
}

#settings-msg {
  font-family: 'Share Tech Mono', monospace;
}
</style>
</head>
<body>

<!-- BACKGROUND LAYERS -->
<div class="bg-layer bg-gradient"></div>
<div class="bg-layer grid-floor"></div>

<!-- FLOATING 3D SHAPES -->
<div class="float-element hex-shape" style="top:10%;left:5%;--fx:40px;--fy:60px;--fx2:-30px;--fy2:-40px;background:var(--cyan);animation-duration:18s;"></div>
<div class="float-element diamond-shape" style="top:70%;left:85%;--fx:-50px;--fy:-40px;--fx2:30px;--fy2:50px;background:var(--magenta);animation-duration:22s;"></div>
<div class="float-element tri-shape" style="top:30%;left:90%;--fx:-30px;--fy:50px;--fx2:40px;--fy2:-30px;background:var(--lime);animation-duration:15s;"></div>
<div class="float-element hex-shape" style="top:80%;left:15%;--fx:50px;--fy:-30px;--fx2:-40px;--fy2:40px;background:var(--purple);animation-duration:20s;width:50px;height:58px;"></div>
<div class="float-element diamond-shape" style="top:5%;left:60%;--fx:-20px;--fy:40px;--fx2:30px;--fy2:-20px;background:var(--orange);animation-duration:25s;width:40px;height:40px;"></div>

<!-- SCANLINES -->
<div class="scanlines"></div>
<div class="scan-beam"></div>

<!-- HEADER -->
<div id="header">
  <span class="logo">TRUEMONITOR</span>
  <span class="header-version">v{{VERSION}}</span>
  <div class="live-dot" id="live-dot"></div>
  <span id="status-badge">Disconnected</span>
  <a href="/logout" class="header-logout" title="Sign out">LOGOUT</a>
</div>

<!-- TABS -->
<div id="tab-bar">
  <button class="tab-btn active" onclick="showTab('monitor')">Monitor</button>
  <button class="tab-btn" id="alerts-tab-btn" onclick="showTab('alerts')">
    Alerts<span class="badge" id="alert-badge" style="display:none">0</span>
  </button>
  <button class="tab-btn" onclick="showTab('settings')">Settings</button>
</div>

<!-- MONITOR TAB -->
<div id="tab-monitor" class="tab-panel active">
  <div id="info-bar">Connect to TrueNAS to begin monitoring</div>
  <div class="cards-grid">
    <!-- CPU -->
    <div class="card card-cpu">
      <div class="card-title"><div class="icon">&#9889;</div> PROCESSOR</div>
      <div class="card-value" id="cpu-val">--</div>
      <div class="card-sub" id="cpu-sub"></div>
      <div class="progress-track"><div class="progress-fill" id="cpu-bar"></div></div>
    </div>
    <!-- Memory -->
    <div class="card card-mem">
      <div class="card-title"><div class="icon">&#9670;</div> MEMORY</div>
      <div class="card-value" id="mem-val">--</div>
      <div class="card-sub" id="mem-sub"></div>
      <div class="progress-track"><div class="progress-fill" id="mem-bar"></div></div>
    </div>
    <!-- Network -->
    <div class="card card-net">
      <div class="graph-header">
        <div class="card-title"><div class="icon">&#9673;</div> NETWORK</div>
        <div class="legend">
          <span><span class="legend-dot" style="background:var(--lime)"></span>In</span>
          <span><span class="legend-dot" style="background:var(--cyan)"></span>Out</span>
        </div>
      </div>
      <div class="speed-row">
        <span class="speed-rx" id="net-rx">&#8595; --</span>
        <span class="speed-tx" id="net-tx">&#8593; --</span>
        <span class="iface-lbl" id="net-iface"></span>
      </div>
      <canvas class="graph-canvas" id="net-canvas"></canvas>
      <div class="scale-lbl" id="net-scale"></div>
    </div>
    <!-- Temperature -->
    <div class="card card-temp">
      <div class="graph-header">
        <div class="card-title"><div class="icon">&#9832;</div> CPU TEMP</div>
      </div>
      <div class="temp-row">
        <span class="temp-val" id="temp-val">--</span>
        <span class="temp-status" id="temp-status"></span>
        <span class="temp-range" id="temp-range"></span>
      </div>
      <canvas class="graph-canvas" id="temp-canvas"></canvas>
    </div>
  </div>
  <!-- Pool cards -->
  <div id="pool-section"><div class="pool-grid" id="pool-grid"></div></div>
</div>

<!-- ALERTS TAB -->
<div id="tab-alerts" class="tab-panel">
  <div id="alerts-header">
    <h2>ALERT LOG</h2>
    <span id="alert-count-lbl">0 alerts</span>
    <button id="clear-btn" onclick="clearAlerts()">CLEAR ALL</button>
  </div>
  <div id="alert-log"></div>
</div>

<!-- SETTINGS TAB -->
<div id="tab-settings" class="tab-panel">
  <div id="settings-panel">
    <div class="settings-section">CONNECTION</div>
    <div class="settings-row">
      <label class="settings-label">IP Address / Hostname:</label>
      <input class="settings-input" id="s-host" type="text" placeholder="192.168.1.100">
    </div>
    <div class="settings-row">
      <label class="settings-label">API Key:</label>
      <div class="key-row">
        <input class="settings-input" id="s-apikey" type="password" placeholder="API key">
        <button class="key-show-btn" onclick="toggleShow('s-apikey',this)">SHOW</button>
      </div>
    </div>
    <div class="settings-divider">--- or use credentials ---</div>
    <div class="settings-row">
      <label class="settings-label">Username:</label>
      <input class="settings-input" id="s-user" type="text" placeholder="admin">
    </div>
    <div class="settings-row">
      <label class="settings-label">Password:</label>
      <div class="key-row">
        <input class="settings-input" id="s-pass" type="password">
        <button class="key-show-btn" onclick="toggleShow('s-pass',this)">SHOW</button>
      </div>
    </div>
    <div class="settings-row">
      <label class="settings-label">Poll Interval (seconds):</label>
      <input class="settings-input" id="s-interval" type="number" min="2" value="5" style="width:80px">
    </div>

    <div class="settings-divider">--- alert thresholds ---</div>
    <div class="settings-row">
      <label class="settings-label">CPU Temp Alert (&deg;C):</label>
      <select class="settings-select" id="s-temp-thresh"></select>
    </div>

    <div class="settings-divider">--- broadcast to clients ---</div>
    <div class="settings-row">
      <label class="settings-label">Enable Broadcast:</label>
      <input type="checkbox" id="s-bcast-enabled" style="width:16px;height:16px;accent-color:var(--cyan)">
    </div>
    <div class="settings-row">
      <label class="settings-label">Broadcast Port:</label>
      <input class="settings-input" id="s-bcast-port" type="number" min="1024" max="65535" style="width:100px">
    </div>
    <div class="settings-row">
      <label class="settings-label">Shared Key:</label>
      <div class="key-row">
        <input class="settings-input" id="s-bcast-key" type="password">
        <button class="key-show-btn" onclick="toggleShow('s-bcast-key',this)">SHOW</button>
      </div>
    </div>
    <div id="broadcast-status"></div>

    <div class="settings-divider">--- web server ---</div>
    <div class="settings-row">
      <label class="settings-label">Bind Address:</label>
      <input class="settings-input" id="s-web-host" type="text" style="width:200px">
    </div>
    <div class="settings-row">
      <label class="settings-label">HTTP Port:</label>
      <input class="settings-input" id="s-web-port" type="number" min="1024" max="65534" style="width:100px"
             oninput="updateHttpsPort()">
    </div>
    <div class="settings-row">
      <label class="settings-label">HTTPS Port:</label>
      <input class="settings-input" id="s-https-port" type="text" readonly style="width:100px;opacity:0.5">
    </div>
    <div class="settings-note" style="margin-left:200px;margin-bottom:6px">
      Address/port changes take effect after restart.
    </div>

    <div class="settings-divider">--- web access ---</div>
    <div class="settings-row">
      <label class="settings-label">Username:</label>
      <input class="settings-input" id="s-web-user" type="text" style="width:200px">
    </div>
    <div class="settings-row">
      <label class="settings-label">New Password:</label>
      <div class="key-row">
        <input class="settings-input" id="s-web-pass" type="password" placeholder="leave blank to keep current">
        <button class="key-show-btn" onclick="toggleShow('s-web-pass',this)">SHOW</button>
      </div>
    </div>
    <div class="settings-row">
      <label class="settings-label">Confirm Password:</label>
      <input class="settings-input" id="s-web-pass2" type="password" placeholder="confirm new password">
    </div>

    <div class="btn-row">
      <button class="btn-primary" id="save-btn" onclick="saveSettings()">SAVE &amp; CONNECT</button>
      <button class="btn-secondary" id="disc-btn" onclick="disconnectNow()" disabled>DISCONNECT</button>
      <button class="btn-demo" id="demo-btn" onclick="toggleDemo()">DEMO MODE</button>
    </div>
    <div id="settings-msg" style="margin-top:14px;font-size:12px;color:var(--text-dim)"></div>
  </div>
</div>

<div id="footer"></div>

<!-- Drive Map Modal -->
<div id="modal-overlay" onclick="closeModal(event)">
  <div id="modal-box">
    <div id="modal-title"></div>
    <div id="modal-content"></div>
    <button id="modal-close" onclick="closeModalBtn()">CLOSE</button>
  </div>
</div>

<script>
// === 3D TILT ON MOUSE (monitor tab cards only) ===
document.addEventListener('mousemove', function(e) {
  if (currentTab !== 'monitor') return;
  var cards = document.querySelectorAll('.cards-grid .card, .pool-card');
  var cx = window.innerWidth / 2;
  var cy = window.innerHeight / 2;
  var rotY = ((e.clientX - cx) / cx) * 2;
  var rotX = ((e.clientY - cy) / cy) * -2;
  cards.forEach(function(card) {
    var rect = card.getBoundingClientRect();
    var cardCX = rect.left + rect.width / 2;
    var cardCY = rect.top + rect.height / 2;
    var dist = Math.hypot(e.clientX - cardCX, e.clientY - cardCY);
    var intensity = Math.max(0, 1 - dist / 600);
    card.style.transform = 'perspective(800px) rotateX(' + (rotX * intensity) +
      'deg) rotateY(' + (rotY * intensity) + 'deg) translateZ(' + (intensity * 8) + 'px)';
  });
});

// === CORE APP LOGIC ===
var HISTORY_LEN = 60;
var netRxHist = [], netTxHist = [], tempHist = [];
var alertCount = 0, unreadAlerts = 0;
var currentTab = 'monitor';
var demoActive = false;
var connected = false;

// --- SSE ---
var sseSource = null;
function connectSSE() {
  if (sseSource) { try { sseSource.close(); } catch(e){} }
  sseSource = new EventSource('/events');
  sseSource.addEventListener('stats', function(e) { var d = JSON.parse(e.data); handleStats(d); });
  sseSource.addEventListener('alert', function(e) { var d = JSON.parse(e.data); appendAlert(d); });
  sseSource.addEventListener('clear_alerts', function() { clearAlertsUI(); });
  sseSource.addEventListener('status', function(e) { var d = JSON.parse(e.data); setStatus(d.text, d.state); });
  sseSource.addEventListener('broadcast_status', function(e) {
    var d = JSON.parse(e.data);
    document.getElementById('broadcast-status').textContent = d.text;
  });
  sseSource.onerror = function() { setStatus('Reconnecting\u2026', 'connecting'); setTimeout(connectSSE, 3000); };
}

// --- Status badge ---
function setStatus(text, state) {
  var el = document.getElementById('status-badge');
  el.textContent = text;
  el.className = state || '';
  connected = (state === 'ok');
  document.getElementById('live-dot').className = 'live-dot' + (connected ? ' on' : '');
  document.getElementById('disc-btn').disabled = !connected;
  document.getElementById('save-btn').disabled = demoActive;
}

// --- Tab switching ---
function showTab(name) {
  currentTab = name;
  document.querySelectorAll('.tab-panel').forEach(function(p) { p.classList.remove('active'); });
  document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
  document.getElementById('tab-' + name).classList.add('active');
  document.querySelector('[onclick="showTab(\'' + name + '\')"]').classList.add('active');
  if (name === 'alerts') { unreadAlerts = 0; updateAlertBadge(); }
  if (name === 'settings') { loadSettingsForm(); }
  // Reset 3D transforms when leaving monitor
  if (name !== 'monitor') {
    document.querySelectorAll('.cards-grid .card, .pool-card').forEach(function(c) {
      c.style.transform = '';
    });
  }
}

// --- Alert badge ---
function updateAlertBadge() {
  var badge = document.getElementById('alert-badge');
  if (unreadAlerts > 0 && currentTab !== 'alerts') {
    badge.textContent = unreadAlerts; badge.style.display = '';
  } else { badge.style.display = 'none'; }
}

// --- Stats update ---
function handleStats(s) {
  updateInfoBar(s);
  updateCpu(s.cpu_percent, s.loadavg);
  updateMem(s.memory_used, s.memory_total, s.memory_percent);
  updateNet(s.net_rx, s.net_tx, s.net_iface, s.net_history_rx, s.net_history_tx);
  updateTemp(s.cpu_temp, s.temp_history);
  updatePools(s.pools || []);
  document.getElementById('footer').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
}

function updateInfoBar(s) {
  var la = (s.loadavg || []).map(function(v) { return v.toFixed(2); }).join(', ');
  document.getElementById('info-bar').textContent =
    (s.hostname||'N/A') + '  \u2502  ' + (s.version||'N/A') +
    '  \u2502  Uptime: ' + (s.uptime||'N/A') + '  \u2502  Load: ' + (la||'N/A');
}

function colorFor(pct, t1, t2) {
  return pct < t1 ? 'var(--good)' : pct < t2 ? 'var(--warning)' : 'var(--critical)';
}

function neonColorFor(pct, t1, t2) {
  return pct < t1 ? 'var(--cyan)' : pct < t2 ? 'var(--gold)' : 'var(--magenta)';
}

function updateCpu(cpu, la) {
  var v = document.getElementById('cpu-val');
  var b = document.getElementById('cpu-bar');
  var s = document.getElementById('cpu-sub');
  if (cpu != null) {
    var c = colorFor(cpu, 70, 90);
    var nc = neonColorFor(cpu, 70, 90);
    v.textContent = cpu + '%'; v.style.color = nc;
    v.style.textShadow = '0 0 20px ' + nc;
    b.style.width = cpu + '%';
    b.style.background = 'linear-gradient(90deg, ' + nc + ', var(--blue))';
    b.style.boxShadow = '0 0 12px ' + nc;
    var la_s = (la||[]).map(function(x) { return x.toFixed(2); }).join(', ');
    s.textContent = 'Load avg: ' + la_s;
  } else { v.textContent = 'N/A'; v.style.color = 'var(--text-dim)'; }
}

function updateMem(mu, mt, mp) {
  var v = document.getElementById('mem-val');
  var b = document.getElementById('mem-bar');
  var s = document.getElementById('mem-sub');
  if (mp != null) {
    var nc = neonColorFor(mp, 70, 90);
    v.textContent = mp + '%'; v.style.color = nc;
    v.style.textShadow = '0 0 20px ' + nc;
    b.style.width = mp + '%';
    b.style.background = 'linear-gradient(90deg, var(--magenta), var(--purple))';
    b.style.boxShadow = '0 0 12px var(--magenta)';
    s.textContent = formatBytes(mu) + ' / ' + formatBytes(mt);
  } else {
    v.textContent = 'N/A'; v.style.color = 'var(--text-dim)';
    if (mt) s.textContent = 'Total: ' + formatBytes(mt);
  }
}

function updateNet(rx, tx, iface, rxHist, txHist) {
  if (rxHist) netRxHist = rxHist;
  else { netRxHist.push(rx||0); if (netRxHist.length > HISTORY_LEN) netRxHist.shift(); }
  if (txHist) netTxHist = txHist;
  else { netTxHist.push(tx||0); if (netTxHist.length > HISTORY_LEN) netTxHist.shift(); }
  document.getElementById('net-rx').textContent = '\u2193 ' + formatBytes(rx||0, true);
  document.getElementById('net-tx').textContent = '\u2191 ' + formatBytes(tx||0, true);
  document.getElementById('net-iface').textContent = iface||'';
  drawNetGraph();
}

function updateTemp(temp, tHist) {
  if (tHist) tempHist = tHist;
  else if (temp != null) { tempHist.push(temp); if (tempHist.length > HISTORY_LEN) tempHist.shift(); }
  var v = document.getElementById('temp-val');
  var st = document.getElementById('temp-status');
  var rng = document.getElementById('temp-range');
  if (temp != null) {
    var c = colorFor(temp, 60, 80);
    var lbl = temp < 60 ? 'Normal' : temp < 80 ? 'Warm' : 'Hot!';
    v.textContent = temp + '\u00b0C'; v.style.color = c;
    v.style.textShadow = '0 0 15px ' + c;
    st.textContent = lbl; st.style.color = c;
    if (tempHist.length > 0) {
      var lo = Math.min.apply(null, tempHist), hi = Math.max.apply(null, tempHist);
      rng.textContent = 'Low: ' + lo.toFixed(0) + '\u00b0C  High: ' + hi.toFixed(0) + '\u00b0C';
    }
    drawTempGraph();
  } else { v.textContent = 'N/A'; v.style.color = 'var(--text-dim)'; st.textContent = ''; }
}

// --- Canvas graphs ---
function drawNetGraph() {
  var canvas = document.getElementById('net-canvas');
  var w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * devicePixelRatio; canvas.height = h * devicePixelRatio;
  var ctx = canvas.getContext('2d');
  ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
  var all = netRxHist.concat(netTxHist);
  var maxVal = Math.max.apply(null, all.concat([1]));
  var n = HISTORY_LEN, graphH = h - 2;

  // Grid lines
  ctx.strokeStyle = 'rgba(0,240,255,0.06)'; ctx.setLineDash([2,6]);
  for (var i=1;i<4;i++) {
    var gy = Math.floor(graphH*i/4);
    ctx.beginPath(); ctx.moveTo(0,gy); ctx.lineTo(w,gy); ctx.stroke();
  }
  ctx.setLineDash([]);

  function drawArea(data, strokeColor, fillColor) {
    if (data.length < 2) return;
    ctx.beginPath(); ctx.moveTo(0, h);
    data.forEach(function(v, i) {
      var x = n > 1 ? w * i / (n - 1) : 0;
      var y = graphH - (v / maxVal) * (graphH - 4) - 2;
      y = Math.max(2, Math.min(graphH - 2, y));
      if (i === 0) ctx.lineTo(x, y);
      else {
        var px = n > 1 ? w * (i - 1) / (n - 1) : 0;
        var cpx = (px + x) / 2;
        ctx.bezierCurveTo(cpx, graphH - (data[i-1] / maxVal) * (graphH - 4) - 2, cpx, y, x, y);
      }
    });
    ctx.lineTo(w, h); ctx.closePath();
    ctx.fillStyle = fillColor; ctx.fill();
    // Stroke
    ctx.beginPath();
    data.forEach(function(v, i) {
      var x = n > 1 ? w * i / (n - 1) : 0;
      var y = graphH - (v / maxVal) * (graphH - 4) - 2;
      y = Math.max(2, Math.min(graphH - 2, y));
      if (i === 0) ctx.moveTo(x, y);
      else {
        var px = n > 1 ? w * (i - 1) / (n - 1) : 0;
        var cpx = (px + x) / 2;
        ctx.bezierCurveTo(cpx, graphH - (data[i-1] / maxVal) * (graphH - 4) - 2, cpx, y, x, y);
      }
    });
    ctx.strokeStyle = strokeColor; ctx.lineWidth = 2;
    ctx.shadowColor = strokeColor; ctx.shadowBlur = 8;
    ctx.stroke(); ctx.shadowBlur = 0;
  }
  drawArea(netRxHist, '#aaff00', 'rgba(170,255,0,0.06)');
  drawArea(netTxHist, '#00f0ff', 'rgba(0,240,255,0.04)');
  document.getElementById('net-scale').textContent = 'Peak: ' + formatBytes(maxVal, true);
}

function drawTempGraph() {
  var canvas = document.getElementById('temp-canvas');
  var w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * devicePixelRatio; canvas.height = h * devicePixelRatio;
  var ctx = canvas.getContext('2d');
  ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
  if (!tempHist.length) return;

  var tMin=20, tMax=100, tRange=tMax-tMin;
  var graphH = h-2;
  var n = HISTORY_LEN;
  function yFor(t) { return Math.floor(graphH - ((t-tMin)/tRange)*(graphH-4) - 2); }

  var yHot = yFor(80), yWarm = yFor(60);
  ctx.fillStyle='rgba(239,83,80,0.05)'; ctx.fillRect(0,0,w,yHot);
  ctx.fillStyle='rgba(255,167,38,0.04)'; ctx.fillRect(0,yHot,w,yWarm-yHot);

  ctx.strokeStyle='rgba(239,83,80,0.3)'; ctx.setLineDash([3,3]);
  ctx.beginPath(); ctx.moveTo(0,yHot); ctx.lineTo(w,yHot); ctx.stroke();
  ctx.fillStyle='rgba(239,83,80,0.6)'; ctx.font='9px "Share Tech Mono"'; ctx.textAlign='right';
  ctx.fillText('80\u00b0C', w-2, yHot-4);

  ctx.strokeStyle='rgba(255,167,38,0.3)';
  ctx.beginPath(); ctx.moveTo(0,yWarm); ctx.lineTo(w,yWarm); ctx.stroke();
  ctx.fillStyle='rgba(255,167,38,0.6)';
  ctx.fillText('60\u00b0C', w-2, yWarm-4);
  ctx.setLineDash([]);

  var latest = tempHist[tempHist.length-1];
  var lineColor = latest < 60 ? '#66bb6a' : latest < 80 ? '#ffa726' : '#ef5350';

  // Area fill
  ctx.beginPath(); ctx.moveTo(0, h);
  tempHist.forEach(function(v, i) {
    var x = n>1 ? w*i/(n-1) : 0;
    var y = yFor(v); y = Math.max(2, Math.min(graphH-2, y));
    if (i === 0) ctx.lineTo(x, y);
    else {
      var px = n>1 ? w*(i-1)/(n-1) : 0;
      var cpx = (px + x) / 2;
      ctx.bezierCurveTo(cpx, yFor(tempHist[i-1]), cpx, y, x, y);
    }
  });
  ctx.lineTo(w, h); ctx.closePath();
  ctx.fillStyle = lineColor.replace(')', ',0.06)').replace('rgb', 'rgba');
  ctx.fill();

  // Line
  ctx.beginPath();
  tempHist.forEach(function(v, i) {
    var x = n>1 ? w*i/(n-1) : 0;
    var y = yFor(v); y = Math.max(2, Math.min(graphH-2, y));
    if (i === 0) ctx.moveTo(x, y);
    else {
      var px = n>1 ? w*(i-1)/(n-1) : 0;
      var cpx = (px + x) / 2;
      ctx.bezierCurveTo(cpx, yFor(tempHist[i-1]), cpx, y, x, y);
    }
  });
  ctx.strokeStyle = lineColor; ctx.lineWidth = 2;
  ctx.shadowColor = lineColor; ctx.shadowBlur = 8;
  ctx.stroke(); ctx.shadowBlur = 0;
}

// --- Pool cards ---
var _poolState = {};
function updatePools(pools) {
  var grid = document.getElementById('pool-grid');
  var names = pools.map(function(p) { return p.name; });
  Object.keys(_poolState).forEach(function(n) {
    if (!names.includes(n)) {
      var el = document.getElementById('pool-card-'+n); if (el) el.remove();
      delete _poolState[n];
    }
  });
  pools.forEach(function(pool) {
    var n = pool.name;
    var card = document.getElementById('pool-card-'+n);
    if (!card || (_poolState[n]||{}).diskCount !== pool.disks.length) {
      if (card) card.remove();
      card = buildPoolCard(pool);
      grid.appendChild(card);
      _poolState[n] = { diskCount: pool.disks.length };
    }
    updatePoolCard(card, pool);
  });
}

function buildPoolCard(pool) {
  var n = pool.name;
  var div = document.createElement('div');
  div.className = 'pool-card'; div.id = 'pool-card-'+n;

  var titleRow = document.createElement('div');
  titleRow.className = 'pool-title-row';
  var nameEl = document.createElement('span');
  nameEl.className = 'pool-name';
  nameEl.textContent = 'POOL: ' + n.toUpperCase();
  var mapBtn = document.createElement('button');
  mapBtn.className = 'map-btn';
  mapBtn.textContent = 'DRIVE MAP';
  mapBtn.setAttribute('onclick', 'showDriveMap(' + JSON.stringify(n) + ')');
  titleRow.appendChild(nameEl);
  titleRow.appendChild(mapBtn);
  div.appendChild(titleRow);

  var val = document.createElement('div');
  val.className = 'card-value'; val.id = 'pv-'+n; val.textContent = '--';
  div.appendChild(val);

  var sub = document.createElement('div');
  sub.className = 'card-sub'; sub.id = 'ps-'+n;
  div.appendChild(sub);

  var track = document.createElement('div');
  track.className = 'progress-track';
  var fill = document.createElement('div');
  fill.className = 'progress-fill'; fill.id = 'pb-'+n;
  track.appendChild(fill);
  div.appendChild(track);

  var diskRow = document.createElement('div');
  diskRow.className = 'disk-row';
  var diskLbl = document.createElement('span');
  diskLbl.className = 'disk-lbl'; diskLbl.textContent = 'Disks:';
  var diskContainer = document.createElement('span');
  diskContainer.id = 'pd-'+n;
  diskRow.appendChild(diskLbl);
  diskRow.appendChild(diskContainer);
  div.appendChild(diskRow);

  return div;
}

function updatePoolCard(card, pool) {
  var n = pool.name, pct = pool.percent||0;
  var c = pct < 70 ? 'var(--lime)' : pct < 85 ? 'var(--gold)' : 'var(--magenta)';
  document.getElementById('pv-'+n).textContent = pct + '%';
  document.getElementById('pv-'+n).style.color = c;
  document.getElementById('pv-'+n).style.textShadow = '0 0 15px ' + c;
  var pb = document.getElementById('pb-'+n);
  pb.style.width = pct+'%';
  pb.style.background = 'linear-gradient(90deg, var(--purple), ' + c + ')';
  pb.style.boxShadow = '0 0 12px ' + c;
  document.getElementById('ps-'+n).textContent =
    formatBytes(pool.used) + ' / ' + formatBytes(pool.total) +
    '  (' + formatBytes(pool.available) + ' free)';
  var pd = document.getElementById('pd-'+n);
  while (pd.firstChild) pd.removeChild(pd.firstChild);
  (pool.disks||[]).forEach(function(d) {
    var ind = document.createElement('span');
    ind.className = 'disk-ind';
    var diskColor = d.has_error ? 'var(--critical)' : 'var(--lime)';
    ind.style.background = diskColor;
    ind.style.color = diskColor;
    ind.title = d.name;
    pd.appendChild(ind);
  });
  if (pool.topology) { window['_topo_'+n] = pool.topology; }
}

// --- Drive Map ---
function showDriveMap(name) {
  var topo = window['_topo_'+name] || {};
  document.getElementById('modal-title').textContent = 'POOL: ' + name.toUpperCase();
  var content = document.getElementById('modal-content');
  while (content.firstChild) content.removeChild(content.firstChild);

  var groupLabels = {
    data:'DATA VDEVS', cache:'CACHE (L2ARC)', log:'LOG (SLOG)',
    spare:'HOT SPARES', special:'SPECIAL VDEVS', dedup:'DEDUP VDEVS'
  };
  var hasContent = false;
  ['data','cache','log','spare','special','dedup'].forEach(function(gk) {
    var vdevs = topo[gk];
    if (!vdevs || !vdevs.length) return;
    hasContent = true;
    var glbl = document.createElement('div');
    glbl.className = 'vdev-group-label';
    glbl.textContent = groupLabels[gk]||gk;
    content.appendChild(glbl);

    vdevs.forEach(function(vdev) {
      var vtype = vdev.type||'DISK', vstatus = vdev.status||'ONLINE';
      var icon = vtype==='MIRROR'?'\u2194':vtype.startsWith('RAIDZ')?'\u2726':vtype==='STRIPE'?'\u2502':'\u25cb';
      var stColor = vstatus==='ONLINE'?'var(--lime)':'var(--critical)';
      var box = document.createElement('div'); box.className = 'vdev-box';

      var hdr = document.createElement('div'); hdr.className = 'vdev-hdr';
      var typeEl = document.createElement('span'); typeEl.className = 'vdev-type';
      typeEl.textContent = icon + '  ' + vtype;
      var stEl = document.createElement('span'); stEl.className = 'vdev-status';
      stEl.style.color = stColor; stEl.textContent = vstatus;
      hdr.appendChild(typeEl); hdr.appendChild(stEl);
      box.appendChild(hdr);

      var dc = document.createElement('div'); dc.className = 'disk-cards';
      (vdev.disks||[]).forEach(function(disk, di) {
        var hasErr = disk.errors>0 || !['ONLINE',''].includes(disk.status||'');
        var dbg = hasErr?'rgba(92,26,26,0.5)':'rgba(26,42,26,0.5)';
        var dbc = hasErr?'var(--critical)':'var(--lime)';
        var stTxt = disk.errors>0 ? disk.status + ' (' + disk.errors + ' err)' : disk.status;
        if (di>0 && ['MIRROR','RAIDZ1','RAIDZ2','RAIDZ3'].includes(vtype)) {
          var conn = document.createElement('span'); conn.className='disk-connector';
          conn.textContent='\u2500\u2500'; dc.appendChild(conn);
        }
        var dcard = document.createElement('div');
        dcard.className='disk-card';
        dcard.style.cssText='background:'+dbg+';border:2px solid '+dbc;
        var dname = document.createElement('div');
        dname.className='disk-card-name';
        dname.style.color = hasErr ? '#fff' : 'var(--text)';
        dname.textContent = disk.name;
        var dstatus = document.createElement('div');
        dstatus.className='disk-card-status';
        dstatus.style.color = dbc;
        dstatus.textContent = stTxt;
        dcard.appendChild(dname);
        dcard.appendChild(dstatus);
        dc.appendChild(dcard);
      });
      box.appendChild(dc);
      content.appendChild(box);
    });
  });
  if (!hasContent) {
    var noData = document.createElement('div');
    noData.style.cssText = 'color:var(--text-dim);padding:20px;font-family:Share Tech Mono,monospace';
    noData.textContent = 'No topology data available';
    content.appendChild(noData);
  }
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal(e) { if (e.target===document.getElementById('modal-overlay')) closeModalBtn(); }
function closeModalBtn() { document.getElementById('modal-overlay').classList.remove('open'); }

// --- Alerts ---
function appendAlert(d) {
  var log = document.getElementById('alert-log');
  var entry = document.createElement('div'); entry.className='alert-entry';
  var cls = 'alert-'+d.severity;
  var prefix = {critical:'CRITICAL',warning:'WARNING',info:'INFO',resolved:'RESOLVED'}[d.severity]||'INFO';
  var ts = document.createElement('span'); ts.className = 'alert-ts';
  ts.textContent = '[' + d.time + '] ';
  var sev = document.createElement('span'); sev.className = cls;
  sev.textContent = prefix + ': ';
  var msg = document.createTextNode(d.message);
  entry.appendChild(ts);
  entry.appendChild(sev);
  entry.appendChild(msg);
  log.insertBefore(entry, log.firstChild);
  alertCount++;
  document.getElementById('alert-count-lbl').textContent = alertCount + ' alert' + (alertCount!==1?'s':'');
  if (d.severity==='critical'||d.severity==='warning'||d.severity==='info') {
    unreadAlerts++; updateAlertBadge();
    if (Notification.permission==='granted') {
      new Notification('TrueMonitor Alert', { body: prefix + ': ' + d.message, icon: '/favicon.ico' });
    }
  }
}

function clearAlertsUI() {
  var log = document.getElementById('alert-log');
  while (log.firstChild) log.removeChild(log.firstChild);
  alertCount = 0; unreadAlerts = 0;
  document.getElementById('alert-count-lbl').textContent = '0 alerts';
  updateAlertBadge();
}

function clearAlerts() {
  fetch('/api/alerts/clear', {method:'POST'}).catch(function(){});
  clearAlertsUI();
}

// --- Settings form ---
function loadSettingsForm() {
  fetch('/api/config').then(function(r) { return r.json(); }).then(function(cfg) {
    document.getElementById('s-host').value = cfg.host||'';
    document.getElementById('s-apikey').value = cfg.api_key||'';
    document.getElementById('s-user').value = cfg.username||'';
    document.getElementById('s-pass').value = cfg.password||'';
    document.getElementById('s-interval').value = cfg.interval||5;
    document.getElementById('s-temp-thresh').value = cfg.temp_threshold||82;
    document.getElementById('s-bcast-enabled').checked = cfg.broadcast_enabled||false;
    document.getElementById('s-bcast-port').value = cfg.broadcast_port||7337;
    document.getElementById('s-bcast-key').value = cfg.broadcast_key||'truemonitor';
    document.getElementById('s-web-host').value = cfg.web_host||'0.0.0.0';
    document.getElementById('s-web-port').value = cfg.web_port||8088;
    updateHttpsPort();
    document.getElementById('s-web-user').value = cfg.web_username||'client';
    document.getElementById('s-web-pass').value = '';
    document.getElementById('s-web-pass2').value = '';
    fetch('/api/broadcast_status').then(function(r) { return r.json(); }).then(function(d) {
      document.getElementById('broadcast-status').textContent = d.text;
    }).catch(function(){});
  }).catch(function(){});
}

function updateHttpsPort() {
  var p = parseInt(document.getElementById('s-web-port').value)||8088;
  document.getElementById('s-https-port').value = p + 1;
}

// Populate temp threshold dropdown
(function() {
  var sel = document.getElementById('s-temp-thresh');
  for (var t=40;t<=96;t++) {
    var opt = document.createElement('option');
    opt.value=t; opt.textContent=t+'\u00b0C'; sel.appendChild(opt);
  }
})();

function saveSettings() {
  var host = document.getElementById('s-host').value.trim();
  var apiKey = document.getElementById('s-apikey').value.trim();
  var user = document.getElementById('s-user').value.trim();
  var pass = document.getElementById('s-pass').value.trim();
  if (!host) { showMsg('Please enter an IP address or hostname.', 'critical'); return; }
  if (!apiKey && !(user && pass)) { showMsg('Provide an API key or username & password.', 'critical'); return; }
  var webUser = document.getElementById('s-web-user').value.trim();
  var webPass = document.getElementById('s-web-pass').value;
  var webPass2 = document.getElementById('s-web-pass2').value;
  if (webPass && webPass !== webPass2) {
    showMsg('New passwords do not match.', 'err'); return;
  }
  if (!webUser) { showMsg('Web username cannot be empty.', 'err'); return; }
  var body = {
    host: host, api_key: apiKey, username: user, password: pass,
    interval: parseInt(document.getElementById('s-interval').value)||5,
    temp_threshold: parseInt(document.getElementById('s-temp-thresh').value)||82,
    broadcast_enabled: document.getElementById('s-bcast-enabled').checked,
    broadcast_port: parseInt(document.getElementById('s-bcast-port').value)||7337,
    broadcast_key: document.getElementById('s-bcast-key').value.trim()||'truemonitor',
    web_host: document.getElementById('s-web-host').value.trim()||'0.0.0.0',
    web_port: parseInt(document.getElementById('s-web-port').value)||8088,
    web_username: webUser,
    web_password: webPass,
  };
  fetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)})
    .then(function(r) { return r.json(); }).then(function(d) {
      showMsg(d.message || 'Saved.', d.ok ? 'ok' : 'err');
    }).catch(function(e) { showMsg('Error: '+e, 'err'); });
}

function showMsg(msg, state) {
  var el = document.getElementById('settings-msg');
  el.textContent = msg;
  el.style.color = state==='ok' ? 'var(--lime)' : state==='err' ? 'var(--critical)' : 'var(--text-dim)';
}

function disconnectNow() {
  fetch('/api/disconnect', {method:'POST'}).catch(function(){});
}

function toggleDemo() {
  fetch('/api/demo', {method:'POST'}).then(function(r) { return r.json(); }).then(function(d) {
    demoActive = d.active;
    var btn = document.getElementById('demo-btn');
    btn.textContent = demoActive ? 'STOP DEMO' : 'DEMO MODE';
    btn.style.background = demoActive ? 'linear-gradient(135deg, var(--critical), var(--magenta))' : 'linear-gradient(135deg, var(--orange), var(--gold))';
    btn.style.color = demoActive ? '#fff' : '#000';
    document.getElementById('save-btn').disabled = demoActive;
  }).catch(function(){});
}

function toggleShow(id, btn) {
  var el = document.getElementById(id);
  if (el.type==='password') { el.type='text'; btn.textContent='HIDE'; }
  else { el.type='password'; btn.textContent='SHOW'; }
}

// --- Utilities ---
function formatBytes(v, ps) {
  if (v==null) return 'N/A';
  var sfx = ps ? '/s' : '';
  var units = ['B','KB','MB','GB','TB'];
  for (var u = 0; u < units.length; u++) {
    if (Math.abs(v) < 1024) return v.toFixed(1)+' '+units[u]+sfx;
    v /= 1024;
  }
  return v.toFixed(1)+' PB'+sfx;
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                  .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// Request notification permission
if ('Notification' in window && Notification.permission==='default') {
  Notification.requestPermission();
}

// Load existing alerts on page load
fetch('/api/alerts').then(function(r) { return r.json(); }).then(function(list) {
  list.forEach(function(a) { appendAlert(a); });
}).catch(function(){});

// Init
loadSettingsForm();
connectSSE();
window.addEventListener('resize', function() { drawNetGraph(); drawTempGraph(); });
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Web Application
# ---------------------------------------------------------------------------
class TrueMonitorWebApp:
    def __init__(self):
        self.config = self._load_config()
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
        self._connect_alert_times = {}

        # Demo state
        self._demo_cpu = 35.0
        self._demo_mem = 55.0
        self._demo_temp = 42.0
        self._demo_rx = 25_000_000.0
        self._demo_tx = 8_000_000.0

        # SSE subscriber queues
        self._sse_queues = []
        self._sse_lock = threading.Lock()

        # Login brute-force tracking: ip -> (failure_count, last_failure_time)
        self._login_failures = {}
        self._login_lock = threading.Lock()

        # Connection status
        self._status_text = "Disconnected"
        self._status_state = ""  # ok, err, connecting, demo

        # Flask app
        import logging
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)
        self.flask_app = Flask(__name__)
        # Deterministic key so sessions survive restarts
        self.flask_app.config["SECRET_KEY"] = _get_encryption_key()
        self.flask_app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
        self._setup_routes()

        # Load existing alerts from disk
        self._load_alerts_from_file()

        # Auto-connect if we have a saved host
        if self.config.get("host"):
            threading.Thread(target=self._connect, daemon=True).start()

        # Start broadcast server if enabled
        self._start_broadcast_server_if_enabled()

    # -----------------------------------------------------------------------
    # Config
    # -----------------------------------------------------------------------
    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                needs_resave = False
                for key in ("password", "api_key", "web_password"):
                    if data.get(f"{key}_encrypted") and data.get(key):
                        data[key] = _decrypt(data[key])
                        del data[f"{key}_encrypted"]
                    elif data.get(key) and key not in ("web_password",):
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
        save_data = dict(self.config)
        for key in ("password", "api_key", "web_password"):
            if save_data.get(key):
                save_data[key] = _encrypt(save_data[key])
                save_data[f"{key}_encrypted"] = True
        with open(CONFIG_FILE, "w") as f:
            json.dump(save_data, f, indent=2)

    # -----------------------------------------------------------------------
    # SSE helpers
    # -----------------------------------------------------------------------
    def _push_event(self, event_type: str, data: dict):
        payload = json.dumps(data)
        with self._sse_lock:
            dead = []
            for q in self._sse_queues:
                try:
                    q.put_nowait({"type": event_type, "data": payload})
                except queue.Full:
                    dead.append(q)
            for q in dead:
                try:
                    self._sse_queues.remove(q)
                except ValueError:
                    pass

    def _set_status(self, text: str, state: str):
        self._status_text = text
        self._status_state = state
        self._push_event("status", {"text": text, "state": state})

    # -----------------------------------------------------------------------
    # Login brute-force protection
    # -----------------------------------------------------------------------
    # After MAX_FAILURES failed attempts the IP is locked out for LOCKOUT_SECONDS.
    # The lockout resets automatically once the period expires.
    MAX_FAILURES = 5
    LOCKOUT_SECONDS = 15 * 60  # 15 minutes

    def _get_client_ip(self):
        """Return the real client IP, respecting X-Forwarded-For from a proxy."""
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or "unknown"

    def _lockout_remaining(self, ip: str) -> int:
        """Return seconds remaining in lockout for this IP, or 0 if not locked."""
        with self._login_lock:
            entry = self._login_failures.get(ip)
            if not entry:
                return 0
            count, last = entry
            if count < self.MAX_FAILURES:
                return 0
            elapsed = (datetime.now() - last).total_seconds()
            remaining = self.LOCKOUT_SECONDS - elapsed
            if remaining <= 0:
                del self._login_failures[ip]
                return 0
            return int(remaining)

    def _record_failure(self, ip: str):
        with self._login_lock:
            count, _ = self._login_failures.get(ip, (0, None))
            self._login_failures[ip] = (count + 1, datetime.now())
            debug(f"Login failure #{count + 1} from {ip}")

    def _reset_failures(self, ip: str):
        with self._login_lock:
            self._login_failures.pop(ip, None)

    def _failures_remaining(self, ip: str) -> int:
        """How many attempts left before lockout."""
        with self._login_lock:
            count, _ = self._login_failures.get(ip, (0, None))
            return max(0, self.MAX_FAILURES - count)

    # -----------------------------------------------------------------------
    # Flask routes
    # -----------------------------------------------------------------------
    def _check_credentials(self, username, password):
        cfg_user = self.config.get("web_username", "client")
        cfg_pass = self.config.get("web_password", "truemonitor")
        return username == cfg_user and password == cfg_pass

    def _setup_routes(self):
        app = self.flask_app

        @app.before_request
        def require_login():
            if request.path in ("/login", "/logout"):
                return None
            if not session.get("logged_in"):
                if request.path.startswith("/api/") or request.path == "/events":
                    return jsonify({"error": "unauthorized"}), 401
                return redirect("/login")

        @app.route("/login", methods=["GET", "POST"])
        def login():
            ip = self._get_client_ip()
            error = ""

            # Check lockout before doing anything
            remaining = self._lockout_remaining(ip)
            locked = remaining > 0
            if locked:
                mins, secs = divmod(remaining, 60)
                error = f"Too many failed attempts. Try again in {mins}m {secs:02d}s."

            elif request.method == "POST":
                u = request.form.get("username", "").strip()
                p = request.form.get("password", "")
                if self._check_credentials(u, p):
                    self._reset_failures(ip)
                    session.permanent = True
                    session["logged_in"] = True
                    return redirect("/")
                self._record_failure(ip)
                left = self._failures_remaining(ip)
                if left == 0:
                    mins, secs = divmod(self.LOCKOUT_SECONDS, 60)
                    error = f"Too many failed attempts. Locked out for {mins} minutes."
                    locked = True
                else:
                    error = f"Invalid username or password. {left} attempt{'s' if left != 1 else ''} remaining."

            disabled = "disabled" if locked else ""
            return Response(
                LOGIN_HTML
                    .replace("{version}", APP_VERSION)
                    .replace("{error}", error)
                    .replace("{disabled}", disabled),
                content_type="text/html",
                status=429 if locked else 200,
            )

        @app.route("/logout")
        def logout():
            session.clear()
            return redirect("/login")

        @app.route("/")
        def index():
            html = HTML_TEMPLATE.replace("{{VERSION}}", APP_VERSION)
            return Response(html, content_type="text/html")

        @app.route("/events")
        def events():
            def stream():
                q = queue.Queue(maxsize=30)
                with self._sse_lock:
                    self._sse_queues.append(q)
                # Send current status immediately
                yield (f"event: status\ndata: "
                       f'{json.dumps({"text": self._status_text, "state": self._status_state})}'
                       f"\n\n")
                try:
                    while True:
                        try:
                            ev = q.get(timeout=15)
                            yield f"event: {ev['type']}\ndata: {ev['data']}\n\n"
                        except queue.Empty:
                            yield ": keepalive\n\n"
                finally:
                    with self._sse_lock:
                        try:
                            self._sse_queues.remove(q)
                        except ValueError:
                            pass
            return Response(
                stream_with_context(stream()),
                content_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )

        @app.route("/api/config")
        def api_config():
            cfg = dict(self.config)
            # Don't send secrets in plaintext
            cfg.pop("password", None)
            cfg.pop("api_key", None)
            cfg["password"] = "••••" if self.config.get("password") else ""
            cfg["api_key"] = "••••" if self.config.get("api_key") else ""
            cfg.setdefault("temp_threshold", 82)
            cfg.setdefault("web_host", WEB_DEFAULT_HOST)
            cfg.setdefault("web_port", WEB_DEFAULT_PORT)
            cfg.setdefault("broadcast_port", BROADCAST_DEFAULT_PORT)
            cfg.setdefault("broadcast_key", BROADCAST_DEFAULT_KEY)
            cfg.setdefault("web_username", "client")
            cfg.pop("web_password", None)  # never send password to browser
            return jsonify(cfg)

        @app.route("/api/broadcast_status")
        def api_broadcast_status():
            if self.broadcast_server:
                port = self.config.get("broadcast_port", BROADCAST_DEFAULT_PORT)
                n = self.broadcast_server.client_count
                text = f"Broadcasting on port {port}  |  {n} client{'s' if n!=1 else ''} connected"
            else:
                text = "Broadcast disabled"
            return jsonify({"text": text})

        @app.route("/api/settings", methods=["POST"])
        def api_settings():
            try:
                body = request.get_json(force=True)
                host = (body.get("host") or "").strip()
                api_key = (body.get("api_key") or "").strip()
                user = (body.get("username") or "").strip()
                pw = (body.get("password") or "").strip()
                if not host:
                    return jsonify({"ok": False, "message": "Host is required."})
                if not api_key and not (user and pw):
                    return jsonify({"ok": False, "message": "Provide an API key or username & password."})

                # Preserve existing secret if placeholder was sent back
                if api_key == "••••":
                    api_key = self.config.get("api_key", "")
                if pw == "••••":
                    pw = self.config.get("password", "")

                try:
                    iv = max(2, int(body.get("interval", 5)))
                except (ValueError, TypeError):
                    iv = 5
                try:
                    temp_thresh = max(1, int(body.get("temp_threshold", 82)))
                except (ValueError, TypeError):
                    temp_thresh = 82
                try:
                    bcast_port = max(1024, min(65535, int(body.get("broadcast_port", BROADCAST_DEFAULT_PORT))))
                except (ValueError, TypeError):
                    bcast_port = BROADCAST_DEFAULT_PORT
                bcast_key = (body.get("broadcast_key") or BROADCAST_DEFAULT_KEY).strip()
                try:
                    web_port = max(1024, min(65534, int(body.get("web_port", WEB_DEFAULT_PORT))))
                except (ValueError, TypeError):
                    web_port = WEB_DEFAULT_PORT
                web_host = (body.get("web_host") or WEB_DEFAULT_HOST).strip()

                web_username = (body.get("web_username") or "client").strip()
                web_password_new = body.get("web_password", "").strip()
                # Keep existing password if none provided
                web_password = (web_password_new if web_password_new
                                else self.config.get("web_password", "truemonitor"))

                old_web = (self.config.get("web_host"), self.config.get("web_port"))
                self.config = {
                    "host": host, "api_key": api_key,
                    "username": user, "password": pw,
                    "interval": iv,
                    "temp_threshold": temp_thresh,
                    "broadcast_enabled": bool(body.get("broadcast_enabled", False)),
                    "broadcast_port": bcast_port,
                    "broadcast_key": bcast_key,
                    "web_host": web_host,
                    "web_port": web_port,
                    "web_username": web_username,
                    "web_password": web_password,
                }
                self._save_config()
                self._start_broadcast_server_if_enabled()
                threading.Thread(target=self._connect, daemon=True).start()

                msg = "Settings saved. Connecting..."
                if (web_host, web_port) != old_web:
                    msg += " (Web address/port changes take effect after restart.)"
                return jsonify({"ok": True, "message": msg})
            except Exception as e:
                return jsonify({"ok": False, "message": str(e)})

        @app.route("/api/disconnect", methods=["POST"])
        def api_disconnect():
            self._disconnect()
            return jsonify({"ok": True})

        @app.route("/api/demo", methods=["POST"])
        def api_demo():
            if self.demo_mode:
                self._stop_demo()
            else:
                self._start_demo()
            return jsonify({"ok": True, "active": self.demo_mode})

        @app.route("/api/alerts")
        def api_alerts():
            result = []
            for a in self.alerts:
                if isinstance(a, dict) and "time" in a:
                    result.append(a)
            return jsonify(result)

        @app.route("/api/alerts/clear", methods=["POST"])
        def api_alerts_clear():
            self._do_clear_alerts_local()
            if self.broadcast_server:
                self.broadcast_server.request_clear_alerts()
            return jsonify({"ok": True})

    # -----------------------------------------------------------------------
    # Alert management
    # -----------------------------------------------------------------------
    def _load_alerts_from_file(self):
        if not os.path.exists(ALERT_LOG):
            return
        try:
            with open(ALERT_LOG) as f:
                lines = f.readlines()
            for line in lines:
                line = line.rstrip("\n")
                if not line:
                    continue
                sev = "info"
                for key, s in (("CRITICAL:", "critical"), ("WARNING:", "warning"),
                               ("RESOLVED:", "resolved"), ("INFO:", "info")):
                    if key in line:
                        sev = s
                        break
                # Try to parse ts and message
                ts, msg = "", line
                try:
                    if line.startswith("["):
                        ts_end = line.index("]")
                        ts = line[1:ts_end]
                        msg = line[ts_end+2:]
                except Exception:
                    pass
                self.alerts.append({"time": ts, "severity": sev, "message": msg})
        except Exception:
            pass

    def _add_alert(self, severity: str, message: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {"time": ts, "severity": severity, "message": message}
        self.alerts.append(entry)
        prefix = {"critical": "CRITICAL", "warning": "WARNING",
                  "info": "INFO", "resolved": "RESOLVED"}.get(severity, "INFO")
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(ALERT_LOG, "a") as f:
                f.write(f"[{ts}] {prefix}: {message}\n")
        except Exception:
            pass
        self._push_event("alert", entry)

    def _do_clear_alerts_local(self):
        self.alerts.clear()
        try:
            with open(ALERT_LOG, "w") as f:
                f.write("")
        except Exception:
            pass
        self._push_event("clear_alerts", {})

    def _on_client_clear_alerts(self):
        self._do_clear_alerts_local()

    def _check_alerts(self, stats):
        try:
            temp_limit = int(self.config.get("temp_threshold", 82))
        except (ValueError, TypeError):
            temp_limit = 82

        temp = stats.get("cpu_temp")
        if temp is not None:
            if temp > temp_limit:
                if not self._temp_alert_active:
                    self._temp_alert_active = True
                    self._add_alert("critical",
                        f"CPU temperature is {temp}\u00b0C (above {temp_limit}\u00b0C threshold)!")
            else:
                if self._temp_alert_active:
                    self._temp_alert_active = False
                    self._add_alert("resolved", f"CPU temperature back to normal: {temp}\u00b0C")

        cpu = stats.get("cpu_percent")
        if cpu is not None:
            if cpu > 95:
                if not self._cpu_alert_active:
                    self._cpu_alert_active = True
                    self._add_alert("warning", f"CPU usage critically high: {cpu}%")
            else:
                if self._cpu_alert_active:
                    self._cpu_alert_active = False
                    self._add_alert("resolved", f"CPU usage back to normal: {cpu}%")

        mem_pct = stats.get("memory_percent")
        if mem_pct is not None:
            if mem_pct > 95:
                if not self._mem_alert_active:
                    self._mem_alert_active = True
                    self._add_alert("warning", f"Memory usage critically high: {mem_pct}%")
            else:
                if self._mem_alert_active:
                    self._mem_alert_active = False
                    self._add_alert("resolved", f"Memory usage back to normal: {mem_pct}%")

        self._process_system_alerts(stats.get("system_alerts", []))

    def _process_system_alerts(self, alerts):
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
                self._add_alert(severity, f"[TrueNAS] {msg}")
            resolved = self._seen_truenas_alerts - current_ids
            for alert_id in resolved:
                self._seen_truenas_alerts.discard(alert_id)
                self._add_alert("resolved", "[TrueNAS] Alert cleared")
        except Exception as e:
            debug(f" truenas alerts error: {e}")

    # -----------------------------------------------------------------------
    # Connection management
    # -----------------------------------------------------------------------
    def _connect(self):
        self._disconnect(update_status=False)
        c = self.config
        self._set_status("Connecting...", "connecting")
        try:
            client = TrueNASClient(
                host=c["host"], api_key=c.get("api_key", ""),
                username=c.get("username", ""), password=c.get("password", ""),
            )
            info = client.test_connection()
            self.client = client
            name = info.get("hostname", "TrueNAS") if info else "TrueNAS"
            self._set_status(f"Connected to {name}", "ok")
            self._start_polling()
        except Exception as e:
            self._set_status("Connection failed", "err")
            self._add_alert("critical", f"Connection failed: {e}")

    def _disconnect(self, update_status=True):
        self.polling = False
        if self.poll_thread and self.poll_thread.is_alive():
            self.poll_thread.join(timeout=3)
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
        self.client = None
        self.net_history_rx.clear()
        self.net_history_tx.clear()
        self.temp_history.clear()
        self._temp_alert_active = False
        self._cpu_alert_active = False
        self._mem_alert_active = False
        if update_status:
            self._set_status("Disconnected", "")

    # -----------------------------------------------------------------------
    # Poll loop
    # -----------------------------------------------------------------------
    def _start_polling(self):
        self.polling = True
        self.poll_thread = threading.Thread(target=self._poll, daemon=True)
        self.poll_thread.start()

    def _poll(self):
        backoff = 0
        fail_count = 0
        while self.polling and self.client:
            if backoff > 0:
                self._set_status(f"Reconnecting in {backoff}s…", "connecting")
                debug(f"Reconnecting in {backoff}s…")
                for _ in range(backoff * 10):
                    if not self.polling:
                        return
                    time.sleep(0.1)
                self._set_status("Reconnecting…", "connecting")
                self.client._ws = None
            try:
                stats = self.client.fetch_all_stats()
                self._process_stats(stats)
                if fail_count > 0:
                    name = stats.get("hostname", "TrueNAS")
                    self._set_status(f"Connected to {name}", "ok")
                backoff = 0
                fail_count = 0
            except Exception as e:
                fail_count += 1
                backoff = min(60, 5 * (2 ** (fail_count - 1)))
                self._set_status(f"Connection lost: {e}", "err")
                debug(f"Poll error (attempt {fail_count}): {e}")
                continue
            time.sleep(self.config.get("interval", 5))

    def _process_stats(self, stats):
        rx = float(stats.get("net_rx") or 0)
        tx = float(stats.get("net_tx") or 0)
        self.net_history_rx.append(rx)
        self.net_history_tx.append(tx)
        if len(self.net_history_rx) > self.HISTORY_LEN:
            self.net_history_rx = self.net_history_rx[-self.HISTORY_LEN:]
        if len(self.net_history_tx) > self.HISTORY_LEN:
            self.net_history_tx = self.net_history_tx[-self.HISTORY_LEN:]

        temp = stats.get("cpu_temp")
        if temp is not None:
            self.temp_history.append(temp)
            if len(self.temp_history) > self.HISTORY_LEN:
                self.temp_history = self.temp_history[-self.HISTORY_LEN:]

        # Include history in SSE push so the browser always has it
        stats["net_history_rx"] = list(self.net_history_rx)
        stats["net_history_tx"] = list(self.net_history_tx)
        stats["temp_history"] = list(self.temp_history)

        self._push_event("stats", stats)
        if self.broadcast_server:
            self.broadcast_server.send_stats({k: v for k, v in stats.items()
                                              if k not in ("net_history_rx", "net_history_tx", "temp_history")})
            n = self.broadcast_server.client_count
            port = self.config.get("broadcast_port", BROADCAST_DEFAULT_PORT)
            text = f"Broadcasting on port {port}  |  {n} client{'s' if n!=1 else ''} connected"
            self._push_event("broadcast_status", {"text": text})
        self._check_alerts(stats)

    # -----------------------------------------------------------------------
    # Demo mode
    # -----------------------------------------------------------------------
    def _start_demo(self):
        self._disconnect(update_status=False)
        self.demo_mode = True
        self.polling = True
        self._demo_cpu = 35.0
        self._demo_mem = 55.0
        self._demo_temp = 42.0
        self._demo_rx = 25_000_000.0
        self._demo_tx = 8_000_000.0
        self._set_status("Demo Mode", "demo")
        self.poll_thread = threading.Thread(target=self._demo_poll, daemon=True)
        self.poll_thread.start()

    def _stop_demo(self):
        self.demo_mode = False
        self.polling = False
        if self.poll_thread and self.poll_thread.is_alive():
            self.poll_thread.join(timeout=3)
        self.net_history_rx.clear()
        self.net_history_tx.clear()
        self.temp_history.clear()
        self._set_status("Disconnected", "")

    def _demo_poll(self):
        while self.polling and self.demo_mode:
            self._demo_cpu = max(1, min(99, self._demo_cpu + random.uniform(-8, 8)))
            self._demo_mem = max(20, min(95, self._demo_mem + random.uniform(-3, 3)))
            self._demo_temp = max(30, min(88, self._demo_temp + random.uniform(-4, 4)))
            self._demo_rx = max(0, self._demo_rx + random.uniform(-5_000_000, 5_000_000))
            self._demo_tx = max(0, self._demo_tx + random.uniform(-2_000_000, 2_000_000))
            mem_total = 34_359_738_368
            mem_used = mem_total * self._demo_mem / 100
            demo_pools = [
                {"name": "tank", "total": 8*1024**4, "used": int(5.2*1024**4),
                 "available": int(2.8*1024**4), "percent": 65.0,
                 "disks": [{"name": "sda","has_error":False},{"name":"sdb","has_error":False},
                            {"name":"sdc","has_error":False},{"name":"sdd","has_error":False}],
                 "topology": {"data": [
                   {"type":"MIRROR","status":"ONLINE","disks":[
                     {"name":"sda","status":"ONLINE","errors":0},{"name":"sdb","status":"ONLINE","errors":0}]},
                   {"type":"MIRROR","status":"ONLINE","disks":[
                     {"name":"sdc","status":"ONLINE","errors":0},{"name":"sdd","status":"ONLINE","errors":0}]}]}},
                {"name": "fast-storage", "total": 2*1024**4, "used": int(1.6*1024**4),
                 "available": int(0.4*1024**4), "percent": 80.0,
                 "disks": [{"name":"nvme0n1","has_error":False},{"name":"nvme1n1","has_error":True}],
                 "topology": {"data": [
                   {"type":"MIRROR","status":"ONLINE","disks":[
                     {"name":"nvme0n1","status":"ONLINE","errors":0},
                     {"name":"nvme1n1","status":"DEGRADED","errors":3}]}],
                   "cache": [{"type":"STRIPE","status":"ONLINE","disks":[
                     {"name":"nvme2n1","status":"ONLINE","errors":0}]}]}},
                {"name": "backup", "total": 16*1024**4, "used": int(14.5*1024**4),
                 "available": int(1.5*1024**4), "percent": 90.6,
                 "disks": [{"name":f"sd{c}","has_error":False} for c in "efghij"],
                 "topology": {"data": [{"type":"RAIDZ2","status":"ONLINE","disks":[
                   {"name":f"sd{c}","status":"ONLINE","errors":0} for c in "efghij"]}],
                   "spare": [{"type":"DISK","status":"ONLINE","disks":[
                     {"name":"sdk","status":"ONLINE","errors":0}]}]}},
            ]
            stats = {
                "cpu_percent": round(self._demo_cpu, 1),
                "memory_used": mem_used, "memory_total": mem_total,
                "memory_percent": round(self._demo_mem, 1),
                "cpu_temp": round(self._demo_temp, 1),
                "net_rx": self._demo_rx, "net_tx": self._demo_tx,
                "net_iface": "eno1", "hostname": "truenas-demo",
                "version": "TrueNAS-SCALE-24.10", "uptime": "14 days, 7:32:15",
                "loadavg": [round(self._demo_cpu/25, 2), round(self._demo_cpu/30, 2),
                            round(self._demo_cpu/40, 2)],
                "pools": demo_pools, "system_alerts": [],
            }
            self._process_stats(stats)
            time.sleep(2)

    # -----------------------------------------------------------------------
    # Broadcast server
    # -----------------------------------------------------------------------
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

    def _on_broadcast_security_event(self, level: str, ip: str, message: str):
        if level == "info" and not message.startswith("Authenticated"):
            return
        now = datetime.now()
        key = f"{ip}:{level}"
        last = self._connect_alert_times.get(key)
        if last and (now - last).total_seconds() < 300:
            return
        self._connect_alert_times[key] = now
        self._add_alert(level, message)

    # -----------------------------------------------------------------------
    # Run servers
    # -----------------------------------------------------------------------
    def run(self):
        web_host = self.config.get("web_host", WEB_DEFAULT_HOST)
        web_port = self.config.get("web_port", WEB_DEFAULT_PORT)
        https_port = web_port + 1

        print(f"\nTrueMonitor Web v{APP_VERSION}")
        print(f"  HTTP:  http://localhost:{web_port}")
        print(f"  HTTPS: https://localhost:{https_port}")
        print(f"\nPress Ctrl+C to stop.\n")

        # Try to generate SSL cert for HTTPS
        try:
            cert_file, key_file = _ensure_ssl_cert()
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(cert_file, key_file)
            ssl_available = True
        except Exception as e:
            debug(f"SSL setup failed: {e}")
            ssl_available = False
            print(f"  (HTTPS unavailable: {e})\n")

        # Open browser after a short delay
        def _open():
            time.sleep(1.5)
            try:
                webbrowser.open(f"http://localhost:{web_port}")
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

        # Run HTTPS in background thread
        if ssl_available:
            def _run_https():
                try:
                    self.flask_app.run(
                        host=web_host, port=https_port, threaded=True,
                        use_reloader=False, ssl_context=ssl_ctx,
                    )
                except Exception as e:
                    debug(f"HTTPS server error: {e}")
            threading.Thread(target=_run_https, daemon=True).start()

        # Run HTTP in main thread
        self.flask_app.run(
            host=web_host, port=web_port, threaded=True, use_reloader=False,
        )

    def shutdown(self):
        self.polling = False
        self.demo_mode = False
        if self.broadcast_server:
            self.broadcast_server.stop()
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(DEBUG_LOG, "w") as f:
        f.write("")

    app = TrueMonitorWebApp()

    def _shutdown(sig, frame):
        print("\nShutting down...")
        app.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        app.run()
    except KeyboardInterrupt:
        app.shutdown()


if __name__ == "__main__":
    main()
