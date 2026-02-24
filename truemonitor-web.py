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

APP_VERSION = "0.5"
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
                    wait = self._backoff_remaining(ip)
                    if wait > 0:
                        conn.close()
                        continue
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
<style>
:root {
  --bg: #1a1a2e; --card: #16213e; --card-border: #0f3460;
  --text: #e0e0e0; --text-dim: #888899; --accent: #4fc3f7;
  --good: #66bb6a; --warning: #ffa726; --critical: #ef5350;
  --input-bg: #0f3460; --button: #533483; --button-hover: #6a42a0;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: Helvetica, Arial, sans-serif;
       font-size: 14px; min-height: 100vh; }
a { color: var(--accent); }

/* Header */
#header { display: flex; align-items: center; padding: 10px 16px 8px;
          gap: 8px; border-bottom: 1px solid var(--card-border); }
#header h1 { color: var(--accent); font-size: 20px; font-weight: bold; }
#header .version { color: var(--text-dim); font-size: 11px; margin-top: 4px; }
#status-badge { margin-left: auto; padding: 4px 12px; border-radius: 4px;
                font-size: 12px; background: var(--card); }
#status-badge.ok { color: var(--good); }
#status-badge.err { color: var(--critical); }
#status-badge.connecting { color: var(--warning); }
#status-badge.demo { color: var(--warning); }

/* Tabs */
#tab-bar { display: flex; background: var(--card); border-bottom: 1px solid var(--card-border); }
.tab-btn { padding: 10px 24px; cursor: pointer; border: none; background: none;
           color: var(--text-dim); font-size: 13px; font-family: inherit; transition: 0.15s; }
.tab-btn:hover { color: var(--text); background: var(--card-border); }
.tab-btn.active { color: var(--accent); border-bottom: 2px solid var(--accent); }
.tab-btn .badge { display: inline-block; background: var(--critical); color: #fff;
                  border-radius: 10px; padding: 1px 6px; font-size: 10px; margin-left: 4px; }

/* Tab panels */
.tab-panel { display: none; }
.tab-panel.active { display: block; }

/* Info bar */
#info-bar { background: var(--card); border: 1px solid var(--card-border);
            padding: 8px 14px; margin: 8px; border-radius: 4px;
            font-size: 12px; color: var(--text); }

/* Cards grid */
.cards-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
              padding: 8px 16px; }
.card { background: var(--card); border: 1px solid var(--card-border);
        border-radius: 4px; padding: 16px 18px; }
.card-title { color: var(--accent); font-size: 13px; font-weight: bold; margin-bottom: 10px; }
.card-value { font-size: 28px; font-weight: bold; color: var(--text); margin-bottom: 4px; }
.card-sub { font-size: 11px; color: var(--text-dim); margin-bottom: 10px; }
.progress-track { background: var(--input-bg); border-radius: 3px; height: 16px;
                  overflow: hidden; margin-top: 8px; }
.progress-fill { height: 100%; border-radius: 3px; transition: width 0.4s, background 0.4s;
                 background: var(--accent); width: 0%; }

/* Graph card header row */
.graph-header { display: flex; align-items: center; margin-bottom: 6px; }
.graph-header .card-title { margin-bottom: 0; flex: 1; }
.legend { display: flex; gap: 10px; font-size: 11px; color: var(--text-dim); }
.legend-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%;
              margin-right: 3px; vertical-align: middle; }

/* Speed row */
.speed-row { display: flex; align-items: center; gap: 16px; margin-bottom: 6px; }
.speed-rx { font-size: 15px; font-weight: bold; color: var(--good); }
.speed-tx { font-size: 15px; font-weight: bold; color: var(--accent); }
.iface-lbl { font-size: 11px; color: var(--text-dim); margin-left: auto; }

/* Canvases */
.graph-canvas { width: 100%; height: 120px; background: #0a1628;
                border-radius: 3px; display: block; }
.scale-lbl { text-align: right; font-size: 10px; color: var(--text-dim); margin-top: 2px; }

/* Temp card */
.temp-row { display: flex; align-items: baseline; gap: 12px; margin-bottom: 6px; }
.temp-val { font-size: 28px; font-weight: bold; }
.temp-status { font-size: 13px; }
.temp-range { font-size: 11px; color: var(--text-dim); margin-left: auto; }

/* Pool cards */
#pool-section { padding: 0 16px 16px; }
.pool-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.pool-card { background: var(--card); border: 1px solid var(--card-border);
             border-radius: 4px; padding: 14px 18px; }
.pool-title-row { display: flex; align-items: center; margin-bottom: 8px; }
.pool-name { color: var(--accent); font-size: 13px; font-weight: bold; flex: 1; }
.map-btn { background: var(--button); color: var(--text); border: none; border-radius: 3px;
           padding: 3px 10px; font-size: 11px; cursor: pointer; font-family: inherit; }
.map-btn:hover { background: var(--button-hover); }
.disk-row { display: flex; align-items: center; gap: 4px; margin-top: 10px; flex-wrap: wrap; }
.disk-lbl { font-size: 11px; color: var(--text-dim); margin-right: 4px; }
.disk-ind { width: 12px; height: 18px; border-radius: 2px; display: inline-block;
            cursor: default; position: relative; margin: 0 3px; }
.disk-ind:hover::after { content: attr(title); position: absolute; bottom: 22px; left: 50%;
  transform: translateX(-50%); background: #333344; color: var(--text); padding: 2px 6px;
  border-radius: 3px; font-size: 10px; white-space: nowrap; z-index: 100; pointer-events: none; }

/* Alerts tab */
#alerts-header { display: flex; align-items: center; padding: 10px 16px; gap: 12px; }
#alerts-header h2 { color: var(--accent); font-size: 15px; }
#alert-count-lbl { font-size: 12px; color: var(--text-dim); }
#clear-btn { margin-left: auto; background: var(--card); color: var(--text); border: none;
             border-radius: 3px; padding: 5px 14px; font-size: 12px; cursor: pointer;
             font-family: inherit; }
#clear-btn:hover { background: var(--card-border); }
#alert-log { background: var(--card); border: 1px solid var(--card-border);
             border-radius: 4px; margin: 0 16px 16px; padding: 10px;
             height: calc(100vh - 200px); overflow-y: auto; font-family: monospace;
             font-size: 12px; line-height: 1.6; }
.alert-entry { padding: 2px 0; border-bottom: 1px solid #1e2a4a; }
.alert-ts { color: var(--text-dim); }
.alert-critical { color: var(--critical); }
.alert-warning { color: var(--warning); }
.alert-info { color: var(--accent); }
.alert-resolved { color: var(--good); }

/* Settings tab */
#settings-panel { padding: 20px 28px; max-width: 600px; }
.settings-section { color: var(--accent); font-size: 15px; font-weight: bold;
                    margin: 0 0 16px; }
.settings-divider { color: var(--text-dim); font-size: 11px; margin: 16px 0 14px;
                    text-align: center; border-top: 1px solid var(--card-border); padding-top: 10px; }
.settings-row { display: grid; grid-template-columns: 200px 1fr; gap: 10px;
                align-items: center; margin-bottom: 10px; }
.settings-label { color: var(--text); font-size: 13px; }
.settings-input { background: var(--input-bg); color: var(--text); border: none;
                  border-radius: 3px; padding: 7px 10px; font-size: 13px;
                  font-family: inherit; width: 100%; }
.settings-input:focus { outline: 1px solid var(--accent); }
.settings-select { background: var(--input-bg); color: var(--text); border: none;
                   border-radius: 3px; padding: 7px 10px; font-size: 13px;
                   font-family: inherit; width: 130px; }
.settings-note { font-size: 11px; color: var(--text-dim); margin-top: 2px; }
#broadcast-status { font-size: 11px; color: var(--text-dim); margin: 4px 0 10px 200px; }
.btn-row { display: flex; gap: 14px; margin-top: 24px; }
.btn-primary { background: #fff; color: #000; border: none; border-radius: 3px;
               padding: 9px 22px; font-size: 13px; font-weight: bold; cursor: pointer;
               font-family: inherit; }
.btn-primary:hover { background: #e0e0e0; }
.btn-primary:disabled { opacity: 0.4; cursor: default; }
.btn-secondary { background: #fff; color: #000; border: none; border-radius: 3px;
                 padding: 9px 22px; font-size: 13px; cursor: pointer; font-family: inherit; }
.btn-secondary:hover { background: #e0e0e0; }
.btn-secondary:disabled { opacity: 0.4; cursor: default; }
.btn-demo { background: var(--warning); color: #1a1a2e; border: none; border-radius: 3px;
            padding: 9px 22px; font-size: 13px; font-weight: bold; cursor: pointer;
            font-family: inherit; }
.btn-demo:hover { background: #ffb74d; }
.key-row { display: flex; gap: 6px; align-items: center; }
.key-show-btn { background: var(--card); color: var(--text); border: none; border-radius: 3px;
                padding: 6px 10px; font-size: 11px; cursor: pointer; font-family: inherit; white-space: nowrap; }

/* Footer */
#footer { padding: 6px 16px; font-size: 11px; color: var(--text-dim);
          border-top: 1px solid var(--card-border); }

/* Drive map modal */
#modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7);
                 z-index: 1000; justify-content: center; align-items: flex-start;
                 padding-top: 40px; }
#modal-overlay.open { display: flex; }
#modal-box { background: var(--bg); border: 1px solid var(--card-border); border-radius: 6px;
             width: min(680px, 95vw); max-height: 80vh; overflow-y: auto; padding: 20px; }
#modal-title { color: var(--accent); font-size: 17px; font-weight: bold; margin-bottom: 16px; }
.vdev-group-label { color: var(--accent); font-size: 13px; font-weight: bold;
                    margin: 12px 0 6px; }
.vdev-box { background: var(--card); border: 1px solid var(--card-border); border-radius: 4px;
            padding: 10px 12px; margin-bottom: 8px; }
.vdev-hdr { display: flex; align-items: center; margin-bottom: 8px; }
.vdev-type { font-size: 12px; font-weight: bold; color: var(--accent); flex: 1; }
.vdev-status { font-size: 11px; }
.disk-cards { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.disk-card { border-radius: 3px; padding: 5px 10px; text-align: center; min-width: 70px; }
.disk-card-name { font-size: 11px; font-weight: bold; }
.disk-card-status { font-size: 10px; margin-top: 2px; }
.disk-connector { font-size: 14px; color: var(--card-border); }
#modal-close { background: var(--button); color: var(--text); border: none; border-radius: 3px;
               padding: 8px 20px; font-size: 13px; cursor: pointer; margin-top: 16px;
               font-family: inherit; }
#modal-close:hover { background: var(--button-hover); }
</style>
</head>
<body>

<div id="header">
  <h1>TrueMonitor</h1>
  <span class="version">v{{VERSION}}</span>
  <span id="status-badge">Disconnected</span>
  <a href="/logout" style="margin-left:12px;font-size:12px;color:var(--text-dim);text-decoration:none" title="Sign out">Logout</a>
</div>

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
    <div class="card">
      <div class="card-title">CPU Usage</div>
      <div class="card-value" id="cpu-val">--</div>
      <div class="card-sub" id="cpu-sub"></div>
      <div class="progress-track"><div class="progress-fill" id="cpu-bar"></div></div>
    </div>
    <!-- Memory -->
    <div class="card">
      <div class="card-title">Memory</div>
      <div class="card-value" id="mem-val">--</div>
      <div class="card-sub" id="mem-sub"></div>
      <div class="progress-track"><div class="progress-fill" id="mem-bar"></div></div>
    </div>
    <!-- Network -->
    <div class="card">
      <div class="graph-header">
        <div class="card-title">Network</div>
        <div class="legend">
          <span><span class="legend-dot" style="background:var(--good)"></span>In</span>
          <span><span class="legend-dot" style="background:var(--accent)"></span>Out</span>
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
    <div class="card">
      <div class="graph-header"><div class="card-title">CPU Temperature</div></div>
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
    <h2>Alert Log</h2>
    <span id="alert-count-lbl">0 alerts</span>
    <button id="clear-btn" onclick="clearAlerts()">Clear All</button>
  </div>
  <div id="alert-log"></div>
</div>

<!-- SETTINGS TAB -->
<div id="tab-settings" class="tab-panel">
  <div id="settings-panel">
    <div class="settings-section">Connection Settings</div>
    <div class="settings-row">
      <label class="settings-label">IP Address / Hostname:</label>
      <input class="settings-input" id="s-host" type="text" placeholder="192.168.1.100">
    </div>
    <div class="settings-row">
      <label class="settings-label">API Key:</label>
      <div class="key-row">
        <input class="settings-input" id="s-apikey" type="password" placeholder="API key">
        <button class="key-show-btn" onclick="toggleShow('s-apikey',this)">Show</button>
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
        <button class="key-show-btn" onclick="toggleShow('s-pass',this)">Show</button>
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
      <input type="checkbox" id="s-bcast-enabled" style="width:16px;height:16px;accent-color:var(--accent)">
    </div>
    <div class="settings-row">
      <label class="settings-label">Broadcast Port:</label>
      <input class="settings-input" id="s-bcast-port" type="number" min="1024" max="65535" style="width:100px">
    </div>
    <div class="settings-row">
      <label class="settings-label">Shared Key:</label>
      <div class="key-row">
        <input class="settings-input" id="s-bcast-key" type="password">
        <button class="key-show-btn" onclick="toggleShow('s-bcast-key',this)">Show</button>
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
      <input class="settings-input" id="s-https-port" type="text" readonly style="width:100px;opacity:0.6">
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
        <button class="key-show-btn" onclick="toggleShow('s-web-pass',this)">Show</button>
      </div>
    </div>
    <div class="settings-row">
      <label class="settings-label">Confirm Password:</label>
      <input class="settings-input" id="s-web-pass2" type="password" placeholder="confirm new password">
    </div>

    <div class="btn-row">
      <button class="btn-primary" id="save-btn" onclick="saveSettings()">Save &amp; Connect</button>
      <button class="btn-secondary" id="disc-btn" onclick="disconnectNow()" disabled>Disconnect</button>
      <button class="btn-demo" id="demo-btn" onclick="toggleDemo()">Demo Mode</button>
    </div>
    <div id="settings-msg" style="margin-top:12px;font-size:12px;color:var(--text-dim)"></div>
  </div>
</div>

<div id="footer"></div>

<!-- Drive Map Modal -->
<div id="modal-overlay" onclick="closeModal(event)">
  <div id="modal-box">
    <div id="modal-title"></div>
    <div id="modal-content"></div>
    <button id="modal-close" onclick="closeModalBtn()">Close</button>
  </div>
</div>

<script>
const HISTORY_LEN = 60;
let netRxHist = [], netTxHist = [], tempHist = [];
let alertCount = 0, unreadAlerts = 0;
let currentTab = 'monitor';
let demoActive = false;
let connected = false;

// --- SSE ---
let sseSource = null;
function connectSSE() {
  if (sseSource) { try { sseSource.close(); } catch(e){} }
  sseSource = new EventSource('/events');
  sseSource.addEventListener('stats', e => { const d = JSON.parse(e.data); handleStats(d); });
  sseSource.addEventListener('alert', e => { const d = JSON.parse(e.data); appendAlert(d); });
  sseSource.addEventListener('clear_alerts', () => { clearAlertsUI(); });
  sseSource.addEventListener('status', e => { const d = JSON.parse(e.data); setStatus(d.text, d.state); });
  sseSource.addEventListener('broadcast_status', e => {
    const d = JSON.parse(e.data);
    document.getElementById('broadcast-status').textContent = d.text;
  });
  sseSource.onerror = () => { setStatus('Reconnecting\u2026', 'connecting'); setTimeout(connectSSE, 3000); };
}

// --- Status badge ---
function setStatus(text, state) {
  const el = document.getElementById('status-badge');
  el.textContent = text;
  el.className = state || '';
  connected = (state === 'ok');
  document.getElementById('disc-btn').disabled = !connected;
  document.getElementById('save-btn').disabled = demoActive;
}

// --- Tab switching ---
function showTab(name) {
  currentTab = name;
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.querySelector(`[onclick="showTab('${name}')"]`).classList.add('active');
  if (name === 'alerts') { unreadAlerts = 0; updateAlertBadge(); }
  if (name === 'settings') { loadSettingsForm(); }
}

// --- Alert badge ---
function updateAlertBadge() {
  const badge = document.getElementById('alert-badge');
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
  const la = (s.loadavg || []).map(v => v.toFixed(2)).join(', ');
  document.getElementById('info-bar').textContent =
    `${s.hostname||'N/A'}  |  ${s.version||'N/A'}  |  Uptime: ${s.uptime||'N/A'}  |  Load: ${la||'N/A'}`;
}

function colorFor(pct, t1, t2) {
  return pct < t1 ? 'var(--good)' : pct < t2 ? 'var(--warning)' : 'var(--critical)';
}

function updateCpu(cpu, la) {
  const v = document.getElementById('cpu-val');
  const b = document.getElementById('cpu-bar');
  const s = document.getElementById('cpu-sub');
  if (cpu != null) {
    const c = colorFor(cpu, 70, 90);
    v.textContent = cpu + '%'; v.style.color = c;
    b.style.width = cpu + '%'; b.style.background = c;
    const la_s = (la||[]).map(x=>x.toFixed(2)).join(', ');
    s.textContent = 'Load avg: ' + la_s;
  } else { v.textContent = 'N/A'; v.style.color = 'var(--text-dim)'; }
}

function updateMem(mu, mt, mp) {
  const v = document.getElementById('mem-val');
  const b = document.getElementById('mem-bar');
  const s = document.getElementById('mem-sub');
  if (mp != null) {
    const c = colorFor(mp, 70, 90);
    v.textContent = mp + '%'; v.style.color = c;
    b.style.width = mp + '%'; b.style.background = c;
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
  const v = document.getElementById('temp-val');
  const st = document.getElementById('temp-status');
  const rng = document.getElementById('temp-range');
  if (temp != null) {
    const c = colorFor(temp, 60, 80);
    const lbl = temp < 60 ? 'Normal' : temp < 80 ? 'Warm' : 'Hot!';
    v.textContent = temp + '\u00b0C'; v.style.color = c;
    st.textContent = lbl; st.style.color = c;
    if (tempHist.length > 0) {
      const lo = Math.min(...tempHist), hi = Math.max(...tempHist);
      rng.textContent = `Low: ${lo.toFixed(0)}\u00b0C  High: ${hi.toFixed(0)}\u00b0C`;
    }
    drawTempGraph();
  } else { v.textContent = 'N/A'; v.style.color = 'var(--text-dim)'; st.textContent = ''; }
}

// --- Canvas graphs ---
function drawNetGraph() {
  const canvas = document.getElementById('net-canvas');
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext('2d');
  const all = netRxHist.concat(netTxHist);
  let maxVal = Math.max(...all, 1);
  const n = HISTORY_LEN, graphH = h - 2;

  ctx.strokeStyle = '#1a2a4a'; ctx.setLineDash([2,4]);
  for (let i=1;i<4;i++) {
    const y = Math.floor(graphH*i/4);
    ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke();
  }
  ctx.setLineDash([]);

  function drawLine(data, color) {
    if (data.length < 2) return;
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
    data.forEach((v,i) => {
      const x = n>1 ? w*i/(n-1) : 0;
      let y = graphH - (v/maxVal)*(graphH-4) - 2;
      y = Math.max(2, Math.min(graphH-2, y));
      i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
    });
    ctx.stroke();
  }
  drawLine(netRxHist, '#66bb6a');
  drawLine(netTxHist, '#4fc3f7');
  document.getElementById('net-scale').textContent = 'Peak: ' + formatBytes(maxVal, true);
}

function drawTempGraph() {
  const canvas = document.getElementById('temp-canvas');
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext('2d');
  if (!tempHist.length) return;

  const tMin=20, tMax=100, tRange=tMax-tMin;
  const graphH = h-2;
  const n = HISTORY_LEN;
  function yFor(t) { return Math.floor(graphH - ((t-tMin)/tRange)*(graphH-4) - 2); }

  const yHot = yFor(80), yWarm = yFor(60);
  ctx.fillStyle='#2a1015'; ctx.fillRect(0,0,w,yHot);
  ctx.fillStyle='#2a2010'; ctx.fillRect(0,yHot,w,yWarm-yHot);

  ctx.strokeStyle='#ef5350'; ctx.setLineDash([3,3]);
  ctx.beginPath(); ctx.moveTo(0,yHot); ctx.lineTo(w,yHot); ctx.stroke();
  ctx.fillStyle='#ef5350'; ctx.font='9px Helvetica'; ctx.textAlign='right';
  ctx.fillText('80\u00b0C', w-2, yHot-4);

  ctx.strokeStyle='#ffa726';
  ctx.beginPath(); ctx.moveTo(0,yWarm); ctx.lineTo(w,yWarm); ctx.stroke();
  ctx.fillStyle='#ffa726';
  ctx.fillText('60\u00b0C', w-2, yWarm-4);
  ctx.setLineDash([]);

  const latest = tempHist[tempHist.length-1];
  const lineColor = latest < 60 ? '#66bb6a' : latest < 80 ? '#ffa726' : '#ef5350';
  ctx.strokeStyle = lineColor; ctx.lineWidth = 2; ctx.beginPath();
  tempHist.forEach((v,i) => {
    const x = n>1 ? w*i/(n-1) : 0;
    let y = yFor(v); y = Math.max(2, Math.min(graphH-2, y));
    i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
  });
  ctx.stroke();
}

// --- Pool cards ---
let _poolState = {};
function updatePools(pools) {
  const grid = document.getElementById('pool-grid');
  const names = pools.map(p=>p.name);
  // Remove stale cards
  Object.keys(_poolState).forEach(n => { if (!names.includes(n)) {
    const el = document.getElementById('pool-card-'+n); if (el) el.remove();
    delete _poolState[n];
  }});
  pools.forEach((pool, idx) => {
    const n = pool.name;
    let card = document.getElementById('pool-card-'+n);
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
  const n = pool.name;
  const div = document.createElement('div');
  div.className = 'pool-card'; div.id = 'pool-card-'+n;
  div.innerHTML = `
    <div class="pool-title-row">
      <span class="pool-name">Pool: ${esc(n)}</span>
      <button class="map-btn" onclick='showDriveMap(${JSON.stringify(n)})'>Drive Map</button>
    </div>
    <div class="card-value" id="pv-${n}">--</div>
    <div class="card-sub" id="ps-${n}"></div>
    <div class="progress-track"><div class="progress-fill" id="pb-${n}"></div></div>
    <div class="disk-row">
      <span class="disk-lbl">Disks:</span>
      <span id="pd-${n}"></span>
    </div>`;
  return div;
}

function updatePoolCard(card, pool) {
  const n = pool.name, pct = pool.percent||0;
  const c = pct < 70 ? 'var(--good)' : pct < 85 ? 'var(--warning)' : 'var(--critical)';
  document.getElementById('pv-'+n).textContent = pct + '%';
  document.getElementById('pv-'+n).style.color = c;
  const pb = document.getElementById('pb-'+n);
  pb.style.width = pct+'%'; pb.style.background = c;
  document.getElementById('ps-'+n).textContent =
    formatBytes(pool.used) + ' / ' + formatBytes(pool.total) +
    '  (' + formatBytes(pool.available) + ' free)';
  const pd = document.getElementById('pd-'+n);
  pd.innerHTML = '';
  (pool.disks||[]).forEach(d => {
    const ind = document.createElement('span');
    ind.className = 'disk-ind';
    ind.style.background = d.has_error ? 'var(--critical)' : 'var(--good)';
    ind.title = d.name;
    pd.appendChild(ind);
  });
  // Store topology for drive map
  if (pool.topology) { window['_topo_'+n] = pool.topology; }
}

// --- Drive Map ---
function showDriveMap(name) {
  const topo = window['_topo_'+name] || {};
  document.getElementById('modal-title').textContent = 'Pool: ' + name;
  const content = document.getElementById('modal-content');
  content.innerHTML = '';

  const groupLabels = {
    data:'Data VDevs', cache:'Cache (L2ARC)', log:'Log (SLOG)',
    spare:'Hot Spares', special:'Special VDevs', dedup:'Dedup VDevs'
  };
  let hasContent = false;
  ['data','cache','log','spare','special','dedup'].forEach(gk => {
    const vdevs = topo[gk];
    if (!vdevs || !vdevs.length) return;
    hasContent = true;
    const glbl = document.createElement('div');
    glbl.className = 'vdev-group-label';
    glbl.textContent = groupLabels[gk]||gk;
    content.appendChild(glbl);

    vdevs.forEach(vdev => {
      const vtype = vdev.type||'DISK', vstatus = vdev.status||'ONLINE';
      const icon = vtype==='MIRROR'?'\u2194':vtype.startsWith('RAIDZ')?'\u2726':vtype==='STRIPE'?'\u2502':'\u25cb';
      const stColor = vstatus==='ONLINE'?'var(--good)':'var(--critical)';
      const box = document.createElement('div'); box.className = 'vdev-box';
      box.innerHTML = `<div class="vdev-hdr">
        <span class="vdev-type">${icon}  ${esc(vtype)}</span>
        <span class="vdev-status" style="color:${stColor}">${esc(vstatus)}</span>
      </div><div class="disk-cards" id="dc-tmp"></div>`;
      const dc = box.querySelector('.disk-cards');
      (vdev.disks||[]).forEach((disk, di) => {
        const hasErr = disk.errors>0 || !['ONLINE',''].includes(disk.status||'');
        const dbg = hasErr?'#5c1a1a':'#1a2a1a', dbc = hasErr?'var(--critical)':'var(--good)';
        const stTxt = disk.errors>0 ? `${disk.status} (${disk.errors} err)` : disk.status;
        if (di>0 && ['MIRROR','RAIDZ1','RAIDZ2','RAIDZ3'].includes(vtype)) {
          const conn = document.createElement('span'); conn.className='disk-connector';
          conn.textContent='\u2500\u2500'; dc.appendChild(conn);
        }
        const dcard = document.createElement('div');
        dcard.className='disk-card';
        dcard.style.cssText=`background:${dbg};border:2px solid ${dbc}`;
        dcard.innerHTML=`<div class="disk-card-name" style="color:${hasErr?'#fff':'var(--text)'}">${esc(disk.name)}</div>
          <div class="disk-card-status" style="color:${dbc}">${esc(stTxt)}</div>`;
        dc.appendChild(dcard);
      });
      content.appendChild(box);
    });
  });
  if (!hasContent) content.innerHTML = '<div style="color:var(--text-dim);padding:20px">No topology data available</div>';
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal(e) { if (e.target===document.getElementById('modal-overlay')) closeModalBtn(); }
function closeModalBtn() { document.getElementById('modal-overlay').classList.remove('open'); }

// --- Alerts ---
function appendAlert(d) {
  const log = document.getElementById('alert-log');
  const entry = document.createElement('div'); entry.className='alert-entry';
  const cls = 'alert-'+d.severity;
  const prefix = {critical:'CRITICAL',warning:'WARNING',info:'INFO',resolved:'RESOLVED'}[d.severity]||'INFO';
  entry.innerHTML = `<span class="alert-ts">[${esc(d.time)}]</span> <span class="${cls}">${prefix}:</span> ${esc(d.message)}`;
  log.insertBefore(entry, log.firstChild);
  alertCount++;
  document.getElementById('alert-count-lbl').textContent = alertCount + ' alert' + (alertCount!==1?'s':'');
  if (d.severity==='critical'||d.severity==='warning') {
    unreadAlerts++; updateAlertBadge();
    if (Notification.permission==='granted') {
      new Notification('TrueMonitor Alert', { body: prefix + ': ' + d.message, icon: '/favicon.ico' });
    }
  }
}

function clearAlertsUI() {
  document.getElementById('alert-log').innerHTML = '';
  alertCount = 0; unreadAlerts = 0;
  document.getElementById('alert-count-lbl').textContent = '0 alerts';
  updateAlertBadge();
}

function clearAlerts() {
  fetch('/api/alerts/clear', {method:'POST'}).catch(()=>{});
  clearAlertsUI();
}

// --- Settings form ---
function loadSettingsForm() {
  fetch('/api/config').then(r=>r.json()).then(cfg => {
    document.getElementById('s-host').value = cfg.host||'';
    document.getElementById('s-apikey').value = cfg.api_key||'';
    document.getElementById('s-user').value = cfg.username||'';
    document.getElementById('s-pass').value = cfg.password||'';
    document.getElementById('s-interval').value = cfg.interval||5;
    document.getElementById('s-bcast-enabled').checked = cfg.broadcast_enabled||false;
    document.getElementById('s-bcast-port').value = cfg.broadcast_port||7337;
    document.getElementById('s-bcast-key').value = cfg.broadcast_key||'truemonitor';
    document.getElementById('s-web-host').value = cfg.web_host||'0.0.0.0';
    document.getElementById('s-web-port').value = cfg.web_port||8088;
    updateHttpsPort();
    document.getElementById('s-web-user').value = cfg.web_username||'client';
    document.getElementById('s-web-pass').value = '';
    document.getElementById('s-web-pass2').value = '';
    fetch('/api/broadcast_status').then(r=>r.json()).then(d => {
      document.getElementById('broadcast-status').textContent = d.text;
    }).catch(()=>{});
  }).catch(()=>{});
}

function updateHttpsPort() {
  const p = parseInt(document.getElementById('s-web-port').value)||8088;
  document.getElementById('s-https-port').value = p + 1;
}

// Populate temp threshold dropdown
(function() {
  const sel = document.getElementById('s-temp-thresh');
  for (let t=40;t<=96;t++) {
    const opt = document.createElement('option');
    opt.value=t; opt.textContent=t+'\u00b0C'; sel.appendChild(opt);
  }
})();

function saveSettings() {
  const host = document.getElementById('s-host').value.trim();
  const apiKey = document.getElementById('s-apikey').value.trim();
  const user = document.getElementById('s-user').value.trim();
  const pass = document.getElementById('s-pass').value.trim();
  if (!host) { showMsg('Please enter an IP address or hostname.', 'critical'); return; }
  if (!apiKey && !(user && pass)) { showMsg('Provide an API key or username & password.', 'critical'); return; }
  const webUser = document.getElementById('s-web-user').value.trim();
  const webPass = document.getElementById('s-web-pass').value;
  const webPass2 = document.getElementById('s-web-pass2').value;
  if (webPass && webPass !== webPass2) {
    showMsg('New passwords do not match.', 'err'); return;
  }
  if (!webUser) { showMsg('Web username cannot be empty.', 'err'); return; }
  const body = {
    host, api_key: apiKey, username: user, password: pass,
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
    .then(r=>r.json()).then(d => {
      showMsg(d.message || 'Saved.', d.ok ? 'ok' : 'err');
    }).catch(e => showMsg('Error: '+e, 'err'));
}

function showMsg(msg, state) {
  const el = document.getElementById('settings-msg');
  el.textContent = msg;
  el.style.color = state==='ok' ? 'var(--good)' : state==='err' ? 'var(--critical)' : 'var(--text-dim)';
}

function disconnectNow() {
  fetch('/api/disconnect', {method:'POST'}).catch(()=>{});
}

function toggleDemo() {
  fetch('/api/demo', {method:'POST'}).then(r=>r.json()).then(d => {
    demoActive = d.active;
    const btn = document.getElementById('demo-btn');
    btn.textContent = demoActive ? 'Stop Demo' : 'Demo Mode';
    btn.style.background = demoActive ? 'var(--critical)' : 'var(--warning)';
    document.getElementById('save-btn').disabled = demoActive;
  }).catch(()=>{});
}

function toggleShow(id, btn) {
  const el = document.getElementById(id);
  if (el.type==='password') { el.type='text'; btn.textContent='Hide'; }
  else { el.type='password'; btn.textContent='Show'; }
}

// --- Utilities ---
function formatBytes(v, ps) {
  if (v==null) return 'N/A';
  const sfx = ps ? '/s' : '';
  for (const u of ['B','KB','MB','GB','TB']) {
    if (Math.abs(v) < 1024) return v.toFixed(1)+' '+u+sfx;
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
fetch('/api/alerts').then(r=>r.json()).then(list => {
  list.forEach(a => appendAlert(a));
}).catch(()=>{});

// Init
loadSettingsForm();
connectSSE();
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
        while self.polling and self.client:
            try:
                stats = self.client.fetch_all_stats()
                self._process_stats(stats)
            except Exception as e:
                debug(f"Poll error: {e}")
                self._push_event("status", {"text": f"Poll error: {e}", "state": "err"})
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
