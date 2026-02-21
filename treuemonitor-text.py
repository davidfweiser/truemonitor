#!/usr/bin/env python3
"""TrueMonitor v0.4 — Interactive Text Mode

Connects to TrueNAS using the same API and credentials as truemonitor.py.
Reads saved settings from ~/.config/truemonitor/config.json automatically,
or accepts command-line arguments to override them.

Usage:
    python3 treuemonitor-text.py
    python3 treuemonitor-text.py --host 192.168.1.100 --api-key YOUR_KEY
    python3 treuemonitor-text.py --host 192.168.1.100 --username admin --password secret
    python3 treuemonitor-text.py --interval 10 --temp-threshold 75

Keys:
    M        Monitor view
    A        Alerts view
    Q        Quit
    ESC / M  (in Alerts) Back to Monitor
    C        (in Alerts) Clear all alerts
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
import getpass
from datetime import datetime, timedelta, timezone
from collections import deque

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("ERROR: 'requests' package is required. Install it with:")
    print("  pip install requests")
    raise SystemExit(1)

APP_VERSION = "0.4"

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "truemonitor")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
DEBUG_LOG   = os.path.join(CONFIG_DIR, "debug.log")
ALERT_LOG   = os.path.join(CONFIG_DIR, "alerts.log")


# ---------------------------------------------------------------------------
# Helpers
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


def _decrypt(ciphertext):
    if not ciphertext:
        return ""
    try:
        f = Fernet(_get_encryption_key())
        return f.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception):
        return ciphertext


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
# TrueNAS REST API client
# ---------------------------------------------------------------------------

class TrueNASClient:
    def __init__(self, host, api_key="", username="", password=""):
        self.base_url = host.rstrip("/")
        if not self.base_url.startswith("http"):
            self.base_url = f"https://{self.base_url}"
        self.api_key  = api_key
        self.username = username
        self.password = password
        self.session  = requests.Session()
        self.session.verify = False
        self._working_report_format = None
        self._working_iface = None

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _auth(self):
        if not self.api_key and self.username and self.password:
            return (self.username, self.password)
        return None

    def _get(self, endpoint):
        url = f"{self.base_url}/api/v2.0/{endpoint}"
        r = self.session.get(url, headers=self._headers(), auth=self._auth(), timeout=10)
        r.raise_for_status()
        return r.json()

    def _post(self, endpoint, payload):
        url = f"{self.base_url}/api/v2.0/{endpoint}"
        r = self.session.post(
            url, headers=self._headers(), auth=self._auth(),
            json=payload, timeout=10,
        )
        if not r.ok:
            debug(f"POST {endpoint} => {r.status_code}: {r.text[:500]}")
        r.raise_for_status()
        return r.json()

    def test_connection(self):
        return self._get("system/info")

    def get_system_info(self):
        return self._get("system/info")

    def get_interfaces(self):
        return self._get("interface")

    def get_alerts(self):
        return self._get("alert/list")

    def get_pools(self):
        return self._get("pool")

    def get_reporting_data(self, graphs):
        now   = datetime.now(timezone.utc)
        start = now - timedelta(seconds=120)

        def _attempts():
            return [
                ("reporting/netdata/get_data", {
                    "graphs": graphs,
                    "reporting_query": {
                        "start": start.strftime("%Y-%m-%dT%H:%M:%S"),
                        "end":   now.strftime("%Y-%m-%dT%H:%M:%S"),
                        "aggregate": True,
                    },
                }),
                ("reporting/get_data", {
                    "graphs": graphs,
                    "reporting_query": {
                        "start": start.strftime("%Y-%m-%dT%H:%M:%S"),
                        "end":   now.strftime("%Y-%m-%dT%H:%M:%S"),
                        "aggregate": True,
                    },
                }),
                ("reporting/get_data", {
                    "graphs": graphs,
                    "reporting_query": {
                        "start": int(start.timestamp()),
                        "end":   int(now.timestamp()),
                        "aggregate": True,
                    },
                }),
                ("reporting/get_data",          {"graphs": graphs}),
                ("reporting/netdata/get_data",  {"graphs": graphs}),
            ]

        if self._working_report_format is not None:
            idx = self._working_report_format
            attempts = _attempts()
            try:
                ep, pl = attempts[idx]
                return self._post(ep, pl)
            except Exception:
                self._working_report_format = None

        last_err = None
        for i, (ep, pl) in enumerate(_attempts()):
            try:
                result = self._post(ep, pl)
                self._working_report_format = i
                return result
            except Exception as e:
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
            items  = report if isinstance(report, list) else []
            for item in items:
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
                               if isinstance(i, dict) and i.get("name", "") not in ("lo", "")]
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
            pools = self.get_pools()
            for p in pools:
                if not isinstance(p, dict):
                    continue
                topology  = p.get("topology", {})
                total     = p.get("size")
                allocated = p.get("allocated")
                free      = p.get("free")
                disks = []
                for topo_key in ("data", "cache", "log", "spare"):
                    for vdev in topology.get(topo_key, []):
                        if not isinstance(vdev, dict):
                            continue
                        children = vdev.get("children", [])
                        members  = children if children else [vdev]
                        for member in members:
                            if not isinstance(member, dict):
                                continue
                            disk_name = member.get("disk") or member.get("name", "")
                            if not disk_name:
                                continue
                            m_stats   = member.get("stats", {})
                            errs      = ((m_stats.get("read_errors", 0) or 0)
                                         + (m_stats.get("write_errors", 0) or 0)
                                         + (m_stats.get("checksum_errors", 0) or 0))
                            status    = member.get("status", "ONLINE")
                            has_error = errs > 0 or status not in ("ONLINE", "")
                            disks.append({"name": disk_name, "has_error": has_error})
                if total and allocated is not None:
                    pct = round(allocated / total * 100, 1) if total > 0 else 0
                    stats["pools"].append({
                        "name":      p.get("name", "unknown"),
                        "used":      allocated,
                        "available": free or (total - allocated),
                        "total":     total,
                        "percent":   pct,
                        "disks":     disks,
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
                    alert_id = alert.get("uuid") or alert.get("id") or str(alert)
                    level    = alert.get("level", "INFO").upper()
                    if level in ("CRITICAL", "ERROR"):
                        severity = "critical"
                    elif level == "WARNING":
                        severity = "warning"
                    else:
                        severity = "info"
                    msg   = alert.get("formatted", "") or alert.get("text", "")
                    klass = alert.get("klass", "")
                    if not msg:
                        msg = klass or "Unknown TrueNAS alert"
                    stats["system_alerts"].append({
                        "id": alert_id, "severity": severity, "message": msg,
                    })
        except Exception as e:
            debug(f" system alerts error: {e}")

        return stats


# ---------------------------------------------------------------------------
# Shared application state (written by poll thread, read by UI thread)
# ---------------------------------------------------------------------------

class AppState:
    def __init__(self):
        self.lock    = threading.Lock()
        self.stats   = None
        self.alerts  = deque(maxlen=200)
        self.last_updated = None
        self.last_error   = None
        self.current_view = "monitor"   # "monitor" | "alerts"
        self.unread_alerts = 0
        self._temp_alert_active = False
        self._cpu_alert_active  = False
        self._mem_alert_active  = False
        self._seen_truenas_alerts = set()

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
        with self.lock:
            self.alerts.clear()
            self.unread_alerts = 0
        try:
            with open(ALERT_LOG, "w") as f:
                f.write("")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Curses color constants (set up in init_colors)
# ---------------------------------------------------------------------------

C_ACCENT   = 1   # cyan
C_GOOD     = 2   # green
C_WARN     = 3   # yellow
C_CRIT     = 4   # red
C_DIM      = 5   # white (dimmed via A_DIM)
C_SEL      = 6   # black on cyan  (selected tab)
C_ALERT_BG = 7   # red on black   (unread badge)


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_ACCENT,   curses.COLOR_CYAN,    -1)
    curses.init_pair(C_GOOD,     curses.COLOR_GREEN,   -1)
    curses.init_pair(C_WARN,     curses.COLOR_YELLOW,  -1)
    curses.init_pair(C_CRIT,     curses.COLOR_RED,     -1)
    curses.init_pair(C_DIM,      curses.COLOR_WHITE,   -1)
    curses.init_pair(C_SEL,      curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(C_ALERT_BG, curses.COLOR_WHITE,   curses.COLOR_RED)


# ---------------------------------------------------------------------------
# Safe addstr (clips to window bounds, swallows curses.error)
# ---------------------------------------------------------------------------

def put(win, y, x, text, attr=0):
    my, mx = win.getmaxyx()
    if y < 0 or y >= my or x < 0 or x >= mx:
        return
    available = mx - x
    if available <= 0:
        return
    try:
        win.addstr(y, x, str(text)[:available], attr)
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
# Header (rows 0-3)
# ---------------------------------------------------------------------------

HEADER_ROWS = 4
NAV_ROW     = 4
SEP_ROW     = 5
CONTENT_ROW = 6


def draw_header(win, state, config):
    my, mx = win.getmaxyx()

    # Row 0 — app title
    put(win, 0, 0, f" TrueMonitor v{APP_VERSION}  —  Text Mode",
        curses.color_pair(C_ACCENT) | curses.A_BOLD)

    # Row 1 — server info
    s = state.stats
    if s:
        host   = s.get("hostname", "N/A")
        ver    = s.get("version",  "N/A")
        uptime = s.get("uptime",   "N/A")
        info   = f" {host}  |  {ver}  |  Uptime: {uptime}"
    else:
        info = f" {config.get('host', '?')}  —  connecting..."
    put(win, 1, 0, info, curses.color_pair(C_DIM) | curses.A_DIM)

    # Row 2 — update timestamp / error
    if state.last_updated:
        ts       = state.last_updated.strftime("%H:%M:%S")
        interval = config.get("interval", 5)
        row2     = f" Updated: {ts}  |  Poll: {interval}s"
        if state.last_error:
            row2 += f"  |  Error: {state.last_error[:50]}"
        put(win, 2, 0, row2, curses.color_pair(C_DIM) | curses.A_DIM)

    # Row 3 — separator
    hline(win, 3, curses.color_pair(C_DIM) | curses.A_DIM)


# ---------------------------------------------------------------------------
# Navigation bar (row 4)
# ---------------------------------------------------------------------------

def draw_nav(win, state):
    my, mx = win.getmaxyx()

    # Build tab labels
    alert_count   = len(state.alerts)
    unread        = state.unread_alerts
    alert_label   = f"Alerts ({alert_count})"
    if unread > 0:
        alert_label += f" [{unread} new]"

    tabs = [
        ("M", "Monitor", state.current_view == "monitor"),
        ("A", alert_label, state.current_view == "alerts"),
    ]

    x = 1
    for key, label, selected in tabs:
        tag = f" [{key}] {label} "
        if selected:
            put(win, NAV_ROW, x, tag, curses.color_pair(C_SEL) | curses.A_BOLD)
        else:
            put(win, NAV_ROW, x, tag, curses.color_pair(C_DIM))
        x += len(tag) + 1

    # Quit hint on right
    quit_tag = " [Q] Quit "
    put(win, NAV_ROW, mx - len(quit_tag) - 1, quit_tag, curses.color_pair(C_DIM))

    # Separator below nav
    hline(win, SEP_ROW, curses.color_pair(C_DIM) | curses.A_DIM)


# ---------------------------------------------------------------------------
# Monitor view
# ---------------------------------------------------------------------------

def _pct_attr(pct):
    if pct >= 90:
        return curses.color_pair(C_CRIT) | curses.A_BOLD
    if pct >= 70:
        return curses.color_pair(C_WARN)
    return curses.color_pair(C_GOOD)


def draw_monitor(win, state, config):
    my, mx = win.getmaxyx()
    row = CONTENT_ROW

    if state.stats is None:
        put(win, row, 2, "Connecting to TrueNAS...", curses.color_pair(C_DIM) | curses.A_DIM)
        return

    s  = state.stats
    la = s.get("loadavg", [0, 0, 0])
    la_s = "  ".join(f"{x:.2f}" for x in la) if la else "N/A"

    # --- CPU ---
    cpu = s.get("cpu_percent")
    if cpu is not None:
        marker = " !!" if cpu >= 90 else "  ~" if cpu >= 70 else "   "
        put(win, row, 0,  "  CPU Usage  ", curses.color_pair(C_DIM))
        put(win, row, 13, f"{cpu:5.1f}%  ", 0)
        put(win, row, 21, _bar(cpu), _pct_attr(cpu))
        put(win, row, 43, f" {marker}  load: {la_s}", curses.color_pair(C_DIM))
    else:
        put(win, row, 0, "  CPU Usage   N/A", curses.color_pair(C_DIM))
    row += 1

    # --- Memory ---
    mp = s.get("memory_percent")
    mu = s.get("memory_used")
    mt = s.get("memory_total")
    if mp is not None and mt:
        marker = " !!" if mp >= 90 else "  ~" if mp >= 70 else "   "
        detail = f"{format_bytes(mu)} / {format_bytes(mt)}"
        put(win, row, 0,  "  Memory     ", curses.color_pair(C_DIM))
        put(win, row, 13, f"{mp:5.1f}%  ", 0)
        put(win, row, 21, _bar(mp), _pct_attr(mp))
        put(win, row, 43, f" {marker}  {detail}", curses.color_pair(C_DIM))
    else:
        put(win, row, 0, "  Memory      N/A", curses.color_pair(C_DIM))
    row += 1

    # --- Network ---
    rx    = s.get("net_rx") or 0
    tx    = s.get("net_tx") or 0
    iface = s.get("net_iface", "")
    put(win, row, 0,  "  Network    ", curses.color_pair(C_DIM))
    put(win, row, 13, "down ", curses.color_pair(C_GOOD))
    put(win, row, 18, f"{format_bytes(rx, per_second=True):<14}", curses.color_pair(C_GOOD))
    put(win, row, 32, "  up ", curses.color_pair(C_ACCENT))
    put(win, row, 37, f"{format_bytes(tx, per_second=True):<14}", curses.color_pair(C_ACCENT))
    if iface:
        put(win, row, 51, f"[{iface}]", curses.color_pair(C_DIM) | curses.A_DIM)
    row += 1

    # --- CPU Temperature ---
    temp            = s.get("cpu_temp")
    temp_threshold  = config.get("temp_threshold", 82)
    if temp is not None:
        if temp >= 80:
            t_attr  = curses.color_pair(C_CRIT) | curses.A_BOLD
            t_label = "HOT!"
        elif temp >= 60:
            t_attr  = curses.color_pair(C_WARN)
            t_label = "Warm"
        else:
            t_attr  = curses.color_pair(C_GOOD)
            t_label = "Normal"
        put(win, row, 0,  "  CPU Temp   ", curses.color_pair(C_DIM))
        put(win, row, 13, f"{temp:.1f}\u00b0C", t_attr)
        put(win, row, 21, f"  ({t_label})", t_attr)
        if temp >= temp_threshold:
            put(win, row, 32, "  \u26a0 ALERT",
                curses.color_pair(C_CRIT) | curses.A_BOLD)
    else:
        put(win, row, 0, "  CPU Temp    N/A", curses.color_pair(C_DIM))
    row += 1

    # --- Storage Pools ---
    pools = s.get("pools", [])
    if pools and row < my - 2:
        row += 1
        put(win, row, 0, "  STORAGE POOLS",
            curses.color_pair(C_ACCENT) | curses.A_BOLD)
        row += 1
        hline(win, row, curses.color_pair(C_DIM) | curses.A_DIM)
        row += 1

        for pool in pools:
            if row >= my - 2:
                break
            name  = pool.get("name", "?")
            pct   = pool.get("percent", 0)
            used  = pool.get("used", 0)
            total = pool.get("total", 0)
            avail = pool.get("available", 0)
            marker = "  !!" if pct >= 85 else "   ~" if pct >= 70 else "    "
            detail = f"{format_bytes(used)} / {format_bytes(total)}  ({format_bytes(avail)} free)"

            put(win, row, 0,  f"  Pool: {name:<14}", curses.color_pair(C_ACCENT))
            put(win, row, 22, f" {pct:5.1f}%  ", 0)
            put(win, row, 31, _bar(pct, 16), _pct_attr(pct))
            put(win, row, 49, f"{marker}  {detail}", curses.color_pair(C_DIM))
            row += 1

            if row < my - 2:
                disks = pool.get("disks", [])
                if disks:
                    put(win, row, 4, "Disks: ", curses.color_pair(C_DIM) | curses.A_DIM)
                    dx = 11
                    for d in disks:
                        name_s = d["name"]
                        flag   = "ERR" if d["has_error"] else "ok"
                        tag    = f"{name_s}[{flag}] "
                        attr   = (curses.color_pair(C_CRIT) | curses.A_BOLD
                                  if d["has_error"] else curses.color_pair(C_GOOD))
                        put(win, row, dx, tag, attr)
                        dx += len(tag)
                    row += 1


# ---------------------------------------------------------------------------
# Alerts view
# ---------------------------------------------------------------------------

SEV_ATTR = {
    "critical": lambda: curses.color_pair(C_CRIT) | curses.A_BOLD,
    "warning":  lambda: curses.color_pair(C_WARN) | curses.A_BOLD,
    "info":     lambda: curses.color_pair(C_ACCENT),
    "resolved": lambda: curses.color_pair(C_GOOD),
}
SEV_LABEL = {
    "critical": "CRITICAL", "warning": "WARNING",
    "info":     "INFO",     "resolved": "RESOLVED",
}


def draw_alerts(win, state):
    my, mx = win.getmaxyx()

    # Bottom hint bar
    hint = " [ESC] or [M] Monitor   [C] Clear All "
    hline(win, my - 2, curses.color_pair(C_DIM) | curses.A_DIM)
    put(win, my - 1, 0, hint, curses.color_pair(C_ACCENT) | curses.A_BOLD)

    visible = my - CONTENT_ROW - 2  # rows available for alert list
    with state.lock:
        alert_list = list(state.alerts)

    if not alert_list:
        put(win, CONTENT_ROW, 2, "No alerts yet.", curses.color_pair(C_DIM) | curses.A_DIM)
        return

    # Show newest at top
    display = list(reversed(alert_list[-visible:])) if len(alert_list) > visible else list(reversed(alert_list))

    for i, a in enumerate(display):
        row = CONTENT_ROW + i
        if row >= my - 2:
            break
        if "time" in a:
            sev    = a.get("severity", "info")
            label  = SEV_LABEL.get(sev, "INFO")
            s_attr = SEV_ATTR.get(sev, lambda: 0)()
            ts_str = f" [{a['time']}] "
            put(win, row, 0,          ts_str,          curses.color_pair(C_DIM) | curses.A_DIM)
            put(win, row, len(ts_str), f"{label}: ",   s_attr)
            msg_x = len(ts_str) + len(label) + 2
            msg   = a.get("message", "")
            put(win, row, msg_x, msg, 0)
        elif "raw" in a:
            put(win, row, 1, a["raw"], curses.color_pair(C_DIM) | curses.A_DIM)


# ---------------------------------------------------------------------------
# Monitor hint bar (bottom of monitor view)
# ---------------------------------------------------------------------------

def draw_monitor_hint(win, state):
    my, mx = win.getmaxyx()
    unread = state.unread_alerts
    if unread > 0:
        hint = f" [A] Alerts  ({unread} unread) "
        put(win, my - 1, 0, hint, curses.color_pair(C_ALERT_BG) | curses.A_BOLD)
    else:
        hint = " [A] Alerts   [Q] Quit "
        put(win, my - 1, 0, hint, curses.color_pair(C_DIM) | curses.A_DIM)


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
        except Exception as e:
            with state.lock:
                state.last_error = str(e)
            debug(f"poll error: {e}")

        stop_event.wait(interval)


# ---------------------------------------------------------------------------
# Main curses loop
# ---------------------------------------------------------------------------

def run_ui(stdscr, client, state, config):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(200)   # refresh every 200 ms
    init_colors()

    while True:
        key = stdscr.getch()

        # --- keyboard handling ---
        if key in (ord("q"), ord("Q")):
            break
        elif key in (ord("m"), ord("M")):
            with state.lock:
                state.current_view  = "monitor"
                state.unread_alerts = 0
        elif key in (ord("a"), ord("A")):
            with state.lock:
                state.current_view  = "alerts"
                state.unread_alerts = 0
        elif state.current_view == "alerts":
            if key == 27:   # ESC
                with state.lock:
                    state.current_view  = "monitor"
                    state.unread_alerts = 0
            elif key in (ord("c"), ord("C")):
                state.clear_alerts()

        # --- render ---
        stdscr.erase()
        draw_header(stdscr, state, config)
        draw_nav(stdscr, state)

        view = state.current_view
        if view == "monitor":
            draw_monitor(stdscr, state, config)
            draw_monitor_hint(stdscr, state)
        elif view == "alerts":
            draw_alerts(stdscr, state)

        stdscr.refresh()


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

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
            "Keys: M=Monitor  A=Alerts  Q=Quit\n"
            "      In Alerts: ESC/M=Back  C=Clear"
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
    if args.host:           config["host"]           = args.host
    if args.api_key:        config["api_key"]         = args.api_key
    if args.username:       config["username"]        = args.username
    if args.password:       config["password"]        = args.password
    if args.interval:       config["interval"]        = max(2, args.interval)
    if args.temp_threshold: config["temp_threshold"]  = args.temp_threshold

    if not config.get("host"):
        parser.error(
            "No TrueNAS host configured.\n"
            "Use --host, or run truemonitor.py first to save settings."
        )
    if not config.get("api_key") and not (config.get("username") and config.get("password")):
        parser.error(
            "No credentials configured.\n"
            "Use --api-key or --username/--password, or run truemonitor.py first."
        )

    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(DEBUG_LOG, "w") as f:
        f.write("")

    # Connect before entering curses so errors print normally
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
        time.sleep(0.4)
    except Exception as e:
        print(f"Connection failed: {e}")
        raise SystemExit(1)

    state      = AppState()
    stop_event = threading.Event()

    poll_thread = threading.Thread(
        target=poll_loop, args=(client, state, config, stop_event), daemon=True)
    poll_thread.start()

    try:
        curses.wrapper(run_ui, client, state, config)
    finally:
        stop_event.set()
        poll_thread.join(timeout=3)


if __name__ == "__main__":
    main()
