#!/usr/bin/env python3
"""TrueMonitor v0.4 — Text Mode (terminal output, no GUI)

Connects to TrueNAS using the same API and credentials as truemonitor.py.
Reads saved settings from ~/.config/truemonitor/config.json automatically,
or accepts command-line arguments to override them.

Usage:
    python3 treuemonitor-text.py
    python3 treuemonitor-text.py --host 192.168.1.100 --api-key YOUR_KEY
    python3 treuemonitor-text.py --host 192.168.1.100 --username admin --password secret
    python3 treuemonitor-text.py --interval 10 --temp-threshold 75
"""

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
DEBUG_LOG = os.path.join(CONFIG_DIR, "debug.log")
ALERT_LOG = os.path.join(CONFIG_DIR, "alerts.log")


# ---------------------------------------------------------------------------
# Helpers (shared with truemonitor.py)
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
        return ciphertext  # fallback: treat as plaintext (old config)


def format_bytes(val, per_second=False):
    if val is None:
        return "N/A"
    suffix = "/s" if per_second else ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(val) < 1024.0:
            return f"{val:.1f} {unit}{suffix}"
        val /= 1024.0
    return f"{val:.1f} PB{suffix}"


def _progress_bar(pct, width=20):
    """Return an ASCII progress bar like [=======>             ]."""
    filled = max(0, min(width, int(pct / 100 * width)))
    return "[" + "=" * filled + " " * (width - filled) + "]"


# ---------------------------------------------------------------------------
# TrueNAS REST API client (identical to truemonitor.py)
# ---------------------------------------------------------------------------

class TrueNASClient:
    def __init__(self, host, api_key="", username="", password=""):
        self.base_url = host.rstrip("/")
        if not self.base_url.startswith("http"):
            self.base_url = f"https://{self.base_url}"
        self.api_key = api_key
        self.username = username
        self.password = password
        self.session = requests.Session()
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
        now = datetime.now(timezone.utc)
        start = now - timedelta(seconds=120)

        def _attempts():
            return [
                ("reporting/netdata/get_data", {
                    "graphs": graphs,
                    "reporting_query": {
                        "start": start.strftime("%Y-%m-%dT%H:%M:%S"),
                        "end": now.strftime("%Y-%m-%dT%H:%M:%S"),
                        "aggregate": True,
                    },
                }),
                ("reporting/get_data", {
                    "graphs": graphs,
                    "reporting_query": {
                        "start": start.strftime("%Y-%m-%dT%H:%M:%S"),
                        "end": now.strftime("%Y-%m-%dT%H:%M:%S"),
                        "aggregate": True,
                    },
                }),
                ("reporting/get_data", {
                    "graphs": graphs,
                    "reporting_query": {
                        "start": int(start.timestamp()),
                        "end": int(now.timestamp()),
                        "aggregate": True,
                    },
                }),
                ("reporting/get_data", {"graphs": graphs}),
                ("reporting/netdata/get_data", {"graphs": graphs}),
            ]

        if self._working_report_format is not None:
            idx = self._working_report_format
            attempts = _attempts()
            try:
                endpoint, payload = attempts[idx]
                return self._post(endpoint, payload)
            except Exception:
                self._working_report_format = None

        last_err = None
        for i, (endpoint, payload) in enumerate(_attempts()):
            try:
                result = self._post(endpoint, payload)
                self._working_report_format = i
                debug(f"reporting OK via {endpoint} (cached as #{i})")
                return result
            except Exception as e:
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
                if total and allocated is not None:
                    pct = round(allocated / total * 100, 1) if total > 0 else 0
                    stats["pools"].append({
                        "name": p.get("name", "unknown"),
                        "used": allocated,
                        "available": free or (total - allocated),
                        "total": total,
                        "percent": pct,
                        "disks": disks,
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

        return stats


# ---------------------------------------------------------------------------
# Terminal display
# ---------------------------------------------------------------------------

def _clear():
    os.system("cls" if sys.platform == "win32" else "clear")


def _severity_label(sev):
    return {"critical": "CRITICAL", "warning": "WARNING",
            "info": "INFO", "resolved": "RESOLVED"}.get(sev, "INFO")


def display_stats(stats, alerts, interval, temp_threshold):
    _clear()
    now = datetime.now().strftime("%H:%M:%S")
    host = stats.get("hostname", "N/A")
    ver = stats.get("version", "N/A")
    uptime = stats.get("uptime", "N/A")
    la = stats.get("loadavg", [0, 0, 0])
    la_s = "  ".join(f"{x:.2f}" for x in la) if la else "N/A"

    W = 70
    print("=" * W)
    print(f"  TrueMonitor v{APP_VERSION}  —  Text Mode")
    print(f"  {host}  |  {ver}")
    print(f"  Uptime: {uptime}  |  Updated: {now}  |  Poll: {interval}s")
    print("=" * W)

    # CPU
    cpu = stats.get("cpu_percent")
    if cpu is not None:
        marker = "!!" if cpu >= 90 else " ~" if cpu >= 70 else "  "
        col_tag = f"{marker}"
        print(f"  CPU Usage   {cpu:5.1f}%  {_progress_bar(cpu)}  {col_tag}  load: {la_s}")
    else:
        print("  CPU Usage   N/A")

    # Memory
    mp = stats.get("memory_percent")
    mu = stats.get("memory_used")
    mt = stats.get("memory_total")
    if mp is not None and mt:
        marker = "!!" if mp >= 90 else " ~" if mp >= 70 else "  "
        print(f"  Memory      {mp:5.1f}%  {_progress_bar(mp)}  {marker}  "
              f"{format_bytes(mu)} / {format_bytes(mt)}")
    else:
        print("  Memory      N/A")

    # Network
    rx = stats.get("net_rx") or 0
    tx = stats.get("net_tx") or 0
    iface = stats.get("net_iface", "")
    iface_tag = f"[{iface}]" if iface else ""
    print(f"  Network     down {format_bytes(rx, per_second=True):<14}  "
          f"up {format_bytes(tx, per_second=True):<14}  {iface_tag}")

    # CPU Temperature
    temp = stats.get("cpu_temp")
    if temp is not None:
        status = "Normal" if temp < 60 else "Warm" if temp < 80 else "HOT!"
        alert_tag = "  <<" if temp >= temp_threshold else ""
        print(f"  CPU Temp    {temp:5.1f}°C  ({status}){alert_tag}")
    else:
        print("  CPU Temp    N/A")

    # Pools
    pools = stats.get("pools", [])
    if pools:
        print()
        print(f"  {'STORAGE POOLS':-<{W - 2}}")
        for pool in pools:
            name = pool.get("name", "?")
            pct = pool.get("percent", 0)
            used = pool.get("used", 0)
            total = pool.get("total", 0)
            avail = pool.get("available", 0)
            marker = " !!" if pct >= 85 else "  ~" if pct >= 70 else "   "
            print(f"  Pool: {name:<14}  {pct:5.1f}%  {_progress_bar(pct, 16)}{marker}  "
                  f"{format_bytes(used)} / {format_bytes(total)}  ({format_bytes(avail)} free)")
            disks = pool.get("disks", [])
            if disks:
                pieces = []
                for d in disks:
                    flag = "ERR" if d["has_error"] else "ok"
                    pieces.append(f"{d['name']}[{flag}]")
                print(f"    Disks: {('  '.join(pieces))}")

    # Recent alerts
    alert_list = list(alerts)
    if alert_list:
        print()
        print(f"  {'RECENT ALERTS (last 10)':-<{W - 2}}")
        for a in alert_list[-10:]:
            if "time" in a:
                lbl = _severity_label(a.get("severity", "info"))
                print(f"  [{a['time']}] {lbl}: {a['message']}")
            elif "raw" in a:
                print(f"  {a['raw']}")

    print()
    print(f"  Ctrl+C to exit.  Alert threshold: CPU temp >{temp_threshold}°C")
    print("=" * W)


# ---------------------------------------------------------------------------
# Main app loop
# ---------------------------------------------------------------------------

class TrueMonitorText:
    def __init__(self, config):
        self.config = config
        self.alerts = deque(maxlen=50)
        self._temp_alert_active = False
        self._cpu_alert_active = False
        self._mem_alert_active = False
        self._seen_truenas_alerts = set()

    def _add_alert(self, severity, message):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.alerts.append({"time": ts, "severity": severity, "message": message})
        prefix = _severity_label(severity)
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(ALERT_LOG, "a") as f:
                f.write(f"[{ts}] {prefix}: {message}\n")
        except Exception:
            pass

    def _check_alerts(self, stats):
        temp_threshold = self.config.get("temp_threshold", 82)

        temp = stats.get("cpu_temp")
        if temp is not None:
            if temp > temp_threshold:
                if not self._temp_alert_active:
                    self._temp_alert_active = True
                    self._add_alert("critical",
                                    f"CPU temperature is {temp}°C (threshold {temp_threshold}°C)!")
            else:
                if self._temp_alert_active:
                    self._temp_alert_active = False
                    self._add_alert("resolved", f"CPU temperature back to normal: {temp}°C")

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

        current_ids = set()
        for alert in stats.get("system_alerts", []):
            alert_id = alert.get("id", "")
            current_ids.add(alert_id)
            if alert_id not in self._seen_truenas_alerts:
                self._seen_truenas_alerts.add(alert_id)
                self._add_alert(alert.get("severity", "info"),
                                f"[TrueNAS] {alert.get('message', '')}")
        resolved = self._seen_truenas_alerts - current_ids
        for aid in resolved:
            self._seen_truenas_alerts.discard(aid)
            self._add_alert("resolved", "[TrueNAS] Alert cleared")

    def run(self):
        c = self.config
        interval = c.get("interval", 5)
        temp_threshold = c.get("temp_threshold", 82)

        client = TrueNASClient(
            host=c["host"],
            api_key=c.get("api_key", ""),
            username=c.get("username", ""),
            password=c.get("password", ""),
        )

        print(f"TrueMonitor v{APP_VERSION} — Text Mode")
        print(f"Connecting to {c['host']}...")
        try:
            info = client.test_connection()
            host = info.get("hostname", c["host"])
            print(f"Connected to {host}")
            time.sleep(0.5)
        except Exception as e:
            print(f"Connection failed: {e}")
            raise SystemExit(1)

        while True:
            try:
                stats = client.fetch_all_stats()
                self._check_alerts(stats)
                display_stats(stats, self.alerts, interval, temp_threshold)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"\nPoll error: {e}")
                debug(f"poll error: {e}")

            try:
                time.sleep(interval)
            except KeyboardInterrupt:
                break

        print("\nDisconnected.")


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
        description=f"TrueMonitor v{APP_VERSION} — Text Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "If no arguments are given, settings are read from\n"
            f"  {CONFIG_FILE}\n"
            "(saved by truemonitor.py). CLI args override saved settings."
        ),
    )
    parser.add_argument("--host", metavar="IP_OR_HOST",
                        help="TrueNAS IP address or hostname")
    parser.add_argument("--api-key", metavar="KEY",
                        help="TrueNAS API key")
    parser.add_argument("--username", metavar="USER",
                        help="TrueNAS username")
    parser.add_argument("--password", metavar="PASS",
                        help="TrueNAS password")
    parser.add_argument("--interval", type=int, metavar="SECS",
                        help="Poll interval in seconds (minimum 2, default 5)")
    parser.add_argument("--temp-threshold", type=int, metavar="TEMP",
                        help="CPU temperature alert threshold in °C (default 82)")
    args = parser.parse_args()

    config = load_config()

    if args.host:
        config["host"] = args.host
    if args.api_key:
        config["api_key"] = args.api_key
    if args.username:
        config["username"] = args.username
    if args.password:
        config["password"] = args.password
    if args.interval is not None:
        config["interval"] = max(2, args.interval)
    if args.temp_threshold is not None:
        config["temp_threshold"] = args.temp_threshold

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

    app = TrueMonitorText(config)
    try:
        app.run()
    except KeyboardInterrupt:
        print("\nExiting.")


if __name__ == "__main__":
    main()
