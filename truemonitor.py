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

from cryptography.fernet import Fernet, InvalidToken

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("ERROR: 'requests' package is required. Install it with:")
    print("  pip install requests")
    raise SystemExit(1)

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
# TrueNAS REST API client
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
        self._working_report_format = None  # cache the format that works
        self._working_iface = None  # cache the interface with data

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
        r = self.session.get(
            url, headers=self._headers(), auth=self._auth(), timeout=10
        )
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

    # --- public helpers ---
    def test_connection(self):
        return self._get("system/info")

    def get_system_info(self):
        return self._get("system/info")

    def get_interfaces(self):
        return self._get("interface")

    def get_reporting_data(self, graphs):
        now = datetime.now(timezone.utc)
        start = now - timedelta(seconds=120)

        # Build list of (endpoint, payload) attempts
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

        # Use cached format if we found one before
        if self._working_report_format is not None:
            idx = self._working_report_format
            attempts = _attempts()
            try:
                endpoint, payload = attempts[idx]
                return self._post(endpoint, payload)
            except Exception:
                self._working_report_format = None  # reset, try all

        last_err = None
        for i, (endpoint, payload) in enumerate(_attempts()):
            try:
                result = self._post(endpoint, payload)
                self._working_report_format = i  # cache working format
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

        debug(f" final stats: {stats}")
        return stats


# ---------------------------------------------------------------------------
# GUI application
# ---------------------------------------------------------------------------
class TrueMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TrueMonitor")
        self.root.geometry("1050x750")
        self.root.minsize(900, 650)
        self.root.configure(bg=COLORS["bg"])

        self.client = None
        self.polling = False
        self.demo_mode = False
        self.poll_thread = None
        self.config = self._load_config()
        self.net_history_rx = []
        self.net_history_tx = []
        self.temp_history = []
        self.HISTORY_LEN = 60
        self.alerts = deque(maxlen=200)
        self._temp_alert_active = False
        self._cpu_alert_active = False
        self._mem_alert_active = False

        self._setup_styles()
        self._build_ui()

        if self.config.get("host"):
            self._populate_settings()
            self._connect()

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
            font=("Helvetica", 11),
        )
        s.map(
            "TNotebook.Tab",
            background=[("selected", COLORS["card_border"])],
            foreground=[("selected", COLORS["accent"])],
        )

        for name, opts in {
            "Card.TLabel": {"bg": COLORS["card"], "fg": COLORS["text"],
                            "font": ("Helvetica", 11)},
            "CardTitle.TLabel": {"bg": COLORS["card"], "fg": COLORS["accent"],
                                 "font": ("Helvetica", 12, "bold")},
            "CardValue.TLabel": {"bg": COLORS["card"], "fg": COLORS["text"],
                                  "font": ("Helvetica", 28, "bold")},
            "CardSub.TLabel": {"bg": COLORS["card"], "fg": COLORS["text_dim"],
                                "font": ("Helvetica", 10)},
            "Status.TLabel": {"bg": COLORS["bg"], "fg": COLORS["text_dim"],
                               "font": ("Helvetica", 10)},
            "StatusOK.TLabel": {"bg": COLORS["bg"], "fg": COLORS["good"],
                                 "font": ("Helvetica", 10)},
            "StatusErr.TLabel": {"bg": COLORS["bg"], "fg": COLORS["critical"],
                                  "font": ("Helvetica", 10)},
            "Settings.TLabel": {"bg": COLORS["bg"], "fg": COLORS["text"],
                                 "font": ("Helvetica", 11)},
            "SettingsH.TLabel": {"bg": COLORS["bg"], "fg": COLORS["accent"],
                                  "font": ("Helvetica", 14, "bold")},
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

    # --- UI construction ---
    def _build_ui(self):
        main = tk.Frame(self.root, bg=COLORS["bg"])
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # header
        hdr = tk.Frame(main, bg=COLORS["bg"])
        hdr.pack(fill=tk.X, pady=(0, 8))
        tk.Label(
            hdr, text="TrueMonitor", bg=COLORS["bg"], fg=COLORS["accent"],
            font=("Helvetica", 20, "bold"),
        ).pack(side=tk.LEFT)
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
        self.footer = tk.Label(main, text="", bg=COLORS["bg"],
                               fg=COLORS["text_dim"], font=("Helvetica", 9))
        self.footer.pack(fill=tk.X, pady=(6, 0))

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
            bg=COLORS["card"], fg=COLORS["text"], font=("Helvetica", 10),
        )
        self.info_lbl.pack(anchor="w")

        # metric cards
        grid = tk.Frame(self.mon_frame, bg=COLORS["bg"])
        grid.pack(fill=tk.BOTH, expand=True, pady=8)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        grid.rowconfigure(0, weight=1)
        grid.rowconfigure(1, weight=1)

        self.cpu_card = self._make_card(grid, "CPU Usage", 0, 0)
        self.mem_card = self._make_card(grid, "Memory", 0, 1)
        self._build_net_graph(grid, 1, 0)
        self._build_temp_graph(grid, 1, 1)

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
                 font=("Helvetica", 10)).pack(side=tk.LEFT)
        tk.Label(leg, text="In ", fg=COLORS["text_dim"], bg=COLORS["card"],
                 font=("Helvetica", 9)).pack(side=tk.LEFT)
        tk.Label(leg, text="\u25cf", fg=COLORS["accent"], bg=COLORS["card"],
                 font=("Helvetica", 10)).pack(side=tk.LEFT)
        tk.Label(leg, text="Out", fg=COLORS["text_dim"], bg=COLORS["card"],
                 font=("Helvetica", 9)).pack(side=tk.LEFT)

        # Current speed labels
        speed_f = tk.Frame(f, bg=COLORS["card"])
        speed_f.pack(fill=tk.X, pady=(6, 4))
        self.net_rx_lbl = tk.Label(
            speed_f, text="\u2193 --", bg=COLORS["card"], fg=COLORS["good"],
            font=("Helvetica", 14, "bold"))
        self.net_rx_lbl.pack(side=tk.LEFT, padx=(0, 16))
        self.net_tx_lbl = tk.Label(
            speed_f, text="\u2191 --", bg=COLORS["card"], fg=COLORS["accent"],
            font=("Helvetica", 14, "bold"))
        self.net_tx_lbl.pack(side=tk.LEFT)
        self.net_iface_lbl = tk.Label(
            speed_f, text="", bg=COLORS["card"], fg=COLORS["text_dim"],
            font=("Helvetica", 9))
        self.net_iface_lbl.pack(side=tk.RIGHT)

        # Canvas for the graph
        self.net_canvas = tk.Canvas(
            f, bg="#0a1628", highlightthickness=0, height=120)
        self.net_canvas.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        # Y-axis scale label
        self.net_scale_lbl = tk.Label(
            f, text="", bg=COLORS["card"], fg=COLORS["text_dim"],
            font=("Helvetica", 8))
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
            font=("Helvetica", 22, "bold"))
        self.temp_val_lbl.pack(side=tk.LEFT)
        self.temp_status_lbl = tk.Label(
            temp_f, text="", bg=COLORS["card"], fg=COLORS["text_dim"],
            font=("Helvetica", 11))
        self.temp_status_lbl.pack(side=tk.LEFT, padx=(12, 0))
        self.temp_range_lbl = tk.Label(
            temp_f, text="", bg=COLORS["card"], fg=COLORS["text_dim"],
            font=("Helvetica", 9))
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
                      font=("Helvetica", 7), anchor="e")
        c.create_line(0, y_warm, w, y_warm, fill=COLORS["warning"], dash=(3, 3))
        c.create_text(w - 4, y_warm - 8, text="60\u00b0C", fill=COLORS["warning"],
                      font=("Helvetica", 7), anchor="e")

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

    def _build_alerts_tab(self):
        # Header
        hdr = tk.Frame(self.alert_frame, bg=COLORS["bg"], pady=8, padx=12)
        hdr.pack(fill=tk.X)
        ttk.Label(hdr, text="Alert Log", style="SettingsH.TLabel").pack(
            side=tk.LEFT)
        self.alert_count_lbl = tk.Label(
            hdr, text="0 alerts", bg=COLORS["bg"], fg=COLORS["text_dim"],
            font=("Helvetica", 10))
        self.alert_count_lbl.pack(side=tk.LEFT, padx=(12, 0))

        clear_btn = tk.Button(
            hdr, text="Clear All", bg=COLORS["card"], fg=COLORS["text"],
            activebackground=COLORS["card_border"],
            activeforeground=COLORS["text"],
            font=("Helvetica", 10), relief="flat", padx=14, pady=4,
            command=self._clear_alerts)
        clear_btn.pack(side=tk.RIGHT)

        # Scrollable alert list
        list_frame = tk.Frame(self.alert_frame, bg=COLORS["bg"], padx=12)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.alert_listbox = tk.Text(
            list_frame, bg=COLORS["card"], fg=COLORS["text"],
            font=("Courier", 10), relief="flat", bd=8,
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
        """Play a system warning sound."""
        def _sound():
            try:
                # Try paplay (PulseAudio) with system alert sound
                subprocess.run(
                    ["paplay", "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"],
                    timeout=3, capture_output=True)
            except Exception:
                try:
                    # Fallback: aplay with beep
                    subprocess.run(
                        ["aplay", "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"],
                        timeout=3, capture_output=True)
                except Exception:
                    try:
                        # Last resort: terminal bell
                        print("\a", end="", flush=True)
                    except Exception:
                        pass
        threading.Thread(target=_sound, daemon=True).start()

    def _clear_alerts(self):
        self.alerts.clear()
        self.alert_listbox.config(state=tk.NORMAL)
        self.alert_listbox.delete("1.0", tk.END)
        self.alert_listbox.config(state=tk.DISABLED)
        self.alert_count_lbl.config(text="0 alerts")
        self.notebook.tab(1, text="  Alerts  ")
        # Clear the log file
        try:
            with open(ALERT_LOG, "w") as f:
                f.write("")
        except Exception:
            pass

    def _check_alerts(self, stats):
        """Check stats and fire alerts as needed."""
        # --- CPU Temperature > 82°C ---
        temp = stats.get("cpu_temp")
        if temp is not None:
            if temp > 82:
                if not self._temp_alert_active:
                    self._temp_alert_active = True
                    self._add_alert(
                        "critical",
                        f"CPU temperature is {temp}\u00b0C (above 82\u00b0C threshold)!",
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

        entry_kw = dict(
            bg=COLORS["input_bg"], fg=COLORS["text"],
            insertbackground=COLORS["text"], font=("Helvetica", 11),
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
                 font=("Helvetica", 10)).grid(row=r, column=0,
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

        c.columnconfigure(1, weight=1)

        # buttons
        bf = tk.Frame(c, bg=COLORS["bg"])
        bf.grid(row=7, column=0, columnspan=2, pady=26, sticky="w")

        self.conn_btn = tk.Button(
            bf, text="Save & Connect", bg=COLORS["button"],
            fg=COLORS["text"], activebackground=COLORS["button_hover"],
            activeforeground=COLORS["text"], font=("Helvetica", 11, "bold"),
            relief="flat", padx=22, pady=8, command=self._on_save,
        )
        self.conn_btn.pack(side=tk.LEFT, padx=(0, 14))

        self.disc_btn = tk.Button(
            bf, text="Disconnect", bg=COLORS["critical"], fg=COLORS["text"],
            activebackground="#d32f2f", activeforeground=COLORS["text"],
            font=("Helvetica", 11), relief="flat", padx=22, pady=8,
            command=self._disconnect, state=tk.DISABLED,
        )
        self.disc_btn.pack(side=tk.LEFT)

        self.demo_btn = tk.Button(
            bf, text="Demo Mode", bg=COLORS["warning"], fg="#1a1a2e",
            activebackground="#ffb74d", activeforeground="#1a1a2e",
            font=("Helvetica", 11, "bold"), relief="flat", padx=22, pady=8,
            command=self._toggle_demo,
        )
        self.demo_btn.pack(side=tk.LEFT, padx=(14, 0))

    def _populate_settings(self):
        self.host_var.set(self.config.get("host", ""))
        self.apikey_var.set(self.config.get("api_key", ""))
        self.user_var.set(self.config.get("username", ""))
        self.pass_var.set(self.config.get("password", ""))
        self.interval_var.set(str(self.config.get("interval", 5)))

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

        self.config = {
            "host": host, "api_key": api_key,
            "username": user, "password": pw,
            "interval": iv_val,
        }
        self._save_config()
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
                self.root.after(0, lambda: self._conn_error(str(e)))

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
        self.notebook.tab(1, text="  Alerts  ")
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
            }
            self.root.after(0, lambda s=stats: self._refresh(s))
            time.sleep(2)

    def _on_close(self):
        self.polling = False
        self.demo_mode = False
        self.root.destroy()


def main():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(DEBUG_LOG, "w") as f:
        f.write("")
    root = tk.Tk()
    TrueMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
