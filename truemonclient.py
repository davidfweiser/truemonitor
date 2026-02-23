#!/usr/bin/env python3
"""TrueMonClient - Remote display client for TrueMonitor"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import threading
import time
import os
import random
import subprocess
import socket
import struct
import base64
import hashlib
import hmac as hmac_mod
import getpass
from datetime import datetime
from collections import deque

import tkinter.font as tkfont
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

FONT_SCALES = {"Small": 0.85, "Medium": 1.0, "Large": 1.15}

APP_VERSION = "0.5"

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "truemonclient")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
DEBUG_LOG = os.path.join(CONFIG_DIR, "debug.log")
ALERT_LOG = os.path.join(CONFIG_DIR, "alerts.log")

BROADCAST_DEFAULT_PORT = 7337
BROADCAST_DEFAULT_KEY = "truemonitor"


def debug(msg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(DEBUG_LOG, "a") as f:
        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")


def _get_encryption_key():
    """Derive a Fernet key from machine-specific data."""
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
    """Derive the raw 32-byte key used for HMAC auth handshake."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"truemonitor_broadcast_v1",
        iterations=100_000,
    )
    return kdf.derive(passphrase.encode())


# Magic prefix sent by server to initiate auth
_AUTH_MAGIC = b"TRUEMON_AUTH\n"


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
# TCP client that receives encrypted stats from TrueMonitor
# ---------------------------------------------------------------------------
class MonitorClient:
    """Connects to a TrueMonitor broadcast server and receives encrypted stats."""

    def __init__(self, host: str, port: int, passphrase: str,
                 on_stats, on_error, on_connected, on_disconnected):
        self.host = host
        self.port = port
        self.passphrase = passphrase
        self.on_stats = on_stats
        self.on_error = on_error
        self.on_connected = on_connected
        self.on_disconnected = on_disconnected
        self._running = False
        self._sock = None
        self._thread = None
        self._send_lock = threading.Lock()

    def _get_fernet(self):
        return Fernet(_derive_broadcast_key(self.passphrase))

    def send_command(self, cmd: dict):
        """Send a plain-JSON command frame to the server (thread-safe)."""
        sock = self._sock
        if not sock:
            return
        try:
            payload = json.dumps(cmd).encode()
            message = struct.pack(">I", len(payload)) + payload
            with self._send_lock:
                sock.sendall(message)
        except Exception:
            pass

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _recvn(self, n: int):
        """Receive exactly n bytes from the socket."""
        data = b""
        while len(data) < n:
            try:
                chunk = self._sock.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except Exception:
                return None
        return data

    def _recv_loop(self):
        retry_delay = 5
        stats_count = 0
        while self._running:
            self._sock = None
            try:
                debug(f"MonitorClient: connecting to {self.host}:{self.port}")
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.settimeout(10.0)
                self._sock.connect((self.host, self.port))
                self._sock.settimeout(10.0)
                debug(f"MonitorClient: connected to {self.host}:{self.port}")

                # --- Auth handshake ---
                magic = self._recvn(len(_AUTH_MAGIC))
                if magic != _AUTH_MAGIC:
                    debug("MonitorClient: unexpected auth magic, disconnecting")
                    self.on_error("Protocol error — server did not send auth challenge")
                    break
                challenge = self._recvn(32)
                if challenge is None or len(challenge) != 32:
                    debug("MonitorClient: failed to receive auth challenge")
                    self.on_error("Auth challenge receive error")
                    break
                raw_key = _derive_broadcast_key_raw(self.passphrase)
                response = hmac_mod.new(raw_key, challenge, hashlib.sha256).digest()
                self._sock.sendall(response)
                debug("MonitorClient: sent auth response")
                # Server drops the connection immediately on wrong key; give it a moment
                self._sock.settimeout(60.0)

                self.on_connected()
                fernet = self._get_fernet()
                stats_count = 0
                while self._running:
                    header = self._recvn(4)
                    if header is None:
                        debug("MonitorClient: connection closed by server")
                        break
                    length = struct.unpack(">I", header)[0]
                    if length == 0 or length > 10 * 1024 * 1024:
                        debug(f"MonitorClient: invalid frame length {length}, disconnecting")
                        break
                    encrypted = self._recvn(length)
                    if encrypted is None:
                        debug("MonitorClient: failed to read payload, disconnecting")
                        break
                    try:
                        payload = fernet.decrypt(encrypted)
                        stats = json.loads(payload.decode())
                        stats_count += 1
                        if stats_count <= 3 or stats_count % 60 == 0:
                            debug(f"MonitorClient: received stats #{stats_count} "
                                  f"(cpu={stats.get('cpu_percent')}% "
                                  f"mem={stats.get('memory_percent')}% "
                                  f"temp={stats.get('cpu_temp')}°C)")
                        self.on_stats(stats)
                    except InvalidToken:
                        debug("MonitorClient: decryption failed — wrong shared key")
                        self.on_error("Decryption failed — check shared key")
                        break
                    except Exception as e:
                        debug(f"MonitorClient: data error: {e}")
                        self.on_error(f"Data error: {e}")
                        break
            except ConnectionRefusedError:
                debug(f"MonitorClient: connection refused at {self.host}:{self.port}")
                if self._running:
                    self.on_error(f"Connection refused — is TrueMonitor running on {self.host}:{self.port}?")
            except socket.timeout:
                debug(f"MonitorClient: connection timed out to {self.host}:{self.port}")
                if self._running:
                    self.on_error(f"Connection timed out to {self.host}:{self.port}")
            except Exception as e:
                debug(f"MonitorClient: unexpected error: {e}")
                if self._running:
                    self.on_error(str(e))
            finally:
                if self._sock:
                    try:
                        self._sock.close()
                    except Exception:
                        pass
                    self._sock = None

            if self._running:
                self.on_disconnected()
                debug(f"MonitorClient: reconnecting in {retry_delay}s")
                time.sleep(retry_delay)


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
class TrueMonClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TrueMonClient")
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        import sys as _sys
        if _sys.platform == "darwin":
            w = min(675, int(sw * 0.675))
            h = min(525, int(sh * 0.66))
        else:
            w = min(900, int(sw * 0.90))
            h = min(700, int(sh * 0.88))
        self.root.geometry(f"{w}x{h}")
        self.root.minsize(min(560, sw - 80), min(400, sh - 80))
        self.root.configure(bg=COLORS["bg"])

        self.monitor_client = None
        self.connected = False
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
        self._seen_truenas_alerts = set()
        self.pool_cards = {}
        self._pool_count = 0
        self._font_scale = FONT_SCALES.get(
            self.config.get("font_size", "Medium"), 1.0)

        self._setup_styles()
        self._build_ui()

        if self.config.get("server_host"):
            self._populate_settings()
            self._connect()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # --- config persistence ---
    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                return data
            except Exception:
                pass
        return {}

    def _save_config(self):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.config, f, indent=2)

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
            hdr, text="TrueMonClient", bg=COLORS["bg"], fg=COLORS["accent"],
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
            info_f, text="Connect to TrueMonitor to begin monitoring",
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
        ttk.Label(hdr, text="Network", style="CardTitle.TLabel").pack(side=tk.LEFT)

        # Legend
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

        self.net_canvas = tk.Canvas(
            f, bg="#0a1628", highlightthickness=0, height=120)
        self.net_canvas.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

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

        all_vals = self.net_history_rx + self.net_history_tx
        max_val = max(all_vals) if all_vals else 1
        if max_val <= 0:
            max_val = 1

        for i in range(1, 4):
            y = int(graph_h * i / 4)
            c.create_line(0, y, w, y, fill="#1a2a4a", dash=(2, 4))

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

        self.net_scale_lbl.config(text=f"Peak: {format_bytes(max_val, per_second=True)}")

    def _build_temp_graph(self, parent, row, col):
        f = tk.Frame(
            parent, bg=COLORS["card"],
            highlightbackground=COLORS["card_border"], highlightthickness=1,
            padx=18, pady=14,
        )
        f.grid(row=row, column=col, padx=16, pady=16, sticky="nsew")

        hdr = tk.Frame(f, bg=COLORS["card"])
        hdr.pack(fill=tk.X)
        ttk.Label(hdr, text="CPU Temperature", style="CardTitle.TLabel").pack(side=tk.LEFT)

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

        t_min = 20
        t_max = 100
        t_range = t_max - t_min

        def y_for_temp(t):
            return int(graph_h - ((t - t_min) / t_range) * (graph_h - 4) - 2)

        y_hot = y_for_temp(80)
        c.create_rectangle(0, 0, w, y_hot, fill="#2a1015", outline="")
        y_warm = y_for_temp(60)
        c.create_rectangle(0, y_hot, w, y_warm, fill="#2a2010", outline="")

        c.create_line(0, y_hot, w, y_hot, fill=COLORS["critical"], dash=(3, 3))
        c.create_text(w - 4, y_hot - 8, text="80\u00b0C", fill=COLORS["critical"],
                      font=("Helvetica", self._sf(7)), anchor="e")
        c.create_line(0, y_warm, w, y_warm, fill=COLORS["warning"], dash=(3, 3))
        c.create_text(w - 4, y_warm - 8, text="60\u00b0C", fill=COLORS["warning"],
                      font=("Helvetica", self._sf(7)), anchor="e")

        points = []
        for i, val in enumerate(self.temp_history):
            x = int(w * i / (n - 1)) if n > 1 else 0
            y = y_for_temp(val)
            y = max(2, min(graph_h - 2, y))
            points.append(x)
            points.append(y)

        if len(points) >= 4:
            latest = self.temp_history[-1]
            col = (COLORS["good"] if latest < 60
                   else COLORS["warning"] if latest < 80
                   else COLORS["critical"])
            c.create_line(points, fill=col, width=2, smooth=True)

        lo = min(self.temp_history)
        hi = max(self.temp_history)
        self.temp_range_lbl.config(text=f"Low: {lo:.0f}\u00b0C  High: {hi:.0f}\u00b0C")

    def _build_pool_cards(self, pools):
        """Dynamically create pool capacity cards in the monitor grid."""
        import math
        for card in self.pool_cards.values():
            card["frame"].destroy()
        self.pool_cards = {}

        num_pools = len(pools)
        if num_pools == 0:
            return

        self._pool_count = num_pools
        pool_rows = math.ceil(num_pools / 2)

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
            map_btn = tk.Button(
                title_row, text="Drive Map", bg="#ffffff",
                fg="#000000", activebackground="#e0e0e0",
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

            disk_frame = tk.Frame(f, bg=COLORS["card"])
            disk_frame.pack(anchor="w", pady=(8, 0))
            tk.Label(
                disk_frame, text="Disks:", bg=COLORS["card"],
                fg=COLORS["text_dim"], font=("Helvetica", self._sf(9)),
            ).pack(side=tk.LEFT, padx=(0, 6))

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

        pool_rows_total = math.ceil(num_pools / 2)
        sh = self.root.winfo_screenheight()
        sw = self.root.winfo_screenwidth()
        max_h = int(sh * 0.92)
        base_h = min(640, int(sh * 0.60))
        new_height = min(base_h + pool_rows_total * 200, max_h)
        cur_geo = self.root.geometry()
        try:
            width = int(cur_geo.split("x")[0])
        except (ValueError, IndexError):
            width = min(900, int(sw * 0.90))
        self.root.geometry(f"{width}x{new_height}")
        self.root.minsize(min(660, sw - 80), min(480, sh - 80))

    def _show_drive_map(self, pool_name, topology):
        """Open a popup window showing the vdev/drive layout of a pool."""
        win = tk.Toplevel(self.root)
        win.title(f"Drive Map - {pool_name}")
        win.configure(bg=COLORS["bg"])
        win.minsize(400, 200)

        tk.Label(
            win, text=f"Pool: {pool_name}", bg=COLORS["bg"],
            fg=COLORS["accent"], font=("Helvetica", self._sf(16), "bold"),
            padx=16, pady=12,
        ).pack(anchor="w")

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

                vdev_frame = tk.Frame(
                    content, bg=COLORS["card"],
                    highlightbackground=COLORS["card_border"],
                    highlightthickness=1, padx=12, pady=8,
                )
                vdev_frame.pack(fill=tk.X, padx=12, pady=4)

                vhdr = tk.Frame(vdev_frame, bg=COLORS["card"])
                vhdr.pack(fill=tk.X)

                type_color = COLORS["accent"]
                if vtype == "MIRROR":
                    type_icon = "\u2194"
                elif vtype.startswith("RAIDZ"):
                    type_icon = "\u2726"
                elif vtype == "STRIPE":
                    type_icon = "\u2502"
                else:
                    type_icon = "\u25cb"

                tk.Label(
                    vhdr, text=f" {type_icon}  {vtype}",
                    bg=COLORS["card"], fg=type_color,
                    font=("Helvetica", self._sf(11), "bold"),
                ).pack(side=tk.LEFT)

                st_color = COLORS["good"] if vstatus == "ONLINE" else COLORS["critical"]
                tk.Label(
                    vhdr, text=vstatus, bg=COLORS["card"], fg=st_color,
                    font=("Helvetica", self._sf(9)),
                ).pack(side=tk.RIGHT)

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

                    name_fg = "#ffffff" if has_err else COLORS["text"]
                    tk.Label(
                        disk_box, text=dname, bg=disk_bg, fg=name_fg,
                        font=("Helvetica", self._sf(10), "bold"),
                    ).pack()

                    status_text = dstatus
                    if derrors > 0:
                        status_text += f" ({derrors} err)"
                    st_col = COLORS["good"] if not has_err else COLORS["critical"]
                    tk.Label(
                        disk_box, text=status_text, bg=disk_bg,
                        fg=st_col, font=("Helvetica", self._sf(7)),
                    ).pack()

                    if di < len(vdisks) - 1 and vtype in ("MIRROR", "RAIDZ1", "RAIDZ2", "RAIDZ3"):
                        tk.Label(
                            disk_grid, text="\u2500\u2500",
                            bg=COLORS["card"], fg=COLORS["card_border"],
                            font=("Helvetica", self._sf(8)),
                        ).pack(side=tk.LEFT)

        tk.Button(
            win, text="Close", bg="#ffffff", fg="#000000",
            activebackground="#e0e0e0",
            activeforeground="#000000",
            font=("Helvetica", self._sf(10)), relief="flat", padx=20, pady=6,
            command=win.destroy,
        ).pack(pady=(0, 12))

        win.update_idletasks()
        w = max(500, content.winfo_reqwidth() + 60)
        h = min(700, content.winfo_reqheight() + 120)
        win.geometry(f"{w}x{h}")

    def _build_alerts_tab(self):
        hdr = tk.Frame(self.alert_frame, bg=COLORS["bg"], pady=8, padx=12)
        hdr.pack(fill=tk.X)
        ttk.Label(hdr, text="Alert Log", style="SettingsH.TLabel").pack(side=tk.LEFT)
        self.alert_count_lbl = tk.Label(
            hdr, text="0 alerts", bg=COLORS["bg"], fg=COLORS["text_dim"],
            font=("Helvetica", self._sf(10)))
        self.alert_count_lbl.pack(side=tk.LEFT, padx=(12, 0))

        clear_btn = tk.Button(
            hdr, text="Clear All", bg=COLORS["card"], fg=COLORS["text"],
            activebackground=COLORS["card_border"],
            activeforeground=COLORS["text"],
            font=("Helvetica", self._sf(10)), relief="flat", padx=14, pady=4,
            command=self._clear_alerts)
        clear_btn.pack(side=tk.RIGHT)

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

        self.alert_listbox.tag_configure("critical", foreground=COLORS["critical"])
        self.alert_listbox.tag_configure("warning", foreground=COLORS["warning"])
        self.alert_listbox.tag_configure("info", foreground=COLORS["accent"])
        self.alert_listbox.tag_configure("resolved", foreground=COLORS["good"])
        self.alert_listbox.tag_configure("timestamp", foreground=COLORS["text_dim"])

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

        self.alert_listbox.config(state=tk.NORMAL)
        self.alert_listbox.insert("1.0", f"[{ts}] ", "timestamp")
        self.alert_listbox.insert("1.end", f"{prefix}: ", severity)
        self.alert_listbox.insert("1.end", f"{message}\n", "")
        self.alert_listbox.config(state=tk.DISABLED)

        count = len(self.alerts)
        self.alert_count_lbl.config(text=f"{count} alert{'s' if count != 1 else ''}")

        if severity in ("critical", "warning"):
            self.notebook.tab(1, text="  Alerts *  ")

        if sound:
            self._play_warning_sound()

        if popup:
            icon = "warning" if severity == "warning" else "error"
            messagebox.showwarning("TrueMonClient Alert", f"{prefix}: {message}")

    def _play_warning_sound(self):
        import sys
        def _sound():
            platform = sys.platform
            try:
                if platform == "win32":
                    import winsound
                    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
                    return
                elif platform == "darwin":
                    subprocess.run(
                        ["afplay", "/System/Library/Sounds/Sosumi.aiff"],
                        timeout=3, capture_output=True)
                    return
                else:
                    result = subprocess.run(
                        ["paplay", "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"],
                        timeout=3, capture_output=True)
                    if result.returncode == 0:
                        return
                    subprocess.run(
                        ["aplay", "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"],
                        timeout=3, capture_output=True)
                    return
            except Exception:
                pass
            try:
                print("\a", end="", flush=True)
            except Exception:
                pass
        threading.Thread(target=_sound, daemon=True).start()

    def _clear_alerts(self, from_server: bool = False):
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
        if not from_server:
            self.monitor_client.send_command({"cmd": "clear_alerts"})

    def _check_alerts(self, stats):
        """Check stats and fire threshold alerts."""
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
                    self._add_alert("resolved",
                                    f"CPU temperature back to normal: {temp}\u00b0C")

        cpu = stats.get("cpu_percent")
        if cpu is not None:
            if cpu > 95:
                if not self._cpu_alert_active:
                    self._cpu_alert_active = True
                    self._add_alert("warning", f"CPU usage critically high: {cpu}%",
                                    popup=True, sound=True)
            else:
                if self._cpu_alert_active:
                    self._cpu_alert_active = False
                    self._add_alert("resolved", f"CPU usage back to normal: {cpu}%")

        mem_pct = stats.get("memory_percent")
        if mem_pct is not None:
            if mem_pct > 95:
                if not self._mem_alert_active:
                    self._mem_alert_active = True
                    self._add_alert("warning", f"Memory usage critically high: {mem_pct}%",
                                    popup=True, sound=True)
            else:
                if self._mem_alert_active:
                    self._mem_alert_active = False
                    self._add_alert("resolved",
                                    f"Memory usage back to normal: {mem_pct}%")

        # --- TrueNAS system alerts (forwarded from server) ---
        self._process_system_alerts(stats.get("system_alerts", []))

    def _process_system_alerts(self, alerts):
        """Process TrueNAS system alerts received from the broadcast."""
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

        ttk.Label(c, text="TrueMonitor Connection",
                  style="SettingsH.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 18))

        entry_kw = dict(
            bg=COLORS["input_bg"], fg=COLORS["text"],
            insertbackground=COLORS["text"], font=("Helvetica", self._sf(11)),
            relief="flat", bd=5,
        )

        self.server_host_var = tk.StringVar()
        self.server_port_var = tk.StringVar(
            value=str(self.config.get("server_port", BROADCAST_DEFAULT_PORT)))
        self.server_key_var = tk.StringVar()
        self.temp_threshold_var = tk.StringVar(
            value=str(self.config.get("temp_threshold", 82)))

        r = 1
        ttk.Label(c, text="TrueMonitor IP / Hostname:",
                  style="Settings.TLabel").grid(row=r, column=0, sticky="w", pady=6)
        tk.Entry(c, textvariable=self.server_host_var, width=36,
                 **entry_kw).grid(row=r, column=1, sticky="ew", pady=6, padx=(10, 0))

        r = 2
        ttk.Label(c, text="Broadcast Port:",
                  style="Settings.TLabel").grid(row=r, column=0, sticky="w", pady=6)
        tk.Entry(c, textvariable=self.server_port_var, width=8,
                 **entry_kw).grid(row=r, column=1, sticky="w", pady=6, padx=(10, 0))

        r = 3
        ttk.Label(c, text="Shared Key:",
                  style="Settings.TLabel").grid(row=r, column=0, sticky="w", pady=6)
        key_row = tk.Frame(c, bg=COLORS["bg"])
        key_row.grid(row=r, column=1, sticky="ew", pady=6, padx=(10, 0))
        self._skey_entry = tk.Entry(
            key_row, textvariable=self.server_key_var, width=30, show="*",
            **entry_kw)
        self._skey_entry.pack(side=tk.LEFT)
        self._skey_show = False
        def _toggle_skey():
            self._skey_show = not self._skey_show
            self._skey_entry.config(show="" if self._skey_show else "*")
        tk.Button(
            key_row, text="Show", bg=COLORS["card"], fg=COLORS["text"],
            activebackground=COLORS["card_border"], activeforeground=COLORS["text"],
            font=("Helvetica", self._sf(9)), relief="flat", padx=8, pady=2,
            command=_toggle_skey,
        ).pack(side=tk.LEFT, padx=(6, 0))

        r = 4
        tk.Label(c, text="--- alert thresholds ---", bg=COLORS["bg"],
                 fg=COLORS["text_dim"],
                 font=("Helvetica", self._sf(10))).grid(row=r, column=0,
                                              columnspan=2, pady=14)

        r = 5
        ttk.Label(c, text="CPU Temp Alert (\u00b0C):",
                  style="Settings.TLabel").grid(row=r, column=0, sticky="w", pady=6)
        temp_values = [str(t) for t in range(40, 97)]
        self.temp_combo = ttk.Combobox(
            c, textvariable=self.temp_threshold_var, values=temp_values,
            width=6, state="readonly", style="Settings.TCombobox",
            font=("Helvetica", self._sf(11)),
        )
        self.temp_combo.grid(row=r, column=1, sticky="w", pady=6, padx=(10, 0))
        self.temp_combo.bind("<<ComboboxSelected>>", self._on_temp_threshold_change)

        r = 6
        tk.Label(c, text="--- display ---", bg=COLORS["bg"],
                 fg=COLORS["text_dim"],
                 font=("Helvetica", self._sf(10))).grid(row=r, column=0,
                                              columnspan=2, pady=14)

        r = 7
        self.font_size_var = tk.StringVar(
            value=self.config.get("font_size", "Medium"))
        ttk.Label(c, text="Font Size:",
                  style="Settings.TLabel").grid(row=r, column=0, sticky="w", pady=6)
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
        bf.grid(row=8, column=0, columnspan=2, pady=26, sticky="w")

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
        self.server_host_var.set(self.config.get("server_host", ""))
        self.server_port_var.set(str(self.config.get("server_port", BROADCAST_DEFAULT_PORT)))
        self.server_key_var.set(self.config.get("server_key", BROADCAST_DEFAULT_KEY))
        self.temp_threshold_var.set(str(self.config.get("temp_threshold", 82)))
        self.font_size_var.set(self.config.get("font_size", "Medium"))

    def _on_font_size_change(self, event=None):
        size_name = self.font_size_var.get()
        self.config["font_size"] = size_name
        self._save_config()
        self._font_scale = FONT_SCALES.get(size_name, 1.0)

        was_connected = self.connected
        was_demo = self.demo_mode

        self._main_frame.destroy()
        self.pool_cards = {}
        self._pool_count = 0
        self._setup_styles()
        self._build_ui()

        self._populate_settings()

        if was_demo:
            self.demo_btn.config(text="Stop Demo", bg=COLORS["critical"])
            self.conn_btn.config(state=tk.DISABLED)
            self.status_lbl.config(text="Demo Mode", style="StatusOK.TLabel")
        elif was_connected:
            self.conn_btn.config(text="Reconnect")
            self.disc_btn.config(state=tk.NORMAL)
            self.status_lbl.config(text="Connected", style="StatusOK.TLabel")

        self.notebook.select(2)

    def _on_temp_threshold_change(self, event=None):
        try:
            val = int(self.temp_threshold_var.get())
        except ValueError:
            return
        self.config["temp_threshold"] = val
        self._save_config()
        self._temp_alert_active = False

    # --- connection management ---
    def _on_save(self):
        host = self.server_host_var.get().strip()
        if not host:
            messagebox.showerror("Error", "Please enter the TrueMonitor IP address or hostname.")
            return

        try:
            port = max(1024, min(65535, int(self.server_port_var.get().strip())))
        except ValueError:
            port = BROADCAST_DEFAULT_PORT

        key = self.server_key_var.get().strip() or BROADCAST_DEFAULT_KEY

        try:
            temp_thresh = max(1, int(self.temp_threshold_var.get().strip()))
        except ValueError:
            temp_thresh = 82

        self.config = {
            "server_host": host,
            "server_port": port,
            "server_key": key,
            "temp_threshold": temp_thresh,
            "font_size": self.font_size_var.get(),
        }
        self._save_config()
        self._connect()

    def _connect(self):
        self._disconnect()
        host = self.config.get("server_host", "")
        port = self.config.get("server_port", BROADCAST_DEFAULT_PORT)
        key = self.config.get("server_key", BROADCAST_DEFAULT_KEY)
        self.status_lbl.config(
            text=f"Connecting to {host}:{port}...", style="Status.TLabel")
        self.conn_btn.config(state=tk.DISABLED)

        self.monitor_client = MonitorClient(
            host=host, port=port, passphrase=key,
            on_stats=lambda s: self.root.after(0, lambda ss=s: self._refresh(ss)),
            on_error=lambda e: self.root.after(0, lambda msg=e: self._on_conn_error(msg)),
            on_connected=lambda: self.root.after(0, self._on_connected),
            on_disconnected=lambda: self.root.after(0, self._on_disconnected),
        )
        self.monitor_client.start()

    def _on_connected(self):
        host = self.config.get("server_host", "")
        port = self.config.get("server_port", BROADCAST_DEFAULT_PORT)
        self.connected = True
        self.status_lbl.config(
            text=f"Connected to {host}:{port}", style="StatusOK.TLabel")
        self.conn_btn.config(text="Reconnect", state=tk.NORMAL)
        self.disc_btn.config(state=tk.NORMAL)
        self.notebook.select(0)

    def _on_conn_error(self, msg):
        self.footer.config(text=f"Error: {msg}", fg=COLORS["critical"])
        if not self.connected:
            self.status_lbl.config(text="Retrying...", style="Status.TLabel")

    def _on_disconnected(self):
        if self.connected:
            self.connected = False
            host = self.config.get("server_host", "")
            port = self.config.get("server_port", BROADCAST_DEFAULT_PORT)
            self.status_lbl.config(
                text=f"Lost connection — retrying {host}:{port}...",
                style="StatusErr.TLabel")
            self.footer.config(
                text=f"Disconnected at {datetime.now().strftime('%H:%M:%S')}",
                fg=COLORS["warning"])

    def _disconnect(self):
        if self.monitor_client:
            self.monitor_client.stop()
            self.monitor_client = None
        self.connected = False
        self.status_lbl.config(text="Disconnected", style="Status.TLabel")
        self.conn_btn.config(text="Save & Connect", state=tk.NORMAL)
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
        self._seen_truenas_alerts.clear()
        self.notebook.tab(1, text="  Alerts  ")
        for card in self.pool_cards.values():
            card["frame"].destroy()
        self.pool_cards = {}
        self._pool_count = 0
        import sys
        if sys.platform == "win32":
            self.root.geometry("760x560")
            self.root.minsize(660, 480)
        else:
            self.root.geometry("860x640")
            self.root.minsize(760, 560)
        self.info_lbl.config(text="Connect to TrueMonitor to begin monitoring")
        self.footer.config(text="")

    # --- UI refresh ---
    def _refresh(self, s):
        if s.get("clear_alerts_at"):
            self._clear_alerts(from_server=True)

        now = datetime.now().strftime("%H:%M:%S")
        self.footer.config(text=f"Last updated: {now}", fg=COLORS["text_dim"])

        host = s.get("hostname", "N/A")
        ver = s.get("version", "N/A")
        up = s.get("uptime", "N/A")
        la = s.get("loadavg", [0, 0, 0])
        la_s = ", ".join(f"{x:.2f}" for x in la) if la else "N/A"
        self.info_lbl.config(
            text=f"{host}  |  {ver}  |  Uptime: {up}  |  Load: {la_s}")

        cpu = s.get("cpu_percent")
        if cpu is not None:
            col = (COLORS["good"] if cpu < 70
                   else COLORS["warning"] if cpu < 90
                   else COLORS["critical"])
            self.cpu_card["value"].config(text=f"{cpu}%", foreground=col)
            self.cpu_card["bar_var"].set(cpu)
            self.cpu_card["sub"].config(text=f"Load avg: {la_s}")
        else:
            self.cpu_card["value"].config(text="N/A", foreground=COLORS["text_dim"])

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
            self.mem_card["value"].config(text="N/A", foreground=COLORS["text_dim"])
            if mt:
                self.mem_card["sub"].config(text=f"Total: {format_bytes(mt)}")

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

        self.net_rx_lbl.config(text=f"\u2193 {format_bytes(rx_val, per_second=True)}")
        self.net_tx_lbl.config(text=f"\u2191 {format_bytes(tx_val, per_second=True)}")
        self.net_iface_lbl.config(text=iface)
        self._draw_net_graph()

        temp = s.get("cpu_temp")
        if temp is not None:
            self.temp_history.append(temp)
            if len(self.temp_history) > self.HISTORY_LEN:
                self.temp_history = self.temp_history[-self.HISTORY_LEN:]
            col = (COLORS["good"] if temp < 60
                   else COLORS["warning"] if temp < 80
                   else COLORS["critical"])
            label = ("Normal" if temp < 60 else "Warm" if temp < 80 else "Hot!")
            self.temp_val_lbl.config(text=f"{temp}\u00b0C", fg=col)
            self.temp_status_lbl.config(text=label, fg=col)
            self._draw_temp_graph()
        else:
            self.temp_val_lbl.config(text="N/A", fg=COLORS["text_dim"])
            self.temp_status_lbl.config(text="")

        pools = s.get("pools", [])
        if pools:
            rebuild = len(pools) != self._pool_count
            if not rebuild:
                for pool in pools:
                    card = self.pool_cards.get(pool.get("name", ""))
                    if card and len(card.get("disk_rects", [])) != len(pool.get("disks", [])):
                        rebuild = True
                        break
            if rebuild:
                self._build_pool_cards(pools)
            for pool in pools:
                name = pool.get("name", "unknown")
                card = self.pool_cards.get(name)
                if not card:
                    continue
                pct = pool.get("percent", 0)
                used = pool.get("used", 0)
                total = pool.get("total", 0)
                avail = pool.get("available", 0)

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

                disks = pool.get("disks", [])
                for i, rect in enumerate(card.get("disk_rects", [])):
                    if i < len(disks):
                        disk_col = COLORS["critical"] if disks[i]["has_error"] else COLORS["good"]
                        rect._img.put(disk_col, to=(0, 0, 14, 20))

                topo = pool.get("topology", {})
                if topo:
                    card["topology"] = topo
                    card["map_btn"].config(
                        command=lambda n=name, t=topo: self._show_drive_map(n, t))

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
        self.poll_thread = threading.Thread(target=self._demo_poll, daemon=True)
        self.demo_btn.config(text="Stop Demo", bg=COLORS["critical"])
        self.status_lbl.config(text="Demo Mode", style="StatusOK.TLabel")
        self.conn_btn.config(state=tk.DISABLED)
        self.notebook.select(0)
        self._demo_cpu = 35.0
        self._demo_mem = 55.0
        self._demo_temp = 42.0
        self._demo_rx = 25_000_000.0
        self._demo_tx = 8_000_000.0
        self.poll_thread.start()

    def _stop_demo(self):
        self.demo_mode = False
        if self.poll_thread and self.poll_thread.is_alive():
            self.poll_thread.join(timeout=3)
        self.demo_btn.config(text="Demo Mode", bg=COLORS["warning"])
        self.conn_btn.config(state=tk.NORMAL)
        self.status_lbl.config(text="Disconnected", style="Status.TLabel")
        self._reset_cards()

    def _demo_poll(self):
        while self.demo_mode:
            self._demo_cpu = max(1, min(99, self._demo_cpu + random.uniform(-8, 8)))
            self._demo_mem = max(20, min(95, self._demo_mem + random.uniform(-3, 3)))
            self._demo_temp = max(30, min(88, self._demo_temp + random.uniform(-4, 4)))
            self._demo_rx = max(0, self._demo_rx + random.uniform(-5_000_000, 5_000_000))
            self._demo_tx = max(0, self._demo_tx + random.uniform(-2_000_000, 2_000_000))

            mem_total = 34_359_738_368
            mem_used = mem_total * self._demo_mem / 100

            demo_pools = [
                {"name": "tank",
                 "total": 8 * 1024**4,
                 "used": int(5.2 * 1024**4),
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
            time.sleep(2)

    def _on_close(self):
        self.demo_mode = False
        if self.monitor_client:
            self.monitor_client.stop()
            self.monitor_client = None
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
    TrueMonClientApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
