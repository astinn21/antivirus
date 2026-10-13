"""
gui/dashboard.py
Main dashboard: sidebar, protection status, scan launchers, animated scan
panel (radar dial + detection pipeline + live counters) and last-scan summary.
"""

import queue
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from config import APP_NAME, APP_VERSION
from core.database import Database
from core.models import ScanError, ScanResult
from core.monitor import MonitorManager
from core.quarantine import QuarantineManager
from core.scan_targets import get_full_scan_targets, get_quick_scan_targets
from core.scanner import FileScanner
from core.settings import Settings
from gui.history_view import HistoryWindow
from gui.monitor_view import MonitorWindow
from gui.quarantine_view import QuarantineWindow
from gui.settings_view import SettingsWindow
from gui.signatures_view import SignaturesWindow
from gui.theme import (
    ACCENT, ACCENT_FG, ACCENT_SOFT, BAD, BAD_SOFT, BG, F_BIG, F_BODY, F_BOLD,
    F_H1, F_H2, F_LABEL, F_MONO, F_SMALL, FONT, GOOD, LINE, MUTED, PANEL, RAISED,
    TEXT, Card, FlatButton, Pill, Pipeline, ScanDial, ShieldIcon, eyebrow,
    human_size, make_tree, page_header, short_time,
)


# ----------------------------------------------------------------------
# Small building blocks
# ----------------------------------------------------------------------

class StatCard(Card):
    """A dashboard tile showing a big number + label."""

    def __init__(self, parent, label: str, value: str = "0", colour: str = TEXT):
        super().__init__(parent)
        self.value_var = tk.StringVar(value=value)
        tk.Label(self, textvariable=self.value_var, font=F_BIG, fg=colour,
                 bg=PANEL, anchor="w").pack(anchor="w", padx=18, pady=(14, 0))
        eyebrow(self, label).pack(anchor="w", padx=18, pady=(0, 14))

    def set(self, value: str):
        self.value_var.set(value)


class NavItem(tk.Frame):
    """Sidebar row. Optional badge on the right."""

    def __init__(self, parent, text: str, command, active: bool = False):
        super().__init__(parent, bg=ACCENT_SOFT if active else PANEL, cursor="hand2")
        self._active = active
        self._cmd = command
        self.label = tk.Label(self, text=text, anchor="w", font=F_BOLD if active else F_BODY,
                              fg=ACCENT if active else MUTED,
                              bg=ACCENT_SOFT if active else PANEL, padx=14, pady=9)
        self.label.pack(side="left", fill="x", expand=True)
        self.badge = tk.Label(self, text="", font=(FONT, 8, "bold"), fg="#ffffff", bg=BAD,
                              padx=6)
        for w in (self, self.label, self.badge):
            w.bind("<Button-1>", lambda e: self._cmd())
            w.bind("<Enter>", lambda e: self._paint(True))
            w.bind("<Leave>", lambda e: self._paint(False))

    def _paint(self, hover: bool):
        if self._active:
            return
        bg = RAISED if hover else PANEL
        self.configure(bg=bg)
        self.label.configure(bg=bg, fg=TEXT if hover else MUTED)

    def set_badge(self, n: int):
        if n > 0:
            self.badge.configure(text=str(n))
            self.badge.pack(side="right", padx=(0, 12))
        else:
            self.badge.pack_forget()


class PickTile(tk.Frame):
    """Clickable scan launcher: drawn icon, title, one-line detail."""

    def __init__(self, parent, kind: str, title: str, detail: str, command):
        super().__init__(parent, bg=PANEL, highlightthickness=1, highlightbackground=LINE,
                         cursor="hand2", padx=12, pady=9)
        self._cmd = command
        self._enabled = True

        icon = tk.Canvas(self, width=38, height=38, bg=ACCENT_SOFT, highlightthickness=0)
        self._draw_icon(icon, kind)
        icon.grid(row=0, column=0, rowspan=2, padx=(0, 12))
        self.title = tk.Label(self, text=title, font=F_BOLD, fg=TEXT, bg=PANEL, anchor="w")
        self.detail = tk.Label(self, text=detail, font=F_SMALL, fg=MUTED, bg=PANEL,
                               anchor="w")
        self.go = tk.Label(self, text="Start  ›", font=F_SMALL, fg=MUTED, bg=PANEL)
        self.title.grid(row=0, column=1, sticky="w")
        self.detail.grid(row=1, column=1, sticky="w")
        self.go.grid(row=0, column=2, rowspan=2, padx=(14, 0))
        self.columnconfigure(1, weight=1)

        self._widgets = [self, icon, self.title, self.detail, self.go]
        for w in self._widgets:
            w.bind("<Button-1>", self._click)
            w.bind("<Enter>", lambda e: self._hover(True))
            w.bind("<Leave>", lambda e: self._hover(False))

    @staticmethod
    def _draw_icon(c: tk.Canvas, kind: str):
        col = ACCENT
        if kind == "quick":
            c.create_polygon(22, 7, 12, 22, 19, 22, 16, 32, 27, 16, 20, 16,
                             fill=col, outline=col, joinstyle="round")
        elif kind == "full":
            for r in (13, 8, 3):
                c.create_oval(19 - r, 19 - r, 19 + r, 19 + r, outline=col, width=2)
            c.create_line(19, 19, 29, 9, fill=col, width=2)
        else:
            c.create_polygon(8, 12, 16, 12, 18, 15, 30, 15, 30, 29, 8, 29,
                             outline=col, fill="", width=2, joinstyle="round")

    def _click(self, _e):
        if self._enabled:
            self._cmd()

    def _hover(self, on: bool):
        if not self._enabled:
            return
        bg = ACCENT_SOFT if on else PANEL
        for w in (self, self.title, self.detail, self.go):
            w.configure(bg=bg)
        self.configure(highlightbackground=ACCENT if on else LINE)
        self.go.configure(fg=ACCENT if on else MUTED)

    def set_enabled(self, enabled: bool):
        self._enabled = enabled
        self._hover(False)
        fg = TEXT if enabled else MUTED
        self.title.configure(fg=fg)
        for w in self._widgets:
            w.configure(cursor="hand2" if enabled else "arrow")


# ----------------------------------------------------------------------
# Dashboard
# ----------------------------------------------------------------------

class DashboardFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=0)

        self.db = Database()
        self.qm = QuarantineManager(db=self.db)
        self.settings = Settings(db=self.db)
        self.monitor = MonitorManager(
            db=self.db, quarantine_manager=self.qm,
            max_file_size_mb=self.settings.get_int("max_file_size_mb", 100),
        )

        self.scanner = None
        self._last_result = None
        self._progress = None                  # latest (current, total, path) from the scan thread
        self._done_queue = queue.Queue()       # scan thread -> GUI thread
        self._scan_tiles = []
        self._monitor_win = None
        self._t0 = 0.0
        self._tick = 0
        self._blips_drawn = 0
        self._mono_w = tkfont.Font(font=F_MONO).measure("0") or 7

        self.build_ui()
        self.refresh_stats()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def build_ui(self):
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self._build_sidebar().grid(row=0, column=0, sticky="nsw")
        body = tk.Frame(self, bg=BG)
        body.grid(row=0, column=1, sticky="nsew", padx=24, pady=(18, 14))
        body.columnconfigure(0, weight=1)
        self._build_body(body)

    def _build_sidebar(self) -> tk.Frame:
        side = tk.Frame(self, bg=PANEL, width=224, highlightthickness=1,
                        highlightbackground=LINE)
        side.grid_propagate(False)
        side.pack_propagate(False)

        brand = tk.Frame(side, bg=PANEL)
        brand.pack(fill="x", padx=16, pady=(20, 22))
        logo = ShieldIcon(brand, size=40)
        logo.pack(side="left")
        txt = tk.Frame(brand, bg=PANEL)
        txt.pack(side="left", padx=(10, 0))
        tk.Label(txt, text="Python Antivirus", font=(FONT, 10, "bold"), fg=TEXT, bg=PANEL,
                 anchor="w").pack(anchor="w")
        tk.Label(txt, text=f"System  ·  v{APP_VERSION}", font=F_SMALL, fg=MUTED,
                 bg=PANEL, anchor="w").pack(anchor="w")

        nav = tk.Frame(side, bg=PANEL)
        nav.pack(fill="x", padx=10)
        NavItem(nav, "Dashboard", lambda: None, active=True).pack(fill="x", pady=1)
        self.nav_quarantine = NavItem(nav, "Quarantine", self.open_quarantine)
        self.nav_quarantine.pack(fill="x", pady=1)
        for text, cmd in (
            ("Scan History", self.open_history),
            ("Signatures", self.open_signatures),
            ("Real-Time Monitor", self.open_monitor),
            ("Settings", self.open_settings),
        ):
            NavItem(nav, text, cmd).pack(fill="x", pady=1)

        tk.Label(side, text="Educational prototype.\nNot a replacement for\ncommercial antivirus\nsoftware.",
                 font=F_SMALL, fg=MUTED, bg=PANEL, justify="left", anchor="w") \
            .pack(side="bottom", anchor="w", padx=16, pady=16)
        return side

    def _build_body(self, body: tk.Frame):
        # --- Title row ---
        top = tk.Frame(body, bg=BG)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        left = tk.Frame(top, bg=BG)
        left.pack(side="left")
        tk.Label(left, text="Dashboard", font=F_H1, fg=TEXT, bg=BG).pack(anchor="w")
        tk.Label(left, text=APP_NAME + "  ·  protection status, scans and recent results",
                 font=F_SMALL, fg=MUTED, bg=BG).pack(anchor="w")
        self.status_pill = Pill(top, "Protected (demo)", "good")
        self.status_pill.pack(side="right")

        # --- Hero: shield + status + scan launchers ---
        hero = Card(body)
        hero.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        hero.columnconfigure(1, weight=1)
        hero.columnconfigure(2, weight=3)
        self.shield = ShieldIcon(hero, size=96)
        self.shield.grid(row=0, column=0, padx=(20, 6), pady=16)
        info = tk.Frame(hero, bg=PANEL)
        info.grid(row=0, column=1, sticky="w", padx=(6, 18))
        eyebrow(info, "Protection status").pack(anchor="w")
        self.hero_title = tk.Label(info, text="Your files are being watched",
                                   font=(FONT, 13, "bold"), fg=TEXT, bg=PANEL, anchor="w",
                                   justify="left", wraplength=210)
        self.hero_title.pack(anchor="w", pady=(2, 4))
        self.hero_sub = tk.Label(info, text="", font=F_SMALL, fg=MUTED, bg=PANEL,
                                 anchor="w", justify="left", wraplength=210)
        self.hero_sub.pack(anchor="w")

        picks = tk.Frame(hero, bg=PANEL)
        picks.grid(row=0, column=2, sticky="ew", padx=(0, 20), pady=16)
        picks.columnconfigure(0, weight=1)
        for i, (kind, title, detail, cmd) in enumerate((
            ("quick", "Quick scan", "Desktop, Downloads, Documents", self.start_quick_scan),
            ("full", "Full scan", "Walks your home folder", self.start_full_scan),
            ("custom", "Custom scan", "Choose a folder", self.start_custom_scan),
        )):
            t = PickTile(picks, kind, title, detail, cmd)
            t.grid(row=i, column=0, sticky="ew", pady=(0 if i == 0 else 6, 0))
            self._scan_tiles.append(t)

        # --- Stat tiles ---
        cards = tk.Frame(body, bg=BG)
        cards.grid(row=2, column=0, sticky="ew", pady=(0, 14))
        self.card_files = StatCard(cards, "Files scanned")
        self.card_threats = StatCard(cards, "Threats detected", colour=BAD)
        self.card_quarantine = StatCard(cards, "Quarantined")
        self.card_scans = StatCard(cards, "Total scans")
        for i, c in enumerate((self.card_files, self.card_threats,
                               self.card_quarantine, self.card_scans)):
            c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0 if i == 3 else 6))
            cards.columnconfigure(i, weight=1, uniform="stat")

        # --- Scan panel + last scan ---
        lower = tk.Frame(body, bg=BG)
        lower.grid(row=3, column=0, sticky="nsew")
        body.rowconfigure(3, weight=1)
        lower.columnconfigure(0, weight=5)
        lower.columnconfigure(1, weight=2, minsize=250)
        lower.rowconfigure(0, weight=1)
        self._build_scan_panel(lower).grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        self._build_last_scan(lower).grid(row=0, column=1, sticky="nsew", padx=(7, 0))

    def _build_scan_panel(self, parent) -> Card:
        card = Card(parent)
        card.columnconfigure(1, weight=1)

        self.dial = ScanDial(card, size=190)
        self.dial.grid(row=0, column=0, padx=(18, 10), pady=18, sticky="n")

        right = tk.Frame(card, bg=PANEL)
        right.grid(row=0, column=1, sticky="nsew", padx=(0, 16), pady=18)
        right.columnconfigure(0, weight=1)

        self.scan_kind = eyebrow(right, "No scan running")
        self.scan_kind.grid(row=0, column=0, sticky="w")

        ticker = tk.Frame(right, bg=BG, highlightthickness=1, highlightbackground=LINE)
        ticker.grid(row=1, column=0, sticky="ew", pady=(6, 10))
        self.progress_label = tk.Label(ticker, text="Idle. Start a scan to begin.",
                                       font=F_MONO, fg=MUTED, bg=BG, anchor="w",
                                       padx=10, pady=8)
        self.progress_label.pack(fill="x")

        self.pipeline = Pipeline(right)
        self.pipeline.grid(row=2, column=0, sticky="ew", pady=(0, 8))

        counters = tk.Frame(right, bg=PANEL)
        counters.grid(row=3, column=0, sticky="ew")
        self.c_files = self._counter(counters, 0, "Files")
        self.c_size = self._counter(counters, 1, "Size")
        self.c_threats = self._counter(counters, 2, "Threats", BAD)
        self.c_errors = self._counter(counters, 3, "Errors")
        self.c_time = self._counter(counters, 4, "Elapsed")
        self._reset_counters()

        self.cancel_btn = FlatButton(right, "Cancel scan", self.cancel_scan, kind="secondary",
                                     state="disabled")
        self.cancel_btn.grid(row=4, column=0, sticky="w", pady=(8, 0))
        return card

    @staticmethod
    def _counter(parent, col: int, label: str, colour: str = TEXT) -> tk.Label:
        f = tk.Frame(parent, bg=PANEL)
        f.grid(row=0, column=col, sticky="w", padx=(0, 10))
        v = tk.Label(f, text="0", font=(FONT, 13, "bold"), fg=colour, bg=PANEL, anchor="w")
        v.pack(anchor="w")
        eyebrow(f, label).pack(anchor="w")
        return v

    def _build_last_scan(self, parent) -> Card:
        card = Card(parent)
        tk.Label(card, text="Last scan", font=F_BOLD, fg=TEXT, bg=PANEL).pack(
            anchor="w", padx=18, pady=(16, 8))
        self.last_scan_body = tk.Frame(card, bg=PANEL)
        self.last_scan_body.pack(fill="both", expand=True, padx=18, pady=(0, 16))
        return card

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    def _set_status(self, kind: str, text: str):
        """kind: ok | bad | busy"""
        tone = {"ok": "good", "bad": "bad", "busy": "accent"}[kind]
        self.status_pill.set(text, tone)
        self.shield.set_state(kind)
        self.hero_title.configure(text={
            "ok": "Your files are being watched",
            "bad": "Threats need your attention",
            "busy": "Scan in progress",
        }[kind])

    def _reset_counters(self):
        self.c_files.configure(text="0")
        self.c_size.configure(text="0 B")
        self.c_threats.configure(text="0")
        self.c_errors.configure(text="0")
        self.c_time.configure(text="0:00")

    # ------------------------------------------------------------------
    # Stats refresh
    # ------------------------------------------------------------------

    def refresh_stats(self):
        total_files, total_threats = self.db.get_totals()
        quarantined = self.qm.count()

        self.card_files.set(f"{total_files:,}")
        self.card_threats.set(str(total_threats))
        self.card_quarantine.set(str(quarantined))
        self.card_scans.set(str(self.db.count_scans()))
        self.nav_quarantine.set_badge(quarantined)

        self.hero_sub.configure(
            text="Hash, signature and heuristic detection are active. "
                 "Run a scan to check your files.")

        for w in self.last_scan_body.winfo_children():
            w.destroy()
        last = self.db.get_last_completed_scan()
        if not last:
            tk.Label(self.last_scan_body, text="No scans yet. Run a quick scan to get started.",
                     font=F_BODY, fg=MUTED, bg=PANEL, justify="left", anchor="w",
                     wraplength=190).pack(anchor="w")
            return
        rows = (
            ("Type", str(last["scan_type"]).title()),
            ("Target", str(last["target"])),
            ("Finished", short_time(last["finished_at"]).replace(" ", "\n", 1)),
            ("Files", f"{last['files_scanned']:,}"),
            ("Threats", str(last["threats_found"])),
            ("Duration", f"{last['duration_seconds']:.2f}s"),
        )
        for i, (k, v) in enumerate(rows):
            tk.Label(self.last_scan_body, text=k, font=F_SMALL, fg=MUTED, bg=PANEL,
                     anchor="w").grid(row=i, column=0, sticky="nw", pady=3)
            bad = k == "Threats" and last["threats_found"]
            tk.Label(self.last_scan_body, text=v, font=F_BOLD if bad else F_BODY,
                     fg=BAD if bad else TEXT, bg=PANEL, anchor="w", justify="left",
                     wraplength=165).grid(row=i, column=1, sticky="nw", padx=(14, 0), pady=3)

    # ------------------------------------------------------------------
    # Scan actions
    # ------------------------------------------------------------------

    def _set_scan_buttons(self, enabled: bool):
        for t in self._scan_tiles:
            t.set_enabled(enabled)

    def _start_scan(self, scan_type: str, targets):
        if self.scanner is not None:
            messagebox.showwarning("Scan Running", "A scan is already in progress.")
            return

        targets = [Path(t) for t in targets if Path(t).exists()]
        if not targets:
            messagebox.showwarning("No Targets",
                                   "No valid folders to scan. Check Settings.")
            return

        label = ", ".join(str(t) for t in targets)
        self._reset_counters()
        self.scan_kind.configure(text=f"{scan_type} scan  ·  {len(targets)} folder(s)")
        self.progress_label.configure(text="Collecting files...", fg=TEXT)
        self.cancel_btn.config(state="normal")
        self._set_scan_buttons(False)
        self._set_status("busy", "Scanning")
        self._progress = None
        self._t0 = time.monotonic()
        self._tick = 0
        self._blips_drawn = 0
        self.dial.set_label("Scanning")
        self.dial.start()

        scanner = FileScanner(
            db=self.db,
            progress_callback=self._on_progress,
            scan_type=scan_type,
            max_file_size_mb=self.settings.get_int("max_file_size_mb", 100),
        )
        self.scanner = scanner
        threading.Thread(target=self._run_scan, args=(scanner, targets),
                         daemon=True).start()
        self.after(80, self._poll_scan)

    def start_quick_scan(self):
        self._start_scan("quick", get_quick_scan_targets(self.settings))

    def start_full_scan(self):
        targets = get_full_scan_targets(self.settings)
        if not targets:
            messagebox.showwarning("No Target",
                                   "Full scan target missing. Check Settings.")
            return
        if not messagebox.askyesno(
            "Full Scan",
            f"Full scan will walk:\n{targets[0]}\n\n"
            "This may take a while. Continue?"
        ):
            return
        self._start_scan("full", targets)

    def start_custom_scan(self):
        folder_str = filedialog.askdirectory(title="Select a folder to scan")
        if not folder_str:
            return
        self._start_scan("custom", [folder_str])

    # --- worker thread ------------------------------------------------

    def _run_scan(self, scanner: FileScanner, targets):
        try:
            result = scanner.scan_paths(targets)
        except Exception as e:
            result = ScanResult(target=targets[0], targets=list(targets),
                                status="failed")
            result.errors.append(ScanError(targets[0], f"Scan crashed: {e}"))
        self._done_queue.put(result)

    def _on_progress(self, current: int, total: int, current_path: str):
        # Called from the worker thread. Just remember the latest value;
        # the GUI thread reads it in _poll_scan (Tk is not thread-safe).
        self._progress = (current, total, current_path)

    # --- GUI thread ---------------------------------------------------

    def _poll_scan(self):
        scanner = self.scanner
        p = self._progress
        if p is not None and scanner is not None:
            current, total, path = p
            live = scanner.live
            if total > 0:
                self.dial.set_progress(current / total)
            width = self.progress_label.winfo_width()
            max_chars = max(24, (width - 24) // self._mono_w) if width > 1 else 40
            short = path if len(path) <= max_chars else "..." + path[-(max_chars - 3):]
            self.progress_label.configure(text=short, fg=TEXT)

            self.c_files.configure(text=f"{current:,}")
            self.c_size.configure(text=human_size(live["size"]))
            self.c_threats.configure(text=str(live["threats"]))
            self.c_errors.configure(text=str(live["errors"]))
            secs = int(time.monotonic() - self._t0)
            self.c_time.configure(text=f"{secs // 60}:{secs % 60:02d}")

            # Radar blip per new threat
            while self._blips_drawn < live["threats"]:
                self.dial.add_blip()
                self._blips_drawn += 1

            # Pipeline: cycle the stage highlight; flash the stage(s) that matched
            self._tick += 1
            active = ("hash", "signature", "rule")[self._tick % 3]
            hits = live["methods"] if live["detected"] else ()
            self.pipeline.set(active, hits)
        elif scanner is not None:
            secs = int(time.monotonic() - self._t0)
            self.c_time.configure(text=f"{secs // 60}:{secs % 60:02d}")

        try:
            result = self._done_queue.get_nowait()
        except queue.Empty:
            if self.scanner is not None:
                self.after(80, self._poll_scan)
            return

        self._on_scan_finished(result)

    def _on_scan_finished(self, result: ScanResult):
        self.scanner = None
        self.cancel_btn.config(state="disabled")
        self._set_scan_buttons(True)
        self._last_result = result
        self.dial.stop()
        self.pipeline.set()

        secs = int(time.monotonic() - self._t0)
        self.c_time.configure(text=f"{secs // 60}:{secs % 60:02d}")
        self.c_files.configure(text=f"{result.file_count:,}")
        self.c_size.configure(text=human_size(result.total_size))
        self.c_threats.configure(text=str(result.threat_count))
        self.c_errors.configure(text=str(result.error_count))

        if result.status == "cancelled":
            self.dial.set_label("Cancelled")
            self.progress_label.configure(
                text=f"Scan cancelled. {result.file_count} files checked, "
                     f"{result.threat_count} threats.", fg=MUTED)
        else:
            self.dial.set_progress(1.0)
            self.dial.set_label("Done" if result.status == "completed" else result.status)
            self.progress_label.configure(
                text=f"Scan {result.status}. {result.file_count} files, "
                     f"{result.threat_count} threats, {result.error_count} errors.",
                fg=MUTED)

        if result.threat_count > 0:
            self._set_status("bad", f"{result.threat_count} threat(s) detected")
        else:
            self._set_status("ok", "No threats found")

        self.refresh_stats()
        self._show_result_popup(result)

    def cancel_scan(self):
        if self.scanner is not None:
            self.scanner.cancel()
            self.progress_label.configure(text="Cancelling...", fg=MUTED)
            self.cancel_btn.config(state="disabled")

    # ------------------------------------------------------------------
    # Scan result popup
    # ------------------------------------------------------------------

    def _show_result_popup(self, result: ScanResult):
        win = tk.Toplevel(self)
        win.title("Scan Result")
        win.geometry("1040x560")
        win.configure(bg=BG)
        win.transient(self.winfo_toplevel())

        hdr = page_header(win, "Scan result", subtitle=f"Target: {result.label}")
        hdr.pack(fill="x", padx=20, pady=(18, 8))

        chips = tk.Frame(win, bg=BG)
        chips.pack(fill="x", padx=20, pady=(0, 10))
        Pill(chips, result.status, "good" if result.status == "completed" else "neutral",
             dot=False).pack(side="left", padx=(0, 8))
        for text, tone in (
            (f"{result.file_count:,} files", "neutral"),
            (human_size(result.total_size), "neutral"),
            (f"{result.threat_count} threats", "bad" if result.threat_count else "good"),
            (f"{result.error_count} errors", "neutral"),
        ):
            Pill(chips, text, tone, dot=False).pack(side="left", padx=(0, 8))

        btns = tk.Frame(win, bg=BG)
        btns.pack(side="bottom", fill="x", padx=20, pady=(8, 16))

        if not result.detected_files:
            empty = Card(win)
            empty.pack(fill="both", expand=True, padx=20, pady=4)
            ShieldIcon(empty, size=84).pack(pady=(60, 8))
            tk.Label(empty, text="Nothing suspicious", font=F_H2, fg=TEXT, bg=PANEL).pack()
            tk.Label(empty, text="No file matched a hash, signature or heuristic rule.",
                     font=F_BODY, fg=MUTED, bg=PANEL).pack(pady=(2, 0))
            FlatButton(btns, "Close", win.destroy, kind="primary").pack(side="right")
            return

        cols = ("path", "method", "threat", "severity", "reason")
        frame, tree = make_tree(
            win, cols,
            {"path": 270, "method": 100, "threat": 160, "severity": 70, "reason": 340},
        )
        frame.pack(fill="both", expand=True, padx=20, pady=4)

        items = {}
        for f in result.detected_files:
            methods = ",".join(f.detection_methods)
            reason = " | ".join(f.reasons)
            iid = tree.insert("", "end", values=(
                str(f.path), methods, f.threat_name or "", f.severity or "", reason,
            ))
            items[iid] = f

        def quarantine_selected():
            selected = tree.selection()
            if not selected:
                messagebox.showinfo("Nothing selected",
                                    "Select one or more files to quarantine.",
                                    parent=win)
                return
            if self.settings.get_bool("confirm_before_quarantine", True):
                if not messagebox.askyesno(
                    "Confirm Quarantine",
                    f"Move {len(selected)} file(s) into quarantine?",
                    parent=win,
                ):
                    return
            ok, failed = 0, 0
            for iid in selected:
                info = items.get(iid)
                if info is None:
                    continue
                entry = self.qm.quarantine_file(
                    path=info.path, threat_name=info.threat_name,
                    severity=info.severity, sha256=info.sha256,
                )
                if entry is not None:
                    ok += 1
                    tree.delete(iid)
                else:
                    failed += 1
            self.refresh_stats()
            messagebox.showinfo("Quarantine Complete",
                                f"Quarantined: {ok}\nFailed: {failed}", parent=win)

        FlatButton(btns, "Quarantine selected", quarantine_selected, kind="primary") \
            .pack(side="left")
        FlatButton(btns, "Select all",
                   lambda: tree.selection_set(tree.get_children()),
                   kind="secondary").pack(side="left", padx=8)
        FlatButton(btns, "Close", win.destroy, kind="secondary").pack(side="right")

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def _open_window(self, window_cls):
        win = window_cls(self, db=self.db)
        win.bind("<Destroy>", lambda e, w=win: self._on_child_closed(e, w))
        return win

    def _on_child_closed(self, event, win):
        if event.widget is win:
            try:
                self.refresh_stats()
            except Exception:
                pass  # app is shutting down

    def open_quarantine(self):
        self._open_window(QuarantineWindow)

    def open_history(self):
        self._open_window(HistoryWindow)

    def open_settings(self):
        self._open_window(SettingsWindow)

    def open_signatures(self):
        self._open_window(SignaturesWindow)

    def open_monitor(self):
        if self._monitor_win is not None and self._monitor_win.winfo_exists():
            self._monitor_win.lift()
            return
        self._monitor_win = MonitorWindow(self, self.monitor, db=self.db)

    # ------------------------------------------------------------------

    def shutdown(self):
        """Called when the main window closes."""
        if self.scanner is not None:
            self.scanner.cancel()
        try:
            self.monitor.stop()
        except Exception:
            pass