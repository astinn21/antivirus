"""
gui/dashboard.py
Main dashboard: stats, scan buttons, tools and scan progress.
"""

import queue
import threading
import tkinter as tk
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
    BG, CARD_BG, GREEN, MUTED, RED, TEXT,
    human_size, make_tree, short_time,
)


class StatCard(ttk.Frame):
    """A small dashboard card showing a number + label."""

    def __init__(self, parent, label: str, value: str = "0", colour: str = TEXT):
        super().__init__(parent, padding=12, style="Card.TFrame")
        self.value_var = tk.StringVar(value=value)

        ttk.Label(self, textvariable=self.value_var,
                  font=("Segoe UI", 20, "bold"),
                  foreground=colour, background=CARD_BG).pack(anchor="w")
        ttk.Label(self, text=label,
                  font=("Segoe UI", 9),
                  foreground=MUTED, background=CARD_BG).pack(anchor="w")

    def set(self, value: str):
        self.value_var.set(value)


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
        self._scan_buttons = []
        self._monitor_win = None

        self.build_ui()
        self.refresh_stats()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def build_ui(self):
        # Footer first: with side="bottom" it must be packed BEFORE the
        # other sections or it is the first thing to get clipped.
        ttk.Label(
            self,
            text="Educational prototype - Not a replacement for commercial antivirus software.",
            style="Sub.TLabel",
        ).pack(side="bottom", pady=8)

        # Header
        header = ttk.Frame(self, padding=(24, 16, 24, 6))
        header.pack(fill="x")
        ttk.Label(header, text=APP_NAME, style="Header.TLabel").pack(side="left")
        ttk.Label(header, text=f"v{APP_VERSION}", style="Sub.TLabel") \
            .pack(side="right", padx=8)

        # Status pill
        status_frame = ttk.Frame(self, padding=(24, 0, 24, 10))
        status_frame.pack(fill="x")

        self.status_label = tk.Label(
            status_frame, text="  ● PROTECTED (DEMO)  ",
            font=("Segoe UI", 11, "bold"),
            bg=GREEN, fg="white", padx=10, pady=6,
        )
        self.status_label.pack(anchor="w")

        # Stat cards row
        cards = ttk.Frame(self, padding=(24, 0, 24, 10))
        cards.pack(fill="x")

        self.card_files = StatCard(cards, "FILES SCANNED")
        self.card_threats = StatCard(cards, "THREATS DETECTED", colour=RED)
        self.card_quarantine = StatCard(cards, "QUARANTINED")
        self.card_scans = StatCard(cards, "TOTAL SCANS")

        self.card_files.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.card_threats.grid(row=0, column=1, sticky="nsew", padx=4)
        self.card_quarantine.grid(row=0, column=2, sticky="nsew", padx=4)
        self.card_scans.grid(row=0, column=3, sticky="nsew", padx=(8, 0))
        for i in range(4):
            cards.columnconfigure(i, weight=1)

        # Scan buttons
        actions = ttk.Frame(self, padding=(24, 0, 24, 10))
        actions.pack(fill="x")
        ttk.Label(actions, text="Scan", style="Section.TLabel") \
            .pack(anchor="w", pady=(0, 6))

        btn_row = ttk.Frame(actions)
        btn_row.pack(fill="x")

        for text, cmd in (
            ("⚡ Quick Scan", self.start_quick_scan),
            ("\U0001f6e1 Full Scan", self.start_full_scan),
            ("\U0001f4c1 Custom Scan", self.start_custom_scan),
        ):
            b = ttk.Button(btn_row, text=text, command=cmd, style="Accent.TButton")
            b.pack(side="left", padx=(0, 8))
            self._scan_buttons.append(b)

        # Tools row
        tools = ttk.Frame(self, padding=(24, 0, 24, 10))
        tools.pack(fill="x")
        ttk.Label(tools, text="Tools", style="Section.TLabel") \
            .pack(anchor="w", pady=(0, 6))

        tool_row = ttk.Frame(tools)
        tool_row.pack(fill="x")

        for text, cmd in (
            ("\U0001f512 Quarantine", self.open_quarantine),
            ("\U0001f4dc Scan History", self.open_history),
            ("\U0001f5c2 Signatures", self.open_signatures),
            ("\U0001f4e1 Real-Time Monitor", self.open_monitor),
            ("⚙ Settings", self.open_settings),
        ):
            ttk.Button(tool_row, text=text, command=cmd) \
                .pack(side="left", padx=(0, 8))

        # Last scan card
        last = ttk.LabelFrame(self, text="Last Scan", padding=12)
        last.pack(fill="x", padx=24, pady=(0, 10))
        self.last_scan_label = ttk.Label(last, text="No scans yet.")
        self.last_scan_label.pack(anchor="w")

        # Progress
        prog = ttk.LabelFrame(self, text="Scan Progress", padding=12)
        prog.pack(fill="x", padx=24, pady=(0, 10))

        self.progress_var = tk.IntVar(value=0)
        ttk.Progressbar(prog, orient="horizontal", mode="determinate",
                        variable=self.progress_var).pack(fill="x")
        self.progress_label = ttk.Label(prog, text="Idle.")
        self.progress_label.pack(anchor="w", pady=(6, 0))
        self.cancel_btn = ttk.Button(prog, text="Cancel Scan",
                                     command=self.cancel_scan, state="disabled")
        self.cancel_btn.pack(anchor="e", pady=(6, 0))

    # ------------------------------------------------------------------
    # Stats refresh
    # ------------------------------------------------------------------

    def refresh_stats(self):
        total_files, total_threats = self.db.get_totals()

        self.card_files.set(str(total_files))
        self.card_threats.set(str(total_threats))
        self.card_quarantine.set(str(self.qm.count()))
        self.card_scans.set(str(self.db.count_scans()))

        last = self.db.get_last_completed_scan()
        if last:
            self.last_scan_label.config(
                text=f"Type: {last['scan_type']}   Target: {last['target']}\n"
                     f"Finished: {short_time(last['finished_at'])}   "
                     f"Files: {last['files_scanned']}   "
                     f"Threats: {last['threats_found']}   "
                     f"Duration: {last['duration_seconds']:.2f}s",
                wraplength=820,
            )
        else:
            self.last_scan_label.config(text="No scans yet.")

    # ------------------------------------------------------------------
    # Scan actions
    # ------------------------------------------------------------------

    def _set_scan_buttons(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        for b in self._scan_buttons:
            b.config(state=state)

    def _start_scan(self, scan_type: str, targets):
        if self.scanner is not None:
            messagebox.showwarning("Scan Running", "A scan is already in progress.")
            return

        targets = [Path(t) for t in targets if Path(t).exists()]
        if not targets:
            messagebox.showwarning("No Targets",
                                   "No valid folders to scan. Check Settings.")
            return

        self.progress_var.set(0)
        self.progress_label.config(
            text=f"Starting {scan_type} scan on {len(targets)} folder(s)..."
        )
        self.cancel_btn.config(state="normal")
        self._set_scan_buttons(False)
        self._progress = None

        scanner = FileScanner(
            db=self.db,
            progress_callback=self._on_progress,
            scan_type=scan_type,
            max_file_size_mb=self.settings.get_int("max_file_size_mb", 100),
        )
        self.scanner = scanner
        threading.Thread(target=self._run_scan, args=(scanner, targets),
                         daemon=True).start()
        self.after(100, self._poll_scan)

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
        p = self._progress
        if p is not None:
            current, total, path = p
            if total > 0:
                self.progress_var.set(int(current / total * 100))
            short = path if len(path) < 70 else "..." + path[-67:]
            self.progress_label.config(text=f"[{current}/{total}] {short}")

        try:
            result = self._done_queue.get_nowait()
        except queue.Empty:
            if self.scanner is not None:
                self.after(100, self._poll_scan)
            return

        self._on_scan_finished(result)

    def _on_scan_finished(self, result: ScanResult):
        self.scanner = None
        self.cancel_btn.config(state="disabled")
        self._set_scan_buttons(True)
        self._last_result = result

        if result.status == "cancelled":
            self.progress_label.config(
                text=f"Scan cancelled. {result.file_count} files checked, "
                     f"{result.threat_count} threats."
            )
        else:
            self.progress_var.set(100)
            self.progress_label.config(
                text=f"Scan {result.status}. {result.file_count} files, "
                     f"{result.threat_count} threats, {result.error_count} errors."
            )

        if result.threat_count > 0:
            self.status_label.config(
                text=f"  ● {result.threat_count} THREAT(S) DETECTED  ", bg=RED)
        else:
            self.status_label.config(text="  ● NO THREATS FOUND  ", bg=GREEN)

        self.refresh_stats()
        self._show_result_popup(result)

    def cancel_scan(self):
        if self.scanner is not None:
            self.scanner.cancel()
            self.progress_label.config(text="Cancelling...")
            self.cancel_btn.config(state="disabled")

    # ------------------------------------------------------------------
    # Scan result popup
    # ------------------------------------------------------------------

    def _show_result_popup(self, result: ScanResult):
        win = tk.Toplevel(self)
        win.title("Scan Result")
        win.geometry("980x520")
        win.configure(bg=BG)

        ttk.Label(win, text=f"Target: {result.label}", wraplength=940,
                  font=("Segoe UI", 10, "bold")) \
            .pack(anchor="w", padx=12, pady=(12, 4))
        ttk.Label(
            win,
            text=f"Status: {result.status}   "
                 f"Files: {result.file_count}   "
                 f"Size: {human_size(result.total_size)}   "
                 f"Threats: {result.threat_count}   "
                 f"Errors: {result.error_count}",
            font=("Segoe UI", 10),
        ).pack(anchor="w", padx=12, pady=(0, 8))

        cols = ("path", "method", "threat", "severity", "reason")
        frame, tree = make_tree(
            win, cols,
            {"path": 260, "method": 100, "threat": 160, "severity": 70, "reason": 340},
        )
        frame.pack(fill="both", expand=True, padx=12, pady=8)

        items = {}
        for f in result.detected_files:
            methods = ",".join(f.detection_methods)
            reason = " | ".join(f.reasons)
            iid = tree.insert("", "end", values=(
                str(f.path), methods, f.threat_name or "", f.severity or "", reason,
            ))
            items[iid] = f

        btns = ttk.Frame(win, padding=8)
        btns.pack(fill="x", padx=12, pady=(0, 10))

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

        ttk.Button(btns, text="Quarantine Selected", command=quarantine_selected) \
            .pack(side="left", padx=5)
        ttk.Button(btns, text="Close", command=win.destroy).pack(side="right", padx=5)

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
