"""
gui/history_view.py
Window that lists past scans.
"""

import tkinter as tk
from tkinter import messagebox, ttk

from core.database import Database
from gui.theme import BG, FONT, make_tree, page_header, short_time


class HistoryWindow(tk.Toplevel):
    def __init__(self, parent, db=None):
        super().__init__(parent)
        self.title("Scan History")
        self.geometry("1000x500")
        self.configure(bg=BG)

        self.db = db or Database()
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        self.count_var = tk.StringVar(value="0 scan(s)")
        page_header(self, "Scan History", self.count_var,
                    "Every scan this app has run").pack(fill="x", padx=20, pady=(18, 8))

        cols = ("id", "type", "target", "started", "finished",
                "files", "threats", "errors", "duration", "status")
        widths = {
            "id": 45, "type": 70, "target": 260, "started": 140, "finished": 140,
            "files": 60, "threats": 65, "errors": 60, "duration": 75, "status": 85,
        }
        frame, self.tree = make_tree(self, cols, widths, selectmode="browse")
        frame.pack(fill="both", expand=True, padx=20, pady=6)

        btns = ttk.Frame(self, padding=(20, 10))
        btns.pack(fill="x")
        ttk.Button(btns, text="Refresh", command=self.refresh).pack(side="left", padx=5)
        ttk.Button(btns, text="Clear History", command=self.clear_history,
                   style="Danger.TButton").pack(side="left", padx=5)
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="right", padx=5)

    def refresh(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        rows = self.db.list_scans(limit=500)
        self.count_var.set(f"{len(rows)} scan(s)")

        for r in rows:
            self.tree.insert("", "end", values=(
                r["id"],
                r["scan_type"],
                r["target"],
                short_time(r["started_at"]),
                short_time(r["finished_at"]) if r["finished_at"] else "-",
                r["files_scanned"],
                r["threats_found"],
                r["errors_count"],
                f"{r['duration_seconds']:.2f}s",
                r["status"],
            ))

    def clear_history(self):
        if not messagebox.askyesno(
            "Clear History",
            "Delete all scan history records?\n\nThis cannot be undone.",
            parent=self,
        ):
            return
        n = self.db.clear_scans()
        self.refresh()
        messagebox.showinfo("History Cleared", f"Removed {n} record(s).", parent=self)