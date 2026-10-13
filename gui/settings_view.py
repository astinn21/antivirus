"""
gui/settings_view.py
Settings window for scan preferences.
"""
 
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
 
from core.database import Database
from core.settings import DEFAULTS, Settings
from gui.theme import BG, FONT, MUTED, page_header
 
 
class SettingsWindow(tk.Toplevel):
    def __init__(self, parent, db=None):
        super().__init__(parent)
        self.title("Settings")
        self.geometry("640x500")
        self.configure(bg=BG)
 
        self.settings = Settings(db=db or Database())
        self._build_ui()
        self._load()
 
    def _build_ui(self):
        pad = {"padx": 12, "pady": 6}
 
        page_header(self, "Settings", subtitle="Scan paths, limits and quarantine behaviour") \
            .pack(fill="x", padx=12, pady=(16, 8))
 
        # --- Buttons (packed first so they never get pushed off-screen) ---
        btns = ttk.Frame(self, padding=10)
        btns.pack(fill="x", side="bottom")
        ttk.Button(btns, text="Save", command=self._save,
                   style="Accent.TButton").pack(side="right", padx=4)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right", padx=4)
        ttk.Button(btns, text="Reset to Defaults", command=self._reset) \
            .pack(side="left", padx=4)
 
        # --- Quick scan paths ---
        qf = ttk.LabelFrame(self, text="Quick Scan Paths", padding=10)
        qf.pack(fill="x", **pad)
 
        ttk.Label(qf, text="Comma-separated list of folders. Leave blank for defaults.",
                  font=(FONT, 9)).pack(anchor="w")
 
        self.quick_var = tk.StringVar()
        ttk.Entry(qf, textvariable=self.quick_var).pack(fill="x", pady=(6, 4))
 
        ttk.Label(qf, text="Defaults: Desktop, Downloads, Documents, Temp",
                  font=(FONT, 8, "italic"), foreground=MUTED).pack(anchor="w")
 
        # --- Full scan path ---
        ff = ttk.LabelFrame(self, text="Full Scan Path", padding=10)
        ff.pack(fill="x", **pad)
 
        ttk.Label(ff, text="Root folder for Full Scan. Leave blank to use your home folder.",
                  font=(FONT, 9)).pack(anchor="w")
 
        row = ttk.Frame(ff)
        row.pack(fill="x", pady=(6, 0))
        self.full_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.full_var).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse...", command=self._browse_full) \
            .pack(side="left", padx=6)
 
        # --- File handling ---
        sf = ttk.LabelFrame(self, text="File Handling", padding=10)
        sf.pack(fill="x", **pad)
 
        ttk.Label(sf, text="Skip files larger than (MB):", font=(FONT, 9)).grid(
            row=0, column=0, sticky="w", pady=4)
        self.size_var = tk.StringVar()
        ttk.Entry(sf, textvariable=self.size_var, width=10).grid(
            row=0, column=1, sticky="w", padx=8)
 
        self.confirm_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(sf, text="Ask before quarantining files",
                        variable=self.confirm_var).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=4)
 
    # ------------------------------------------------------------------
 
    def _load(self):
        self.quick_var.set(self.settings.get("quick_scan_paths", DEFAULTS["quick_scan_paths"]))
        self.full_var.set(self.settings.get("full_scan_path", DEFAULTS["full_scan_path"]))
        self.size_var.set(self.settings.get("max_file_size_mb", DEFAULTS["max_file_size_mb"]))
        self.confirm_var.set(self.settings.get_bool("confirm_before_quarantine", True))
 
    def _save(self):
        try:
            size = int(self.size_var.get().strip())
            if size <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Value",
                                 "Max file size must be a whole number greater than 0.",
                                 parent=self)
            return
 
        self.settings.set("quick_scan_paths", self.quick_var.get().strip())
        self.settings.set("full_scan_path", self.full_var.get().strip())
        self.settings.set("max_file_size_mb", str(size))
        self.settings.set("confirm_before_quarantine",
                          "true" if self.confirm_var.get() else "false")
        messagebox.showinfo("Saved", "Settings saved.", parent=self)
        self.destroy()
 
    def _reset(self):
        if not messagebox.askyesno("Reset", "Reset all settings to defaults?", parent=self):
            return
        for k, v in DEFAULTS.items():
            self.settings.set(k, v)
        self._load()
 
    def _browse_full(self):
        folder = filedialog.askdirectory(parent=self, title="Choose Full Scan folder")
        if folder:
            self.full_var.set(folder)
 
