"""
gui/signatures_view.py
View, add and remove hash signatures and byte-pattern signatures.
"""

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from core.database import Database
from gui.theme import BG, FONT, make_tree, page_header


VALID_SEVERITIES = ("low", "medium", "high")
MIN_PATTERN_BYTES = 4  # shorter patterns would match far too many files


class SignaturesWindow(tk.Toplevel):
    def __init__(self, parent, db=None):
        super().__init__(parent)
        self.title("Detection Signatures")
        self.geometry("820x520")
        self.configure(bg=BG)

        self.db = db or Database()
        self._build_ui()
        self.refresh()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self):
        self.summary_var = tk.StringVar()
        page_header(self, "Detection Signatures", self.summary_var,
                    "Known hashes and byte patterns the scanner looks for"
                    ).pack(fill="x", padx=20, pady=(18, 8))

        ttk.Button(self, text="Close", command=self.destroy) \
            .pack(side="bottom", anchor="e", padx=20, pady=12)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=20, pady=4)

        # --- Hash tab ---
        hash_tab = ttk.Frame(nb, padding=8)
        nb.add(hash_tab, text="Hash signatures")
        frame, self.hash_tree = make_tree(
            hash_tab, ("sha256", "name", "severity", "added_on"),
            {"sha256": 300, "name": 170, "severity": 80, "added_on": 140},
        )
        frame.pack(fill="both", expand=True)

        row = ttk.Frame(hash_tab)
        row.pack(fill="x", pady=(8, 0))
        ttk.Button(row, text="Add Hash...", command=self.add_hash,
                   style="Accent.TButton").pack(side="left")
        ttk.Button(row, text="Remove Selected", command=self.remove_hash) \
            .pack(side="left", padx=8)

        # --- Byte signature tab ---
        sig_tab = ttk.Frame(nb, padding=8)
        nb.add(sig_tab, text="Byte signatures")
        frame, self.sig_tree = make_tree(
            sig_tab, ("name", "pattern_hex", "severity", "description"),
            {"name": 160, "pattern_hex": 260, "severity": 80, "description": 200},
        )
        frame.pack(fill="both", expand=True)

        row = ttk.Frame(sig_tab)
        row.pack(fill="x", pady=(8, 0))
        ttk.Button(row, text="Add Signature...", command=self.add_signature,
                   style="Accent.TButton").pack(side="left")
        ttk.Button(row, text="Remove Selected", command=self.remove_signature) \
            .pack(side="left", padx=8)

    def refresh(self):
        for tree in (self.hash_tree, self.sig_tree):
            for item in tree.get_children():
                tree.delete(item)

        for r in self.db.list_threats():
            self.hash_tree.insert("", "end", iid=r["sha256"], values=(
                r["sha256"], r["name"], r["severity"], r["added_on"]))
        for r in self.db.list_signatures():
            self.sig_tree.insert("", "end", iid=r["name"], values=(
                r["name"], r["pattern_hex"], r["severity"], r["description"] or ""))

        self.summary_var.set(
            f"Hash signatures: {self.db.count_threats()}   |   "
            f"Byte signatures: {self.db.count_signatures()}"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ask_severity(self):
        sev = simpledialog.askstring(
            "Severity", "Severity (low / medium / high):",
            initialvalue="medium", parent=self)
        if sev is None:
            return None
        sev = sev.strip().lower()
        if sev not in VALID_SEVERITIES:
            messagebox.showerror("Invalid Severity",
                                 "Severity must be low, medium or high.", parent=self)
            return None
        return sev

    # ------------------------------------------------------------------
    # Hash signatures
    # ------------------------------------------------------------------

    def add_hash(self):
        digest = simpledialog.askstring(
            "Add Hash", "SHA-256 (64 hex characters):", parent=self)
        if not digest:
            return
        digest = digest.strip().lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            messagebox.showerror("Invalid Hash",
                                 "A SHA-256 hash is exactly 64 hex characters.",
                                 parent=self)
            return

        name = simpledialog.askstring("Add Hash", "Threat name:", parent=self)
        if not name or not name.strip():
            return
        sev = self._ask_severity()
        if sev is None:
            return

        if self.db.add_threat(digest, name.strip(), sev):
            self.refresh()
        else:
            messagebox.showerror("Duplicate", "That hash is already in the list.",
                                 parent=self)

    def remove_hash(self):
        selected = self.hash_tree.selection()
        if not selected:
            messagebox.showinfo("Nothing selected", "Select a hash to remove.",
                                parent=self)
            return
        for iid in selected:
            self.db.remove_threat(iid)
        self.refresh()

    # ------------------------------------------------------------------
    # Byte signatures
    # ------------------------------------------------------------------

    def add_signature(self):
        name = simpledialog.askstring("Add Signature", "Signature name:", parent=self)
        if not name or not name.strip():
            return

        raw = simpledialog.askstring(
            "Add Signature",
            "Pattern to look for inside files.\n"
            "Plain text, or start with  hex:  for raw bytes (e.g. hex:4d5a9000).",
            parent=self)
        if not raw:
            return

        if raw.lower().startswith("hex:"):
            try:
                pattern = bytes.fromhex(raw[4:].replace(" ", ""))
            except ValueError:
                messagebox.showerror("Invalid Hex", "That is not valid hex.",
                                     parent=self)
                return
        else:
            pattern = raw.encode("utf-8")

        if len(pattern) < MIN_PATTERN_BYTES:
            messagebox.showerror(
                "Pattern Too Short",
                f"Use at least {MIN_PATTERN_BYTES} bytes, or the signature "
                "will match far too many files.", parent=self)
            return

        sev = self._ask_severity()
        if sev is None:
            return

        if self.db.add_signature(name.strip(), pattern, severity=sev):
            self.refresh()
        else:
            messagebox.showerror("Duplicate",
                                 "A signature with that name already exists.",
                                 parent=self)

    def remove_signature(self):
        selected = self.sig_tree.selection()
        if not selected:
            messagebox.showinfo("Nothing selected", "Select a signature to remove.",
                                parent=self)
            return
        for iid in selected:
            self.db.remove_signature(iid)
        self.refresh()