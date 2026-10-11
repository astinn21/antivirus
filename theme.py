"""
gui/theme.py
Shared colours, ttk styling and small helpers for every window.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Sequence, Tuple


# ---------- Colours ----------
BG = "#1e1e2e"
CARD_BG = "#2a2a3d"
HEADER_BG = "#33334d"
TEXT = "#e0e0e0"
MUTED = "#9a9ab0"
GREEN = "#4caf50"
RED = "#e53935"
YELLOW = "#ffb300"
ACCENT = "#5c6bc0"
ACCENT_HOVER = "#7986cb"


def apply_theme(root: tk.Misc) -> None:
    """Configure the global ttk style. Call once, on the root window."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(".", background=BG, foreground=TEXT, fieldbackground=CARD_BG)

    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=CARD_BG, relief="flat")

    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Header.TLabel", font=("Segoe UI", 22, "bold"))
    style.configure("Sub.TLabel", font=("Segoe UI", 10), foreground=MUTED, background=BG)
    style.configure("Card.TLabel", background=CARD_BG, foreground=TEXT)
    style.configure("Section.TLabel", font=("Segoe UI", 12, "bold"))

    style.configure("TLabelframe", background=BG, bordercolor=HEADER_BG)
    style.configure("TLabelframe.Label", background=BG, foreground=TEXT)

    style.configure("TButton", padding=8, background=CARD_BG, foreground=TEXT,
                    bordercolor=HEADER_BG)
    style.map("TButton",
              background=[("active", HEADER_BG), ("disabled", BG)],
              foreground=[("disabled", MUTED)])
    style.configure("Accent.TButton", background=ACCENT, foreground="white")
    style.map("Accent.TButton",
              background=[("active", ACCENT_HOVER), ("disabled", CARD_BG)],
              foreground=[("disabled", MUTED)])

    style.configure("TCheckbutton", background=BG, foreground=TEXT)
    style.map("TCheckbutton", background=[("active", BG)])

    style.configure("TEntry", fieldbackground=CARD_BG, foreground=TEXT,
                    insertcolor=TEXT, bordercolor=HEADER_BG)

    style.configure("Treeview", background=CARD_BG, fieldbackground=CARD_BG,
                    foreground=TEXT, rowheight=24, borderwidth=0)
    style.configure("Treeview.Heading", background=HEADER_BG, foreground=TEXT,
                    relief="flat", padding=4)
    style.map("Treeview",
              background=[("selected", ACCENT)],
              foreground=[("selected", "white")])
    style.map("Treeview.Heading", background=[("active", HEADER_BG)])

    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=CARD_BG, foreground=TEXT,
                    padding=(12, 5))
    style.map("TNotebook.Tab",
              background=[("selected", ACCENT)],
              foreground=[("selected", "white")])

    style.configure("TProgressbar", troughcolor=CARD_BG, background=ACCENT,
                    bordercolor=BG, lightcolor=ACCENT, darkcolor=ACCENT)
    style.configure("Vertical.TScrollbar", background=HEADER_BG,
                    troughcolor=CARD_BG, bordercolor=BG, arrowcolor=TEXT)

    try:
        root.configure(bg=BG)
    except tk.TclError:
        pass


def make_tree(parent: tk.Misc, columns: Sequence[str], widths: Dict[str, int],
              selectmode: str = "extended") -> Tuple[ttk.Frame, ttk.Treeview]:
    """
    Build a Treeview with a vertical scrollbar.
    Returns (frame, tree). The caller packs/grids the frame.
    """
    frame = ttk.Frame(parent)
    tree = ttk.Treeview(frame, columns=tuple(columns), show="headings",
                        selectmode=selectmode)
    vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)

    for c in columns:
        tree.heading(c, text=c.replace("_", " ").title())
        tree.column(c, width=widths.get(c, 120), anchor="w")

    tree.pack(side="left", fill="both", expand=True)
    vsb.pack(side="right", fill="y")
    return frame, tree


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def short_time(ts) -> str:
    if not ts:
        return "Never"
    return str(ts).replace("T", " ")[:19]
