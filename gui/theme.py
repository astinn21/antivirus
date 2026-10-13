"""
gui/theme.py
Shared colours, ttk styling, custom widgets and small helpers for every window.

Design notes
- Dark indigo palette (same family as the original), with soft tinted fills
  for status instead of solid blocks.
- Custom widgets drawn on Canvas: ShieldIcon, ScanDial (progress ring + radar
  sweep + threat blips), Pipeline (hash -> signature -> rules).
- Every colour used by other modules is exported here. The old names
  (BG, CARD_BG, HEADER_BG, GREEN, RED, YELLOW ...) still work.
"""

import math
import sys
import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional, Sequence, Tuple


# ---------- Colours ----------
BG = "#151521"            # window background
PANEL = "#1f1f30"         # cards, sidebar
RAISED = "#2a2a41"        # buttons, table headers, inputs
ROW_ALT = "#24243a"       # zebra rows
LINE = "#38384f"          # hairlines and card borders
TEXT = "#e8e8f2"
MUTED = "#9a9ab4"
ACCENT = "#7886dc"
ACCENT_HOVER = "#8d9aea"
ACCENT_SOFT = "#2b2f57"
ACCENT_FG = "#11111c"
GOOD = "#55c47f"
GOOD_SOFT = "#1b3a2a"
BAD = "#f0605c"
BAD_SOFT = "#43202a"
WARN = "#ffb92e"
WARN_SOFT = "#43361a"
RADAR_BG = "#101019"

# Backwards-compatible names used by the other windows
CARD_BG = PANEL
HEADER_BG = RAISED
GREEN = GOOD
RED = BAD
YELLOW = WARN

# ---------- Fonts ----------
if sys.platform.startswith("win"):
    FONT, MONO = "Segoe UI", "Consolas"
elif sys.platform == "darwin":
    FONT, MONO = "Helvetica Neue", "Menlo"
else:
    FONT, MONO = "DejaVu Sans", "DejaVu Sans Mono"

F_BODY = (FONT, 10)
F_SMALL = (FONT, 9)
F_BOLD = (FONT, 10, "bold")
F_LABEL = (FONT, 8, "bold")          # uppercase eyebrow labels
F_H1 = (FONT, 20, "bold")
F_H2 = (FONT, 14, "bold")
F_BIG = (FONT, 24, "bold")
F_MONO = (MONO, 9)

SEVERITY_FG = {"high": BAD, "medium": WARN, "low": MUTED}
SEVERITY_BG = {"high": BAD_SOFT, "medium": WARN_SOFT, "low": ACCENT_SOFT}


def mix(c1: str, c2: str, t: float) -> str:
    """Blend two #rrggbb colours. t=0 -> c1, t=1 -> c2."""
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(round(x + (y - x) * t) for x, y in zip(a, b))


# ---------- ttk styling ----------
def apply_theme(root: tk.Misc) -> None:
    """Configure the global ttk style. Call once, on the root window."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(".", background=BG, foreground=TEXT, fieldbackground=RAISED,
                    bordercolor=LINE, lightcolor=BG, darkcolor=BG,
                    troughcolor=PANEL, focuscolor=BG, font=F_BODY)

    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=PANEL)

    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Header.TLabel", font=F_H1)
    style.configure("Sub.TLabel", font=F_SMALL, foreground=MUTED, background=BG)
    style.configure("Card.TLabel", background=PANEL, foreground=TEXT)
    style.configure("Section.TLabel", font=(FONT, 12, "bold"))

    style.configure("TLabelframe", background=BG, bordercolor=LINE,
                    lightcolor=LINE, darkcolor=LINE, relief="solid")
    style.configure("TLabelframe.Label", background=BG, foreground=MUTED,
                    font=F_BOLD)

    # Buttons: flat, no bevel
    flat = dict(padding=(14, 8), borderwidth=1, relief="flat", focuscolor=RAISED,
                font=F_BOLD)
    style.configure("TButton", background=RAISED, foreground=TEXT,
                    bordercolor=LINE, lightcolor=RAISED, darkcolor=RAISED, **flat)
    style.map("TButton",
              background=[("disabled", PANEL), ("active", LINE)],
              foreground=[("disabled", MUTED)],
              bordercolor=[("active", ACCENT)])
    style.configure("Accent.TButton", background=ACCENT, foreground=ACCENT_FG,
                    bordercolor=ACCENT, lightcolor=ACCENT, darkcolor=ACCENT,
                    focuscolor=ACCENT, **{k: v for k, v in flat.items() if k != "focuscolor"})
    style.map("Accent.TButton",
              background=[("disabled", PANEL), ("active", ACCENT_HOVER)],
              foreground=[("disabled", MUTED)],
              bordercolor=[("disabled", LINE), ("active", ACCENT_HOVER)])
    style.configure("Danger.TButton", background=BAD, foreground="#ffffff",
                    bordercolor=BAD, lightcolor=BAD, darkcolor=BAD,
                    focuscolor=BAD, **{k: v for k, v in flat.items() if k != "focuscolor"})
    style.map("Danger.TButton",
              background=[("disabled", PANEL), ("active", mix(BAD, "#ffffff", .15))],
              foreground=[("disabled", MUTED)],
              bordercolor=[("disabled", LINE)])

    style.configure("TCheckbutton", background=BG, foreground=TEXT,
                    indicatorbackground=RAISED, indicatorforeground=ACCENT)
    style.map("TCheckbutton", background=[("active", BG)],
              indicatorbackground=[("selected", ACCENT)])
    style.configure("TRadiobutton", background=BG, foreground=TEXT)
    style.map("TRadiobutton", background=[("active", BG)])

    style.configure("TEntry", fieldbackground=RAISED, foreground=TEXT,
                    insertcolor=TEXT, bordercolor=LINE, lightcolor=RAISED,
                    darkcolor=RAISED, padding=6)
    style.map("TEntry", bordercolor=[("focus", ACCENT)],
              lightcolor=[("focus", ACCENT)], darkcolor=[("focus", ACCENT)])
    style.configure("TSpinbox", fieldbackground=RAISED, foreground=TEXT,
                    arrowcolor=TEXT, bordercolor=LINE, padding=4)
    style.configure("TCombobox", fieldbackground=RAISED, foreground=TEXT,
                    arrowcolor=TEXT, bordercolor=LINE, padding=4)

    style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=TEXT, rowheight=30, borderwidth=0, font=F_BODY)
    style.configure("Treeview.Heading", background=RAISED, foreground=MUTED,
                    relief="flat", padding=(8, 7), font=F_LABEL, borderwidth=0)
    style.map("Treeview",
              background=[("selected", ACCENT_SOFT)],
              foreground=[("selected", TEXT)])
    style.map("Treeview.Heading", background=[("active", LINE)])
    style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
    style.configure("TNotebook.Tab", background=BG, foreground=MUTED,
                    padding=(16, 8), borderwidth=0, font=F_BOLD, bordercolor=BG,
                    lightcolor=BG, darkcolor=BG)
    style.map("TNotebook.Tab",
              background=[("selected", PANEL), ("active", RAISED)],
              foreground=[("selected", TEXT)])

    style.configure("TProgressbar", troughcolor=PANEL, background=ACCENT,
                    bordercolor=PANEL, lightcolor=ACCENT, darkcolor=ACCENT,
                    thickness=8)
    for orient in ("Vertical", "Horizontal"):
        style.configure(f"{orient}.TScrollbar", background=RAISED,
                        troughcolor=PANEL, bordercolor=PANEL, arrowcolor=MUTED,
                        lightcolor=RAISED, darkcolor=RAISED, gripcount=0, arrowsize=12)
        style.map(f"{orient}.TScrollbar", background=[("active", LINE)])

    try:
        root.configure(bg=BG)
    except tk.TclError:
        pass
    # Dropdown list of ttk.Combobox lives in a plain Tk listbox
    root.option_add("*TCombobox*Listbox.background", RAISED)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", ACCENT_FG)


# ---------- Tables ----------
def make_tree(parent: tk.Misc, columns: Sequence[str], widths: Dict[str, int],
              selectmode: str = "extended") -> Tuple[ttk.Frame, ttk.Treeview]:
    """
    Build a Treeview with a vertical scrollbar.
    Returns (frame, tree). The caller packs/grids the frame.

    Rows are striped automatically, and rows whose "severity" column is
    high / medium are tinted red / amber. Callers just use tree.insert().
    """
    frame = tk.Frame(parent, bg=PANEL, highlightthickness=1,
                     highlightbackground=LINE, highlightcolor=LINE)
    tree = ttk.Treeview(frame, columns=tuple(columns), show="headings",
                        selectmode=selectmode)
    vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)

    for c in columns:
        tree.heading(c, text=c.replace("_", " ").upper(), anchor="w")
        tree.column(c, width=widths.get(c, 120), anchor="w")

    tree.tag_configure("even", background=PANEL)
    tree.tag_configure("odd", background=ROW_ALT)
    tree.tag_configure("sev_high", foreground=BAD)
    tree.tag_configure("sev_medium", foreground=WARN)

    sev_idx = list(columns).index("severity") if "severity" in columns else None
    raw_insert = tree.insert

    def insert(parent_iid, index, iid=None, **kw):
        tags = list(kw.pop("tags", ()))
        tags.append("odd" if len(tree.get_children()) % 2 else "even")
        vals = kw.get("values")
        if sev_idx is not None and vals is not None and sev_idx < len(vals):
            sev = str(vals[sev_idx]).lower()
            if sev in ("high", "medium"):
                tags.append("sev_" + sev)
        kw["tags"] = tuple(tags)
        if iid is None:
            return raw_insert(parent_iid, index, **kw)
        return raw_insert(parent_iid, index, iid=iid, **kw)

    tree.insert = insert  # type: ignore[method-assign]

    tree.pack(side="left", fill="both", expand=True)
    vsb.pack(side="right", fill="y")
    return frame, tree


# ---------- Small widgets ----------
class Card(tk.Frame):
    """A bordered panel. Put children in it with pack/grid as normal."""

    def __init__(self, parent, padx=18, pady=16, **kw):
        super().__init__(parent, bg=PANEL, highlightthickness=1,
                         highlightbackground=LINE, highlightcolor=LINE, **kw)
        self.inner = self  # kept for readability at call sites
        self._padx, self._pady = padx, pady

    def pad(self, widget, **pack_kw):
        pack_kw.setdefault("padx", self._padx)
        widget.pack(**pack_kw)


def eyebrow(parent, text: str, bg: str = PANEL) -> tk.Label:
    return tk.Label(parent, text=text.upper(), font=F_LABEL, fg=MUTED, bg=bg)


class FlatButton(tk.Button):
    """Flat button with hover. kind: primary | secondary | danger."""

    KINDS = {
        "primary": (ACCENT, ACCENT_FG, ACCENT_HOVER),
        "secondary": (RAISED, TEXT, LINE),
        "danger": (BAD, "#ffffff", mix(BAD, "#ffffff", .15)),
    }

    def __init__(self, parent, text: str, command: Optional[Callable] = None,
                 kind: str = "secondary", **kw):
        bg, fg, hover = self.KINDS[kind]
        super().__init__(parent, text=text, command=command, bg=bg, fg=fg,
                         activebackground=hover, activeforeground=fg,
                         disabledforeground=MUTED, relief="flat", bd=0,
                         padx=16, pady=8, font=F_BOLD, cursor="hand2",
                         highlightthickness=0, **kw)
        self._bg, self._hover = bg, hover
        self.bind("<Enter>", lambda e: self["state"] != "disabled" and self.configure(bg=self._hover))
        self.bind("<Leave>", lambda e: self.configure(bg=self._bg if self["state"] != "disabled" else PANEL))

    def configure(self, cnf=None, **kw):  # keep disabled look in sync
        res = super().configure(cnf, **kw)
        if "state" in kw:
            super().configure(bg=PANEL if kw["state"] == "disabled" else self._bg,
                              cursor="arrow" if kw["state"] == "disabled" else "hand2")
        return res

    config = configure


class Pill(tk.Label):
    """Rounded-looking status chip (flat tinted label)."""

    TONES = {
        "good": (GOOD_SOFT, GOOD), "bad": (BAD_SOFT, BAD),
        "warn": (WARN_SOFT, WARN), "accent": (ACCENT_SOFT, ACCENT),
        "neutral": (RAISED, MUTED),
    }

    def __init__(self, parent, text: str = "", tone: str = "good", dot: bool = True,
                 **kw):
        self._dot = dot
        super().__init__(parent, font=(FONT, 9, "bold"), padx=12, pady=5, **kw)
        self.set(text, tone)

    def set(self, text: str, tone: str):
        bg, fg = self.TONES[tone]
        self.configure(text=("●  " if self._dot else "") + text.upper(), bg=bg, fg=fg)


class ShieldIcon(tk.Canvas):
    """Shield with a glow. States: ok (check), bad (!), busy (dots)."""

    def __init__(self, parent, size: int = 108, bg: str = PANEL):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0)
        self.size = size
        self._bg = bg
        self._phase = 0.0
        self._state = "ok"
        self._anim = None
        self._draw()
        self._pulse()

    def _pts(self):
        s = self.size
        pts = [(.5, .12), (.82, .24), (.82, .52), (.5, .88), (.18, .52), (.18, .24)]
        return [c * s for p in pts for c in p]

    def _draw(self):
        self.delete("all")
        s = self.size
        col = {"ok": GOOD, "bad": BAD, "busy": ACCENT}[self._state]
        soft = {"ok": GOOD_SOFT, "bad": BAD_SOFT, "busy": ACCENT_SOFT}[self._state]
        grow = 3 * math.sin(self._phase)
        self.create_oval(4 - grow, 4 - grow, s - 4 + grow, s - 4 + grow, fill=soft,
                         outline="", tags="glow")
        self.create_polygon(self._pts(), fill=col, outline=col, width=8,
                            joinstyle="round", tags="body")
        mark = self._bg if self._state != "busy" else self._bg
        if self._state == "ok":
            self.create_line(.37 * s, .5 * s, .46 * s, .59 * s, .64 * s, .38 * s,
                             fill=mark, width=max(4, s // 16), capstyle="round",
                             joinstyle="round")
        elif self._state == "bad":
            self.create_line(.5 * s, .32 * s, .5 * s, .55 * s, fill=mark,
                             width=max(4, s // 16), capstyle="round")
            self.create_oval(.5 * s - 3, .65 * s - 3, .5 * s + 3, .65 * s + 3,
                             fill=mark, outline="")
        else:
            for i in range(3):
                x = (.38 + i * .12) * s
                self.create_oval(x - 3.5, .5 * s - 3.5, x + 3.5, .5 * s + 3.5,
                                 fill=mark, outline="")

    def set_state(self, state: str):
        if state != self._state:
            self._state = state
            self._draw()

    def _pulse(self):
        try:
            self._phase += 0.12
            grow = 3 * math.sin(self._phase)
            s = self.size
            self.coords("glow", 4 - grow, 4 - grow, s - 4 + grow, s - 4 + grow)
            self._anim = self.after(60, self._pulse)
        except tk.TclError:
            pass

    def destroy(self):
        if self._anim:
            try:
                self.after_cancel(self._anim)
            except tk.TclError:
                pass
        super().destroy()


class ScanDial(tk.Canvas):
    """
    Progress ring around a radar. The radar sweeps while a scan runs and
    drops a pulsing red blip for every threat found.
    """

    SLICES = 16
    SLICE_DEG = 5

    def __init__(self, parent, size: int = 220, bg: str = PANEL):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0)
        self.size = size
        pad = 6
        inner = pad + 18
        self._inner = inner
        c = size / 2
        self._c = c
        self._r = c - inner

        self.create_oval(pad, pad, size - pad, size - pad, outline=RAISED, width=8)
        self._arc = self.create_arc(pad, pad, size - pad, size - pad, start=90,
                                    extent=0, style="arc", outline=ACCENT, width=8)
        self.create_oval(inner, inner, size - inner, size - inner, fill=RADAR_BG,
                         outline=LINE)
        for f in (.33, .66):
            r = self._r * f
            self.create_oval(c - r, c - r, c + r, c + r, outline=LINE)
        self.create_line(c, inner, c, size - inner, fill=LINE)
        self.create_line(inner, c, size - inner, c, fill=LINE)

        self._wedges: List[int] = []
        for i in range(self.SLICES):
            colour = mix(RADAR_BG, ACCENT, .6 * (1 - i / self.SLICES) ** 1.5)
            w = self.create_arc(inner, inner, size - inner, size - inner,
                                start=90 + i * self.SLICE_DEG, extent=self.SLICE_DEG,
                                style="pieslice", fill=colour, outline="",
                                state="hidden")
            self._wedges.append(w)

        self._pct = self.create_text(c, c - 6, text="0%", fill=TEXT,
                                     font=(FONT, int(size * .15), "bold"))
        self._label = self.create_text(c, c + size * .09, text="IDLE", fill=MUTED,
                                       font=F_LABEL)
        self._angle = 90.0
        self._running = False
        self._blips: List[dict] = []
        self._t = 0.0
        self._job = None

    # --- public API ---
    def set_progress(self, frac: float):
        frac = max(0.0, min(1.0, frac))
        self.itemconfigure(self._arc, extent=-min(359.9, frac * 360))
        self.itemconfigure(self._pct, text=f"{int(round(frac * 100))}%")

    def set_label(self, text: str):
        self.itemconfigure(self._label, text=text.upper())

    def start(self):
        self.clear_blips()
        self.set_progress(0)
        self._running = True
        for w in self._wedges:
            self.itemconfigure(w, state="normal")
        self.tag_raise(self._pct)
        self.tag_raise(self._label)
        if self._job is None:
            self._tick()

    def stop(self):
        self._running = False
        for w in self._wedges:
            self.itemconfigure(w, state="hidden")

    def add_blip(self):
        a = math.radians(self._angle + 20 + (len(self._blips) * 67) % 300)
        d = self._r * (.3 + .6 * ((len(self._blips) * 0.37) % 1))
        x, y = self._c + math.cos(a) * d, self._c - math.sin(a) * d
        while len(self._blips) >= 14:          # keep the radar readable
            old = self._blips.pop(0)
            self.delete(old["ring"])
            self.delete(old["dot"])
        ring = self.create_oval(x, y, x, y, outline=BAD)
        dot = self.create_oval(x - 4, y - 4, x + 4, y + 4, fill=BAD, outline="")
        self._blips.append({"x": x, "y": y, "ring": ring, "dot": dot, "born": self._t})
        self.tag_raise(self._pct)
        self.tag_raise(self._label)

    def clear_blips(self):
        for b in self._blips:
            self.delete(b["ring"])
            self.delete(b["dot"])
        self._blips.clear()

    # --- animation ---
    def _tick(self):
        try:
            self._t += 0.033
            if self._running:
                self._angle = (self._angle - 4.5) % 360
                for i, w in enumerate(self._wedges):
                    self.itemconfigure(w, start=(self._angle + i * self.SLICE_DEG) % 360)
            for b in self._blips:
                phase = ((self._t - b["born"]) * 0.9) % 1.0
                r = 4 + 12 * phase
                self.coords(b["ring"], b["x"] - r, b["y"] - r, b["x"] + r, b["y"] + r)
                self.itemconfigure(b["ring"], outline=mix(BAD, RADAR_BG, phase))
            if self._running or self._blips:
                self._job = self.after(33, self._tick)
            else:
                self._job = None
        except tk.TclError:
            self._job = None

    def destroy(self):
        self._running = False
        if self._job:
            try:
                self.after_cancel(self._job)
            except tk.TclError:
                pass
        super().destroy()


class Pipeline(tk.Frame):
    """Three boxes showing which detection stage is working: hash / signature / rule."""

    STAGES = (
        ("hash", "1 · Hash", "Known SHA-256"),
        ("signature", "2 · Signature", "Byte patterns"),
        ("rule", "3 · Rules", "Heuristics"),
    )

    def __init__(self, parent, bg: str = PANEL):
        super().__init__(parent, bg=bg)
        self._boxes: Dict[str, Tuple[tk.Frame, tk.Label, tk.Label]] = {}
        for i, (key, title, sub) in enumerate(self.STAGES):
            box = tk.Frame(self, bg=PANEL, highlightthickness=1, highlightbackground=LINE,
                           padx=10, pady=7)
            t = tk.Label(box, text=title, font=F_BOLD, fg=TEXT, bg=PANEL, anchor="w")
            s = tk.Label(box, text=sub, font=F_SMALL, fg=MUTED, bg=PANEL, anchor="w")
            t.pack(fill="x")
            s.pack(fill="x")
            box.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 4, 0 if i == 2 else 4))
            self.columnconfigure(i, weight=1, uniform="stage")
            self._boxes[key] = (box, t, s)

    def set(self, active: str = "", hits: Sequence[str] = ()):
        for key, (box, t, s) in self._boxes.items():
            if key in hits:
                bg, border = BAD_SOFT, BAD
            elif key == active:
                bg, border = ACCENT_SOFT, ACCENT
            else:
                bg, border = PANEL, LINE
            box.configure(bg=bg, highlightbackground=border)
            t.configure(bg=bg)
            s.configure(bg=bg)


# ---------- Helpers ----------
def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.2f} PB"


def short_time(ts) -> str:
    if not ts:
        return "Never"
    return str(ts).replace("T", " ")[:19]


def page_header(parent: tk.Misc, title: str, right_text_var: Optional[tk.StringVar] = None,
                subtitle: str = "") -> tk.Frame:
    """Consistent title strip for the tool windows."""
    bar = tk.Frame(parent, bg=BG)
    left = tk.Frame(bar, bg=BG)
    left.pack(side="left")
    tk.Label(left, text=title, font=F_H2, fg=TEXT, bg=BG).pack(anchor="w")
    if subtitle:
        tk.Label(left, text=subtitle, font=F_SMALL, fg=MUTED, bg=BG).pack(anchor="w")
    if right_text_var is not None:
        tk.Label(bar, textvariable=right_text_var, font=F_BOLD, fg=MUTED,
                 bg=BG).pack(side="right")
    return bar