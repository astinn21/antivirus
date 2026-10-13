"""
gui/app.py
Main application window. Manages frames and navigation.
"""

import tkinter as tk
from tkinter import ttk

from config import (
    WINDOW_HEIGHT, WINDOW_MIN_HEIGHT, WINDOW_MIN_WIDTH,
    WINDOW_TITLE, WINDOW_WIDTH,
)
from gui.dashboard import DashboardFrame
from gui.theme import apply_theme


class AntivirusApp(tk.Tk):
    """Main Tkinter application window."""

    def __init__(self):
        super().__init__()

        self.title(WINDOW_TITLE)
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.minsize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)

        apply_theme(self)

        # Container that holds all frames.
        # Frames MUST be created with this container as their parent,
        # otherwise the empty container steals half of the window.
        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self.current_frame = None
        self.show_frame(DashboardFrame)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def show_frame(self, frame_class):
        """Destroy current frame and show a new one."""
        if self.current_frame is not None:
            self.current_frame.destroy()

        self.current_frame = frame_class(parent=self.container)
        self.current_frame.pack(fill="both", expand=True)

    def _on_close(self):
        shutdown = getattr(self.current_frame, "shutdown", None)
        if callable(shutdown):
            try:
                shutdown()
            except Exception:
                pass
        self.destroy()
