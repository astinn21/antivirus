"""
core/scan_targets.py

Builds the list of folders for Quick Scan and Full Scan.
Uses platform-safe defaults.
"""

import os
import sys
from pathlib import Path
from typing import List

from core.settings import Settings


def get_quick_scan_targets(settings: Settings) -> List[Path]:
    """
    Quick scan target folders:
    - If the user configured custom paths in Settings, use those.
    - Otherwise, use sensible defaults per platform.
    """
    custom = settings.get_list("quick_scan_paths")
    if custom:
        return [Path(p) for p in custom if Path(p).exists()]

    home = Path.home()
    candidates: List[Path] = []

    # Common user content folders
    for name in ["Desktop", "Downloads", "Documents"]:
        p = home / name
        if p.exists() and p.is_dir():
            candidates.append(p)

    # Temp folder
    if sys.platform.startswith("win"):
        tmp = os.environ.get("TEMP")
        if tmp and Path(tmp).exists():
            candidates.append(Path(tmp))
    else:
        tmp_path = Path("/tmp")
        if tmp_path.exists():
            candidates.append(tmp_path)

    return candidates


def get_full_scan_targets(settings: Settings) -> List[Path]:
    """
    Full scan target folders:
    - If the user configured a custom path, use that.
    - Otherwise, use the user home folder (never scan system root by default).
    """
    custom = settings.get("full_scan_path", "")
    if custom:
        p = Path(custom)
        if p.exists() and p.is_dir():
            return [p]

    home = Path.home()
    if home.exists():
        return [home]

    return []
