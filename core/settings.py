"""
core/settings.py

Simple key/value settings stored in the database.
Falls back to defaults defined in DEFAULTS.
"""

from typing import Optional

from core.database import Database


DEFAULTS = {
    "quick_scan_paths": "",          # comma-separated, empty = use defaults
    "full_scan_path": "",            # empty = use user home
    "max_file_size_mb": "100",       # skip files larger than this
    "confirm_before_quarantine": "true",
    "monitor_path": "",              # empty = Desktop
    "monitor_interval": "2.0",
    "monitor_auto_quarantine": "false",
}


class Settings:
    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()

    def get(self, key: str, default: Optional[str] = None) -> str:
        value = self.db.get_setting(key)
        if value is not None:
            return value
        if default is not None:
            return default
        return DEFAULTS.get(key, "")

    def set(self, key: str, value: str) -> None:
        self.db.set_setting(key, value)

    def get_int(self, key: str, default: int = 0) -> int:
        try:
            return int(self.get(key, str(default)))
        except (ValueError, TypeError):
            return default

    def get_float(self, key: str, default: float = 0.0) -> float:
        try:
            return float(self.get(key, str(default)))
        except (ValueError, TypeError):
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        v = self.get(key, "true" if default else "false").lower()
        return v in ("1", "true", "yes", "on")

    def get_list(self, key: str) -> list:
        raw = self.get(key, "")
        if not raw:
            return []
        return [p.strip() for p in raw.split(",") if p.strip()]
