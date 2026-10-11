"""
core/signatures.py

Signature detection: look for known byte/text patterns inside a file.
Signatures are stored in the SQLite `signatures` table so you can add
or remove them without touching code.

Safe, educational signatures only.
"""

from pathlib import Path
from typing import List, Optional

from core.database import Database


# How many bytes of the file we inspect for signature matching.
MAX_SCAN_BYTES = 1024 * 1024  # 1 MB - plenty for a demo


class SignatureMatcher:
    """Looks for byte patterns (signatures) inside a file."""

    def __init__(self, db: Database):
        self.db = db
        # Cache signatures at init so we only query the DB once per scan
        self._signatures: List[dict] = self._load_signatures()

    def _load_signatures(self) -> List[dict]:
        signatures = []
        for r in self.db.list_signatures():
            try:
                pattern = bytes.fromhex(r["pattern_hex"])
            except ValueError:
                continue  # corrupt row - ignore it
            if not pattern:
                continue  # an empty pattern would match every file
            signatures.append({
                "id": r["id"],
                "name": r["name"],
                "pattern": pattern,
                "severity": r["severity"],
            })
        return signatures

    def refresh(self):
        """Re-load signatures from the DB."""
        self._signatures = self._load_signatures()

    def match_file(self, path: Path) -> Optional[dict]:
        """
        Read up to MAX_SCAN_BYTES of the file and return the first
        signature that matches, or None.
        """
        if not self._signatures:
            return None

        try:
            with open(path, "rb") as f:
                data = f.read(MAX_SCAN_BYTES)
        except (PermissionError, FileNotFoundError, OSError):
            return None

        for sig in self._signatures:
            if sig["pattern"] in data:
                return sig
        return None
