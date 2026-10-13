"""
core/database.py
SQLite wrapper (threats, signatures, quarantine, scan history, settings).

The connection is shared between the GUI thread, the scan thread and the
monitor thread, so every public method takes a lock.
"""

import functools
import sqlite3
import threading
from pathlib import Path
from typing import List, Optional, Tuple

from config import DB_PATH


def _locked(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class Database:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    @_locked
    def _create_schema(self):
        cur = self.conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256       TEXT NOT NULL UNIQUE,
                name         TEXT NOT NULL,
                severity     TEXT NOT NULL DEFAULT 'medium',
                added_on     TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_threats_sha256 ON threats(sha256)")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT NOT NULL UNIQUE,
                pattern_hex  TEXT NOT NULL,
                description  TEXT,
                severity     TEXT NOT NULL DEFAULT 'low',
                added_on     TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                id             TEXT PRIMARY KEY,
                original_path  TEXT NOT NULL,
                stored_path    TEXT NOT NULL,
                name           TEXT NOT NULL,
                sha256         TEXT,
                threat_name    TEXT,
                severity       TEXT,
                size           INTEGER NOT NULL DEFAULT 0,
                quarantined_on TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at       TEXT NOT NULL DEFAULT (datetime('now')),
                finished_at      TEXT,
                scan_type        TEXT NOT NULL DEFAULT 'custom',
                target           TEXT NOT NULL,
                files_scanned    INTEGER NOT NULL DEFAULT 0,
                threats_found    INTEGER NOT NULL DEFAULT 0,
                errors_count     INTEGER NOT NULL DEFAULT 0,
                duration_seconds REAL NOT NULL DEFAULT 0,
                status           TEXT NOT NULL DEFAULT 'completed'
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        self.conn.commit()

    # ------------------------------------------------------------------
    # Threats (known-bad SHA-256 hashes)
    # ------------------------------------------------------------------

    @_locked
    def add_threat(self, sha256: str, name: str, severity: str = "medium") -> bool:
        try:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO threats (sha256, name, severity) VALUES (?, ?, ?)",
                (sha256.lower(), name, severity),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    @_locked
    def lookup_hash(self, sha256: str) -> Optional[Tuple[str, str]]:
        cur = self.conn.cursor()
        cur.execute("SELECT name, severity FROM threats WHERE sha256 = ?",
                    (sha256.lower(),))
        row = cur.fetchone()
        return (row["name"], row["severity"]) if row else None

    @_locked
    def list_threats(self) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM threats ORDER BY id DESC")
        return cur.fetchall()

    @_locked
    def count_threats(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM threats")
        return cur.fetchone()["c"]

    @_locked
    def remove_threat(self, sha256: str) -> bool:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM threats WHERE sha256 = ?", (sha256.lower(),))
        self.conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Signatures (byte patterns)
    # ------------------------------------------------------------------

    @_locked
    def add_signature(self, name: str, pattern: bytes,
                      description: str = "", severity: str = "low") -> bool:
        try:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO signatures (name, pattern_hex, description, severity) "
                "VALUES (?, ?, ?, ?)",
                (name, pattern.hex(), description, severity),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    @_locked
    def list_signatures(self) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM signatures ORDER BY id DESC")
        return cur.fetchall()

    @_locked
    def count_signatures(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM signatures")
        return cur.fetchone()["c"]

    @_locked
    def remove_signature(self, name: str) -> bool:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM signatures WHERE name = ?", (name,))
        self.conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------------

    @_locked
    def add_quarantine_entry(
        self, qid: str, original_path: str, stored_path: str, name: str,
        sha256: Optional[str], threat_name: Optional[str],
        severity: Optional[str], size: int,
    ) -> bool:
        try:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO quarantine "
                "(id, original_path, stored_path, name, sha256, threat_name, severity, size) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (qid, original_path, stored_path, name,
                 sha256, threat_name, severity, size),
            )
            self.conn.commit()
            return True
        except sqlite3.Error:
            return False

    @_locked
    def list_quarantine(self) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM quarantine ORDER BY quarantined_on DESC")
        return cur.fetchall()

    @_locked
    def get_quarantine_entry(self, qid: str) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM quarantine WHERE id = ?", (qid,))
        return cur.fetchone()

    @_locked
    def delete_quarantine_entry(self, qid: str) -> bool:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM quarantine WHERE id = ?", (qid,))
        self.conn.commit()
        return cur.rowcount > 0

    @_locked
    def count_quarantine(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM quarantine")
        return cur.fetchone()["c"]

    # ------------------------------------------------------------------
    # Scan history
    # ------------------------------------------------------------------

    @_locked
    def start_scan_record(self, scan_type: str, target: str) -> int:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scan_history (scan_type, target, status) "
            "VALUES (?, ?, 'running')",
            (scan_type, target),
        )
        self.conn.commit()
        return cur.lastrowid

    @_locked
    def finish_scan_record(self, scan_id: int, files_scanned: int,
                           threats_found: int, errors_count: int,
                           duration_seconds: float, status: str = "completed") -> bool:
        cur = self.conn.cursor()
        cur.execute(
            """
            UPDATE scan_history
            SET finished_at = datetime('now'),
                files_scanned = ?,
                threats_found = ?,
                errors_count = ?,
                duration_seconds = ?,
                status = ?
            WHERE id = ?
            """,
            (files_scanned, threats_found, errors_count,
             duration_seconds, status, scan_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    @_locked
    def list_scans(self, limit: int = 100) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,))
        return cur.fetchall()

    @_locked
    def get_scan(self, scan_id: int) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,))
        return cur.fetchone()

    @_locked
    def get_last_completed_scan(self) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM scan_history WHERE status = 'completed' "
            "ORDER BY id DESC LIMIT 1"
        )
        return cur.fetchone()

    @_locked
    def get_totals(self) -> Tuple[int, int]:
        """Return (total files scanned, total threats found) across all scans."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT COALESCE(SUM(files_scanned), 0) AS f, "
            "       COALESCE(SUM(threats_found), 0) AS t FROM scan_history"
        )
        row = cur.fetchone()
        return int(row["f"]), int(row["t"])

    @_locked
    def count_scans(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM scan_history")
        return cur.fetchone()["c"]

    @_locked
    def clear_scans(self) -> int:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM scan_history")
        self.conn.commit()
        return cur.rowcount

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    @_locked
    def get_setting(self, key: str) -> Optional[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cur.fetchone()
        return row["value"] if row else None

    @_locked
    def set_setting(self, key: str, value: str) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self.conn.commit()

    @_locked
    def list_settings(self) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM settings ORDER BY key")
        return cur.fetchall()

    # ------------------------------------------------------------------

    def close(self):
        try:
            with self._lock:
                self.conn.close()
        except Exception:
            pass
