"""
core/scanner.py
Walks folders, runs detection, and records scan history + logs.
"""

import os
import threading
import time
from pathlib import Path
from typing import Callable, Iterable, List, Optional

from config import QUARANTINE_DIR
from core.database import Database
from core.detection import DetectionEngine
from core.logger import get_logger
from core.models import FileInfo, ScanError, ScanResult


log = get_logger()


class FileScanner:
    def __init__(
        self,
        db: Optional[Database] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        scan_type: str = "custom",
        max_file_size_mb: Optional[int] = None,
    ):
        self.db = db or Database()
        self.detection = DetectionEngine(self.db)
        self.progress_callback = progress_callback
        self.scan_type = scan_type
        self.scan_id: Optional[int] = None

        self.max_file_size_mb = max_file_size_mb if (max_file_size_mb or 0) > 0 else None
        self.max_bytes: Optional[int] = (
            int(self.max_file_size_mb * 1024 * 1024) if self.max_file_size_mb else None
        )

        # Live counters the GUI can read while a scan runs (read-only for callers).
        self.live = {"size": 0, "threats": 0, "errors": 0,
                     "detected": False, "methods": []}

        self._cancel_event = threading.Event()
        # Never scan our own quarantine vault (it would re-detect quarantined files)
        try:
            self._exclude = [QUARANTINE_DIR.resolve()]
        except OSError:
            self._exclude = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def cancel(self):
        self._cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def scan_folder(self, folder: Path) -> ScanResult:
        """Scan a single folder."""
        return self.scan_paths([Path(folder)])

    def scan_paths(self, folders: Iterable[Path]) -> ScanResult:
        """
        Scan one or more folders as ONE scan (one history record).
        Bad folders are reported as errors; the rest are still scanned.
        """
        folders = [Path(f) for f in folders]
        result = ScanResult(
            target=folders[0] if folders else Path("."),
            targets=folders,
        )
        started = time.time()

        # ---- Record scan start ----
        try:
            self.scan_id = self.db.start_scan_record(self.scan_type, result.label)
        except Exception as e:
            log.error(f"Failed to start scan record: {e}")
            self.scan_id = None

        log.info(f"Scan started: type={self.scan_type} target={result.label}")

        valid: List[Path] = []
        for folder in folders:
            if not folder.exists():
                result.errors.append(ScanError(folder, "Folder does not exist"))
            elif not folder.is_dir():
                result.errors.append(ScanError(folder, "Path is not a folder"))
            else:
                valid.append(folder)

        if not valid:
            self._finalize(started, result, status="failed")
            return result

        all_files = self._collect_files(valid, result)

        total = len(all_files)
        if total == 0:
            status = "cancelled" if self.cancelled else "completed"
            log.info(f"Scan finished: no files found in {result.label}")
            self._finalize(started, result, status=status)
            return result

        for index, file_path in enumerate(all_files, start=1):
            if self.cancelled:
                break

            info = self._process_file(file_path)

            if info.readable:
                result.files.append(info)
                result.total_size += info.size
                self.live["size"] = result.total_size
                self.live["detected"] = info.detected
                self.live["methods"] = list(info.detection_methods)
                if info.detected:
                    self.live["threats"] += 1
                    log.warning(
                        f"DETECTED: {file_path} | "
                        f"threat={info.threat_name} | "
                        f"methods={','.join(info.detection_methods)}"
                    )
            else:
                result.errors.append(ScanError(file_path, info.error or "Unreadable"))
                self.live["errors"] += 1
                self.live["detected"] = False
                self.live["methods"] = []

            if self.progress_callback:
                try:
                    self.progress_callback(index, total, str(file_path))
                except Exception:
                    pass

        status = "cancelled" if self.cancelled else "completed"
        self._finalize(started, result, status=status)
        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _is_excluded(self, path: Path) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            return False
        return any(resolved == ex or ex in resolved.parents for ex in self._exclude)

    def _collect_files(self, folders: List[Path], result: ScanResult) -> List[Path]:
        files: List[Path] = []
        for folder in folders:
            for root, dirs, names in os.walk(
                folder, onerror=self._on_walk_error_factory(result)
            ):
                if self.cancelled:
                    return files
                # prune excluded folders so os.walk does not descend into them
                dirs[:] = [d for d in dirs if not self._is_excluded(Path(root) / d)]
                for name in names:
                    files.append(Path(root) / name)
        return files

    def _finalize(self, started: float, result: ScanResult, status: str):
        duration = round(time.time() - started, 3)
        result.status = status

        if self.scan_id is not None:
            try:
                self.db.finish_scan_record(
                    scan_id=self.scan_id,
                    files_scanned=result.file_count,
                    threats_found=result.threat_count,
                    errors_count=result.error_count,
                    duration_seconds=duration,
                    status=status,
                )
            except Exception as e:
                log.error(f"Failed to record scan history: {e}")

        log.info(
            f"Scan {status}: files={result.file_count} "
            f"threats={result.threat_count} errors={result.error_count} "
            f"duration={duration}s"
        )

    def _process_file(self, path: Path) -> FileInfo:
        ext = path.suffix.lower()

        try:
            size = path.stat().st_size
        except Exception as e:
            return FileInfo(path=path, name=path.name, extension=ext, size=0,
                            readable=False, error=str(e))

        if self.max_bytes is not None and size > self.max_bytes:
            return FileInfo(
                path=path, name=path.name, extension=ext, size=size,
                readable=False,
                error=f"Skipped: larger than {self.max_file_size_mb} MB limit",
            )

        info = FileInfo(path=path, name=path.name, extension=ext,
                        size=size, readable=True)

        try:
            det = self.detection.analyze(path, max_bytes=self.max_bytes)
        except Exception as e:
            info.readable = False
            info.error = f"Could not scan: {e}"
            return info

        info.sha256 = det.sha256
        info.detected = det.detected
        info.threat_name = det.threat_name
        info.severity = det.severity
        info.detection_methods = det.detection_methods
        info.reasons = det.reasons
        return info

    def _on_walk_error_factory(self, result: ScanResult):
        def _on_error(os_error):
            try:
                result.errors.append(ScanError(Path(os_error.filename), str(os_error)))
            except Exception:
                pass
        return _on_error