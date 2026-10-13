"""
core/models.py
Plain data containers shared across the app.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class FileInfo:
    path: Path
    name: str
    extension: str
    size: int
    readable: bool = True
    error: Optional[str] = None

    sha256: Optional[str] = None
    detected: bool = False
    threat_name: Optional[str] = None
    severity: Optional[str] = None
    detection_methods: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


@dataclass
class ScanError:
    path: Path
    reason: str


@dataclass
class ScanResult:
    target: Path
    files: List[FileInfo] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)
    total_size: int = 0
    targets: List[Path] = field(default_factory=list)   # every folder in this scan
    status: str = "completed"                           # completed | cancelled | failed

    @property
    def label(self) -> str:
        """Human-readable description of what was scanned."""
        if self.targets:
            return ", ".join(str(t) for t in self.targets)
        return str(self.target)

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def threat_count(self) -> int:
        return sum(1 for f in self.files if f.detected)

    @property
    def detected_files(self) -> List[FileInfo]:
        return [f for f in self.files if f.detected]


@dataclass
class QuarantineEntry:
    id: str
    original_path: Path
    stored_path: Path
    name: str
    sha256: Optional[str]
    threat_name: Optional[str]
    severity: Optional[str]
    size: int
    quarantined_on: str = ""
