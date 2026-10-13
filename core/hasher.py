"""
core/hasher.py
SHA-256 hashing with an optional size limit.
"""

import hashlib
from pathlib import Path
from typing import Optional


CHUNK_SIZE = 1024 * 1024  # 1 MB


class FileTooLargeError(Exception):
    """Raised when a file exceeds the configured size limit."""


def hash_file(path: Path, max_bytes: Optional[int] = None) -> str:
    """
    Return the SHA-256 hex digest of a file.

    If max_bytes is set and the file is larger, raise FileTooLargeError.
    Raises FileNotFoundError / PermissionError / OSError on access issues.
    """
    path = Path(path)

    if max_bytes is not None and path.stat().st_size > max_bytes:
        raise FileTooLargeError(
            f"File exceeds max size ({max_bytes} bytes): {path}"
        )

    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
