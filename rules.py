"""
core/rules.py

Rule-based (heuristic) detection.

IMPORTANT: These rules are INDICATORS, not proof of malware.
Any single rule can fire on a perfectly safe file. The goal is to
demonstrate the concept of heuristics in a teaching context.
"""

import math
from pathlib import Path
from typing import List, Optional


# ----------------------------------------------------------------------
# Individual rules
# ----------------------------------------------------------------------
# Each rule returns either None (no match) or a short reason string.

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".hta", ".jar",
}

# Double extensions like  invoice.pdf.exe
DOUBLE_EXT_TRICKS = {
    (".pdf", ".exe"), (".doc", ".exe"), (".docx", ".exe"),
    (".jpg", ".exe"), (".png", ".exe"), (".txt", ".exe"),
    (".pdf", ".scr"), (".doc", ".scr"),
}

# Magic numbers for common file types (first few bytes)
MAGIC_NUMBERS = {
    b"MZ":               "Windows executable (MZ header)",
    b"\x7fELF":          "Linux executable (ELF header)",
    b"\xca\xfe\xba\xbe": "Mach-O / Java class header",
    b"PK\x03\x04":       "ZIP/Office archive",
    b"%PDF":             "PDF document",
    b"\xff\xd8\xff":     "JPEG image",
    b"\x89PNG":          "PNG image",
}


def rule_suspicious_extension(path: Path) -> Optional[str]:
    if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
        return f"File has a potentially risky extension: {path.suffix}"
    return None


def rule_double_extension(path: Path) -> Optional[str]:
    # Split on dots: "invoice.pdf.exe" -> [".pdf", ".exe"]
    parts = path.suffixes
    if len(parts) >= 2:
        pair = (parts[-2].lower(), parts[-1].lower())
        if pair in DOUBLE_EXT_TRICKS:
            return f"Double extension trick: {parts[-2]}{parts[-1]}"
    return None


def rule_hidden_executable(path: Path) -> Optional[str]:
    """
    A file whose name starts with a dot (hidden on Linux/macOS) AND
    has an executable extension is suspicious.
    """
    name = path.name
    if name.startswith(".") and path.suffix.lower() in {".exe", ".sh", ".bat", ".py"}:
        return f"Hidden executable: {name}"
    return None


def rule_mismatched_magic(path: Path) -> Optional[str]:
    """
    If the file's extension says one thing but the header says another,
    that's suspicious. E.g. .txt that starts with MZ (an EXE).
    """
    try:
        with open(path, "rb") as f:
            header = f.read(8)
    except (PermissionError, FileNotFoundError, OSError):
        return None

    if not header:
        return None

    detected = None
    for magic, desc in MAGIC_NUMBERS.items():
        if header.startswith(magic):
            detected = desc
            break

    if detected is None:
        return None

    ext = path.suffix.lower()
    looks_like_exe = detected.startswith("Windows executable") or \
        detected.startswith("Linux executable")

    if looks_like_exe and ext in {".txt", ".jpg", ".png", ".pdf", ".doc", ".docx"}:
        return f"File content ({detected}) does not match extension {ext}"

    return None


def rule_very_high_entropy(path: Path, sample_size: int = 65536) -> Optional[str]:
    """
    Compute Shannon entropy of the first `sample_size` bytes.
    Entropy close to 8.0 often means the file is packed/encrypted.
    Plain text is around 4.0-5.0. This is a classic heuristic.
    """
    try:
        with open(path, "rb") as f:
            data = f.read(sample_size)
    except (PermissionError, FileNotFoundError, OSError):
        return None

    if len(data) < 256:
        return None  # too small to judge

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    total = len(data)
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)

    # Only flag if the extension is not already a known compressed format
    if entropy >= 7.5 and path.suffix.lower() not in {
        ".zip", ".gz", ".7z", ".rar", ".jpg", ".png", ".mp3", ".mp4"
    }:
        return f"Very high entropy ({entropy:.2f}) - possibly packed or encrypted"
    return None


def rule_threat_keyword_filename(path: Path) -> Optional[str]:
    """Filenames that are classic red flags in demos."""
    lowered = path.name.lower()
    keywords = ["ransom", "malware", "virus", "trojan", "keylog", "payload"]
    for kw in keywords:
        if kw in lowered:
            return f"Filename contains suspicious keyword: '{kw}'"
    return None


# ----------------------------------------------------------------------
# Rule registry
# ----------------------------------------------------------------------

RULES = [
    rule_suspicious_extension,
    rule_double_extension,
    rule_hidden_executable,
    rule_mismatched_magic,
    rule_very_high_entropy,
    rule_threat_keyword_filename,
]


class RuleEngine:
    """Runs every rule against a file and collects reasons."""

    def evaluate(self, path: Path) -> List[str]:
        reasons: List[str] = []
        for rule in RULES:
            try:
                reason = rule(path)
            except Exception:
                reason = None
            if reason:
                reasons.append(reason)
        return reasons
