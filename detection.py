"""
core/detection.py
Orchestrates hash + signature + rule-based detection.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from core.database import Database
from core.hasher import hash_file
from core.rules import RuleEngine
from core.signatures import SignatureMatcher


@dataclass
class DetectionResult:
    detected: bool = False
    sha256: Optional[str] = None
    threat_name: Optional[str] = None
    severity: Optional[str] = None
    detection_methods: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


class DetectionEngine:
    def __init__(self, db: Database):
        self.db = db
        self.signature_matcher = SignatureMatcher(db)
        self.rule_engine = RuleEngine()

    def refresh(self):
        self.signature_matcher.refresh()

    def analyze(self, path: Path, max_bytes: Optional[int] = None) -> DetectionResult:
        result = DetectionResult()

        # --- 1. Hash (may raise FileTooLargeError) ---
        digest = hash_file(path, max_bytes=max_bytes)
        result.sha256 = digest

        match = self.db.lookup_hash(digest)
        if match is not None:
            result.detected = True
            result.threat_name = match[0]
            result.severity = match[1]
            result.detection_methods.append("hash")
            result.reasons.append(f"Hash matches known threat: {match[0]}")

        # --- 2. Signature ---
        try:
            sig = self.signature_matcher.match_file(path)
        except Exception:
            sig = None
        if sig is not None:
            result.detected = True
            result.detection_methods.append("signature")
            result.reasons.append(f"Signature matched: {sig['name']}")
            if not result.threat_name:
                result.threat_name = sig["name"]
                result.severity = sig["severity"]

        # --- 3. Rules ---
        try:
            rule_reasons = self.rule_engine.evaluate(path)
        except Exception:
            rule_reasons = []
        if rule_reasons:
            result.detected = True
            result.detection_methods.append("rule")
            result.reasons.extend(rule_reasons)
            if not result.threat_name:
                result.threat_name = "Heuristic.Suspicious"
                result.severity = "low"

        return result
