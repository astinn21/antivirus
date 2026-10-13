"""
tests/run_tests.py

End-to-end test suite for the Python Antivirus System.

Run from the project folder:
    python tests/run_tests.py

Exit code 0 = all passed, 1 = one or more failed.

The tests use a temporary database, so your real settings, signatures and
scan history are never touched.
"""

import shutil
import sys
import tempfile
import time
from pathlib import Path

# Put the project root on sys.path BEFORE importing anything from the project.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.helpers import Sandbox, TestRunner  # noqa: E402


def main():
    print("=" * 60)
    print("Python Antivirus System - Test Suite")
    print("=" * 60)

    from core.database import Database
    from core.hasher import hash_bytes, hash_file
    from core.quarantine import QuarantineManager
    from core.scan_targets import get_quick_scan_targets
    from core.scanner import FileScanner
    from core.settings import Settings

    runner = TestRunner()

    tmp_db_dir = Path(tempfile.mkdtemp(prefix="av_testdb_"))
    db = Database(db_path=tmp_db_dir / "test.db")

    # ------------------------------------------------------------------
    # 1. Empty folder
    # ------------------------------------------------------------------
    def test_empty_folder(r):
        sb = Sandbox()
        try:
            empty = sb.mkdir("empty")
            res = FileScanner(db=db, scan_type="test").scan_folder(empty)
            assert res.file_count == 0, f"expected 0 files, got {res.file_count}"
            assert res.error_count == 0, f"expected 0 errors, got {res.error_count}"
            r.ok("empty folder returned 0 files, 0 errors")
        finally:
            sb.cleanup()
    runner.run("Empty folder scan", test_empty_folder)

    # ------------------------------------------------------------------
    # 2. Normal files
    # ------------------------------------------------------------------
    def test_normal_files(r):
        sb = Sandbox()
        try:
            sb.write("a.txt", b"hello")
            sb.write("b.txt", b"world")
            sb.write("c.log", b"some log")
            res = FileScanner(db=db, scan_type="test").scan_folder(sb.root)
            assert res.file_count == 3, f"expected 3 files, got {res.file_count}"
            assert res.threat_count == 0, f"expected 0 threats, got {res.threat_count}"
            r.ok(f"scanned {res.file_count} files, 0 threats")
        finally:
            sb.cleanup()
    runner.run("Normal files scan", test_normal_files)

    # ------------------------------------------------------------------
    # 3. Nested folders
    # ------------------------------------------------------------------
    def test_nested_folders(r):
        sb = Sandbox()
        try:
            sb.write("top.txt", b"a")
            sb.write("sub1/inner.txt", b"b")
            sb.write("sub1/sub2/deep.txt", b"c")
            res = FileScanner(db=db, scan_type="test").scan_folder(sb.root)
            assert res.file_count == 3, f"expected 3, got {res.file_count}"
            r.ok(f"nested scan found {res.file_count} files")
        finally:
            sb.cleanup()
    runner.run("Nested folder scan", test_nested_folders)

    # ------------------------------------------------------------------
    # 4. Large file handling
    # ------------------------------------------------------------------
    def test_large_file_skip(r):
        sb = Sandbox()
        try:
            # 5 MB file, scanner max = 1 MB -> should be skipped
            sb.write("big.bin", b"\x00" * (5 * 1024 * 1024))
            scanner = FileScanner(db=db, scan_type="test", max_file_size_mb=1)
            res = scanner.scan_folder(sb.root)
            assert res.file_count == 0, f"expected 0 readable, got {res.file_count}"
            assert res.error_count >= 1, "expected at least 1 error"
            r.ok(f"large file skipped ({res.error_count} error logged)")
        finally:
            sb.cleanup()
    runner.run("Large file skipped when over limit", test_large_file_skip)

    # ------------------------------------------------------------------
    # 5. Invalid path
    # ------------------------------------------------------------------
    def test_invalid_path(r):
        scanner = FileScanner(db=db, scan_type="test")
        res = scanner.scan_folder(Path("/nonexistent/path/xyz_123"))
        assert res.error_count >= 1, "expected an error"
        r.ok("invalid path produced a scan error instead of crashing")
    runner.run("Invalid path handling", test_invalid_path)

    # ------------------------------------------------------------------
    # 6. File is not a folder
    # ------------------------------------------------------------------
    def test_file_not_folder(r):
        sb = Sandbox()
        try:
            f = sb.write("notafolder.txt", b"x")
            res = FileScanner(db=db, scan_type="test").scan_folder(f)
            assert res.error_count >= 1, "expected an error for non-folder path"
            r.ok("file-as-folder path rejected cleanly")
        finally:
            sb.cleanup()
    runner.run("File passed as folder", test_file_not_folder)

    # ------------------------------------------------------------------
    # 7. Hash detection
    # ------------------------------------------------------------------
    def test_hash_detection(r):
        sb = Sandbox()
        try:
            payload = b"HARMLESS_TEST_PAYLOAD_42"
            f = sb.write("hashdemo.bin", payload)
            digest = hash_file(f)
            unique_name = f"TestHash.{int(time.time())}"
            db.add_threat(digest, unique_name, severity="low")

            res = FileScanner(db=db, scan_type="test").scan_folder(sb.root)
            assert res.threat_count == 1, f"expected 1 threat, got {res.threat_count}"
            det = res.detected_files[0]
            assert det.threat_name == unique_name, f"threat name mismatch: {det.threat_name}"
            assert "hash" in det.detection_methods, "hash method missing"
            r.ok(f"hash detected {f.name}")
            db.remove_threat(digest)
        finally:
            sb.cleanup()
    runner.run("Hash-based detection", test_hash_detection)

    # ------------------------------------------------------------------
    # 8. Signature detection
    # ------------------------------------------------------------------
    def test_signature_detection(r):
        sb = Sandbox()
        try:
            marker = b"TEST-SIG-MARKER-FOR-UNIT-TEST"
            unique_sig_name = f"TestSig.Unit.{int(time.time())}"
            db.add_signature(unique_sig_name, marker, description="unit test", severity="low")

            f = sb.write("sigfile.bin", b"prefix-" + marker + b"-suffix")
            res = FileScanner(db=db, scan_type="test").scan_folder(sb.root)
            assert res.threat_count >= 1, "signature not detected"
            det = res.detected_files[0]
            assert "signature" in det.detection_methods, "signature method missing"
            r.ok(f"signature detected {f.name}")
            db.remove_signature(unique_sig_name)
        finally:
            sb.cleanup()
    runner.run("Signature-based detection", test_signature_detection)

    # ------------------------------------------------------------------
    # 9. Rule-based detection (suspicious extension)
    # ------------------------------------------------------------------
    def test_rule_detection(r):
        sb = Sandbox()
        try:
            sb.write("suspicious.exe", b"notreallyanexe")
            res = FileScanner(db=db, scan_type="test").scan_folder(sb.root)
            assert res.threat_count >= 1, "rule did not flag suspicious.exe"
            det = res.detected_files[0]
            assert "rule" in det.detection_methods, "rule method missing"
            r.ok("rule-based detection flagged .exe")
        finally:
            sb.cleanup()
    runner.run("Rule-based detection (.exe)", test_rule_detection)

    # ------------------------------------------------------------------
    # 10. Double extension rule
    # ------------------------------------------------------------------
    def test_double_extension(r):
        sb = Sandbox()
        try:
            sb.write("invoice.pdf.exe", b"x")
            res = FileScanner(db=db, scan_type="test").scan_folder(sb.root)
            assert res.threat_count >= 1, "double extension not flagged"
            reasons = " ".join(res.detected_files[0].reasons)
            assert "Double extension" in reasons, f"rule did not fire: {reasons}"
            r.ok("double extension rule fired")
        finally:
            sb.cleanup()
    runner.run("Double extension rule", test_double_extension)

    # ------------------------------------------------------------------
    # 11. Quarantine + restore
    # ------------------------------------------------------------------
    def test_quarantine_restore(r):
        sb = Sandbox()
        try:
            payload = b"QUARANTINE_ROUND_TRIP_DATA"
            f = sb.write("qt.bin", payload)
            original_bytes = f.read_bytes()

            qm = QuarantineManager(db=db)
            entry = qm.quarantine_file(f, threat_name="UnitTest", severity="low")
            assert entry is not None, "quarantine returned None"
            assert not f.exists(), "original file still exists after quarantine"
            assert entry.stored_path.exists(), "stored payload missing"

            ok = qm.restore(entry.id)
            assert ok, "restore returned False"
            assert f.exists(), "file not restored"
            assert f.read_bytes() == original_bytes, "restored bytes differ"
            r.ok("quarantine -> restore preserved file bytes")
        finally:
            sb.cleanup()
    runner.run("Quarantine + restore round-trip", test_quarantine_restore)

    # ------------------------------------------------------------------
    # 12. Quarantine + delete forever
    # ------------------------------------------------------------------
    def test_quarantine_delete(r):
        sb = Sandbox()
        try:
            f = sb.write("qd.bin", b"DELETE_ME")
            qm = QuarantineManager(db=db)
            entry = qm.quarantine_file(f, threat_name="UnitTest", severity="low")
            assert entry is not None, "quarantine returned None"
            ok = qm.delete_forever(entry.id)
            assert ok, "delete_forever returned False"
            assert not entry.stored_path.exists(), "stored payload still exists"
            assert qm.get_entry(entry.id) is None, "DB row still exists"
            r.ok("quarantine -> delete forever removed payload + DB row")
        finally:
            sb.cleanup()
    runner.run("Quarantine + delete forever", test_quarantine_delete)

    # ------------------------------------------------------------------
    # 13. Settings persistence
    # ------------------------------------------------------------------
    def test_settings(r):
        s = Settings(db=db)
        unique_key = f"test_key_{int(time.time())}"
        s.set(unique_key, "hello")
        assert s.get(unique_key) == "hello", "setting not persisted"
        s.set("max_file_size_mb", "42")
        assert s.get_int("max_file_size_mb") == 42, "int conversion failed"
        s.set("monitor_interval", "1.5")
        assert s.get_float("monitor_interval") == 1.5, "float conversion failed"
        r.ok("settings persisted and typed conversion works")
    runner.run("Settings persistence", test_settings)

    # ------------------------------------------------------------------
    # 14. Interrupted scan (cancel)
    # ------------------------------------------------------------------
    def test_cancel_scan(r):
        sb = Sandbox()
        try:
            for i in range(200):
                sb.write(f"f{i}.txt", b"x" * 64)

            scanner = FileScanner(db=db, scan_type="test")
            scanner.cancel()  # cancel BEFORE starting - should short-circuit
            res = scanner.scan_folder(sb.root)
            assert res.file_count == 0, f"expected 0 files, got {res.file_count}"
            assert res.status == "cancelled", f"unexpected status: {res.status}"
            r.ok("cancelled-before-start scan returns 0 files")
        finally:
            sb.cleanup()
    runner.run("Cancelled scan", test_cancel_scan)

    # ------------------------------------------------------------------
    # 15. DB read/write
    # ------------------------------------------------------------------
    def test_db_readwrite(r):
        n_before = db.count_scans()
        sid = db.start_scan_record("test", "/tmp/fake")
        assert isinstance(sid, int) and sid > 0, "scan id invalid"
        db.finish_scan_record(sid, 5, 1, 0, 0.25, status="completed")
        row = db.get_scan(sid)
        assert row is not None, "scan row missing"
        assert row["files_scanned"] == 5, "files_scanned not saved"
        assert row["threats_found"] == 1, "threats_found not saved"
        n_after = db.count_scans()
        assert n_after == n_before + 1, "scan count did not increase"
        r.ok("DB write + read + count all consistent")
    runner.run("Database read/write", test_db_readwrite)

    # ------------------------------------------------------------------
    # 16. hash_file on missing file
    # ------------------------------------------------------------------
    def test_hash_missing(r):
        try:
            hash_file(Path("/nonexistent/file/xyz"))
            raise AssertionError("expected FileNotFoundError")
        except FileNotFoundError:
            r.ok("FileNotFoundError raised as expected")
    runner.run("hash_file on missing file", test_hash_missing)

    # ------------------------------------------------------------------
    # 17. hash_bytes deterministic
    # ------------------------------------------------------------------
    def test_hash_bytes(r):
        a = hash_bytes(b"abc")
        b = hash_bytes(b"abc")
        c = hash_bytes(b"abd")
        assert a == b, "same input produced different hashes"
        assert a != c, "different input produced same hash"
        assert len(a) == 64, "sha256 hex should be 64 chars"
        r.ok("hash_bytes deterministic and 64 hex chars")
    runner.run("hash_bytes determinism", test_hash_bytes)

    # ------------------------------------------------------------------
    # 18. Quick scan targets non-empty
    # ------------------------------------------------------------------
    def test_quick_targets(r):
        s = Settings(db=db)
        targets = get_quick_scan_targets(s)
        assert isinstance(targets, list), "expected a list"
        # Even if empty on a bare system, the call must not crash
        r.ok(f"quick scan targets computed: {len(targets)} folder(s)")
    runner.run("Quick scan targets", test_quick_targets)

    # ------------------------------------------------------------------
    # 19. Empty signature pattern must not match everything
    # ------------------------------------------------------------------
    def test_empty_signature(r):
        sb = Sandbox()
        name = f"TestSig.Empty.{int(time.time())}"
        try:
            db.add_signature(name, b"", description="empty pattern", severity="low")
            sb.write("harmless.txt", b"just some text")
            res = FileScanner(db=db, scan_type="test").scan_folder(sb.root)
            assert res.threat_count == 0, "empty signature matched a harmless file"
            r.ok("empty signature pattern is ignored")
        finally:
            db.remove_signature(name)
            sb.cleanup()
    runner.run("Empty signature ignored", test_empty_signature)

    # ------------------------------------------------------------------
    # 20. Several folders = ONE history record
    # ------------------------------------------------------------------
    def test_multi_folder(r):
        sb1, sb2 = Sandbox(), Sandbox()
        try:
            sb1.write("a.txt", b"a")
            sb2.write("b.txt", b"b")
            sb2.write("c.txt", b"c")
            before = db.count_scans()
            res = FileScanner(db=db, scan_type="test").scan_paths([sb1.root, sb2.root])
            assert res.file_count == 3, f"expected 3 files, got {res.file_count}"
            assert db.count_scans() == before + 1, "expected exactly one history record"
            r.ok("two folders scanned as one scan record")
        finally:
            sb1.cleanup()
            sb2.cleanup()
    runner.run("Multi-folder scan", test_multi_folder)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    passed, failed = runner.summary()
    db.close()
    shutil.rmtree(tmp_db_dir, ignore_errors=True)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
