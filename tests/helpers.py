"""
tests/helpers.py
Small helpers used by run_tests.py: a temp-folder sandbox and a tiny runner.
"""

import shutil
import sys
import tempfile
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class Sandbox:
    """A throw-away temp folder for creating test files."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="av_test_"))

    def mkdir(self, rel: str) -> Path:
        p = self.root / rel
        p.mkdir(parents=True, exist_ok=True)
        return p

    def write(self, rel: str, data: bytes) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


class _Context:
    """Passed to each test so it can report a success message."""

    def __init__(self):
        self.message = ""

    def ok(self, message: str):
        self.message = message


class TestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def run(self, name: str, fn):
        ctx = _Context()
        try:
            fn(ctx)
        except AssertionError as e:
            self.failed += 1
            print(f"[FAIL] {name}\n       {e}")
        except Exception as e:
            self.failed += 1
            print(f"[ERROR] {name}\n        {type(e).__name__}: {e}")
            traceback.print_exc()
        else:
            self.passed += 1
            print(f"[PASS] {name} - {ctx.message}")

    def summary(self):
        total = self.passed + self.failed
        print("=" * 60)
        print(f"Passed: {self.passed}/{total}   Failed: {self.failed}")
        print("=" * 60)
        return self.passed, self.failed
