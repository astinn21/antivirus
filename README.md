# Python Antivirus System

An educational antivirus prototype written in Python with a Tkinter GUI.
It is **not** a replacement for real antivirus software.

## Features

- **Hash detection** - SHA-256 lookup against a list of known-bad hashes
- **Signature detection** - byte patterns searched inside files
- **Heuristic rules** - risky extensions, double extensions, mismatched file headers, high entropy, suspicious file names
- **Quick / Full / Custom scans** with progress bar and cancel
- **Quarantine** - move, restore, restore-as, delete forever
- **Real-time monitor** - polls a folder every few seconds, optional auto-quarantine
- **Scan history, settings and signature management** windows

## Requirements

- Python 3.8+
- Tkinter (bundled with Python on Windows/macOS; on Debian/Ubuntu: `sudo apt install python3-tk`)
- No third-party packages

## Run

```
python main.py
```

## Run the tests

```
python tests/run_tests.py
```

The tests use a temporary database, so your real data is not touched.

## Project layout

```
main.py
config.py
core/        detection engine, scanner, quarantine, monitor, database, settings
gui/         Tkinter windows (dashboard, quarantine, history, settings, signatures, monitor)
tests/       run_tests.py + helpers.py
data/        created on first run (SQLite DB + quarantine vault)
logs/        created on first run (activity.log)
```

## Notes and limitations

- Heuristic rules are **indicators, not proof**. Any rule can flag a safe file
  (for example every `.js` file). Review detections before quarantining.
- Files larger than the "Skip files larger than (MB)" setting are skipped and
  listed as scan errors.
- The quarantine folder is excluded from scans.
- The monitor only polls a folder; it cannot block a file from being written.
