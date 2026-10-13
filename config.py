"""
config.py
Application-wide constants and paths.
"""

from pathlib import Path

# --- Application Info ---
APP_NAME = "Python Antivirus System"
APP_VERSION = "0.1.0"
APP_AUTHOR = "BSCS Student Project"

# --- Base Directory ---
BASE_DIR = Path(__file__).resolve().parent

# --- Data Directories ---
DATA_DIR = BASE_DIR / "data"
QUARANTINE_DIR = DATA_DIR / "quarantine"
DB_PATH = DATA_DIR / "antivirus.db"

# --- Logs ---
LOGS_DIR = BASE_DIR / "logs"
LOG_FILE = LOGS_DIR / "activity.log"

# --- Ensure directories exist ---
for _d in (DATA_DIR, QUARANTINE_DIR, LOGS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# --- GUI Settings ---
# The dashboard needs about 720px of height; 780 leaves some breathing room.
WINDOW_WIDTH = 1180
WINDOW_HEIGHT = 780
WINDOW_MIN_WIDTH = 1040
WINDOW_MIN_HEIGHT = 740
WINDOW_TITLE = f"{APP_NAME} v{APP_VERSION}"
"""
config.py
Application-wide constants and paths.
"""

from pathlib import Path

# --- Application Info ---
APP_NAME = "Python Antivirus System"
APP_VERSION = "0.1.0"
APP_AUTHOR = "BSCS Student Project"

# --- Base Directory ---
BASE_DIR = Path(__file__).resolve().parent

# --- Data Directories ---
DATA_DIR = BASE_DIR / "data"
QUARANTINE_DIR = DATA_DIR / "quarantine"
DB_PATH = DATA_DIR / "antivirus.db"

# --- Logs ---
LOGS_DIR = BASE_DIR / "logs"
LOG_FILE = LOGS_DIR / "activity.log"

# --- Ensure directories exist ---
for _d in (DATA_DIR, QUARANTINE_DIR, LOGS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# --- GUI Settings ---
# The dashboard needs about 680px of height; 740 leaves some breathing room.
WINDOW_WIDTH = 920
WINDOW_HEIGHT = 740
WINDOW_MIN_WIDTH = 860
WINDOW_MIN_HEIGHT = 700
WINDOW_TITLE = f"{APP_NAME} v{APP_VERSION}"
