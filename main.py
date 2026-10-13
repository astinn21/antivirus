"""
main.py
Entry point for the Python Antivirus System.

Run from the project folder:
    python main.py
"""

import sys
from pathlib import Path

# Make sure the project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.app import AntivirusApp


def main():
    app = AntivirusApp()
    app.mainloop()


if __name__ == "__main__":
    main()
