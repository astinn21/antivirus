"""
core/logger.py

Central logger. Writes to logs/activity.log and also to the console.
Use core.logger.get_logger() everywhere instead of print().
"""

import logging
from logging.handlers import RotatingFileHandler

from config import LOG_FILE, LOGS_DIR


_LOGGER_NAME = "python_antivirus"
_initialized = False


def get_logger() -> logging.Logger:
    """Return the shared application logger."""
    global _initialized
    logger = logging.getLogger(_LOGGER_NAME)

    if _initialized:
        return logger

    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    logger.setLevel(logging.INFO)
    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotating file handler — cap at 1 MB, keep 3 backups
    fh = RotatingFileHandler(str(LOG_FILE), maxBytes=1_000_000,
                             backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    _initialized = True
    return logger
