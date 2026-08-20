"""Logging setup for ERA-AI (stdlib-based; replaces the old print banners).

All library code should log through :func:`get_logger`, which returns a child of
the ``era`` logger tree. ``setup_logging`` is called once by the CLI; it is
idempotent (safe to call again, e.g. after a config change).
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from era.config import Config, era_home

LOG_DIR_NAME = "logs"
LOG_FILE_NAME = "era.log"
_MAX_BYTES = 1_000_000
_BACKUP_COUNT = 3
_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}


def setup_logging(config: Config) -> Path | None:
    """Configure the ``era`` logger tree from ``config``.

    Returns the log file path when file logging is enabled, else ``None``.
    Never raises for an unwritable log directory — file logging is skipped with
    a warning so the CLI still starts.
    """
    level = logging.DEBUG if config.debug else _LEVELS[config.logging.level]
    formatter = logging.Formatter(_FORMAT)

    root = logging.getLogger("era")
    root.setLevel(logging.DEBUG)  # handlers do the filtering
    root.handlers.clear()
    root.propagate = False

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(formatter)
    root.addHandler(console)

    log_file: Path | None = None
    if config.logging.to_file:
        log_dir = era_home() / LOG_DIR_NAME
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_dir / LOG_FILE_NAME,
                maxBytes=_MAX_BYTES,
                backupCount=_BACKUP_COUNT,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
            log_file = log_dir / LOG_FILE_NAME
        except OSError as exc:
            root.addHandler(logging.NullHandler())
            logging.getLogger("era.logging").warning(
                "file logging disabled: cannot create log directory %s (%s)", log_dir, exc
            )
    return log_file


def get_logger(name: str) -> logging.Logger:
    """Return a logger in the ``era`` tree, e.g. ``get_logger("cli")`` -> ``era.cli``."""
    if name.startswith("era."):
        return logging.getLogger(name)
    return logging.getLogger(f"era.{name}")
