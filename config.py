"""Deprecated facade — import ``era.config`` instead.

The original file held unused constants; the real layered configuration system
now lives in ``era.config``. ``APP_NAME``/``AUTHOR``/``VERSION`` are kept for
backwards compatibility with any code that referenced them.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "config.py is deprecated; import era.config instead.", DeprecationWarning, stacklevel=2
)

from era import __version__
from era.config import APP_NAME

AUTHOR = "Sarafraj"
DEBUG = False
VERSION = __version__

__all__ = ["APP_NAME", "AUTHOR", "DEBUG", "VERSION"]
