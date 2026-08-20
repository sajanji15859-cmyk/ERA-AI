"""Deprecated facade — import ``era.legacy.memory`` instead."""

from __future__ import annotations

import warnings

warnings.warn(
    "memory.py is deprecated; import era.legacy.memory instead.", DeprecationWarning, stacklevel=2
)

from era.legacy.memory import Memory

__all__ = ["Memory"]
