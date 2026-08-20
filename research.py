"""Deprecated facade — import ``era.legacy.research`` instead."""

from __future__ import annotations

import warnings

warnings.warn(
    "research.py is deprecated; import era.legacy.research instead.",
    DeprecationWarning,
    stacklevel=2,
)

from era.legacy.research import Research

__all__ = ["Research"]
