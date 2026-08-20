"""Deprecated facade — import ``era.legacy.brain`` instead."""

from __future__ import annotations

import warnings

warnings.warn(
    "brain.py is deprecated; import era.legacy.brain instead.", DeprecationWarning, stacklevel=2
)

from era.legacy.brain import Brain

__all__ = ["Brain"]
