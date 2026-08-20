"""Deprecated facade — import ``era.legacy.chat`` instead.

The word-boundary matching fix lives in ``era.legacy.chat``.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "chat.py is deprecated; import era.legacy.chat instead.", DeprecationWarning, stacklevel=2
)

from era.legacy.chat import Chat

__all__ = ["Chat"]
