"""Deprecated facade — import ``era.legacy.agent`` instead.

The original file defined the class ``ERAAI`` twice; the second definition
shadowed the first. The fixed single class now lives in ``era.legacy.agent``.
"""

from __future__ import annotations

import warnings

warnings.warn(
    "agent.py is deprecated; import era.legacy.agent instead.", DeprecationWarning, stacklevel=2
)

from era.legacy.agent import ERAAI

__all__ = ["ERAAI"]
