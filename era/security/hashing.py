"""Canonical JSON + SHA-256 helpers for the append-only hash chain."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any


def _default(o: Any) -> Any:
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, Enum):
        return o.value
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    raise TypeError(f"not JSON-serializable: {type(o)!r}")


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, compact separators, stable value types."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=_default)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def action_fingerprint(action_type: str, params: dict, risk_level: Any) -> str:
    """Canonical hash binding an action to its type, params and risk tier.

    Used to bind a confirmation to exactly the action that was authorized, so a
    later (substituted) action fails to match on resolution.
    """
    return sha256_hex(canonical_json({
        "action_type": action_type,
        "params": params,
        "risk_level": risk_level,
    }))
