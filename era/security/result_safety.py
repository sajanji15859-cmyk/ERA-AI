"""Central safety boundary for provider result payloads (Phase 4A.1).

Provider contracts prohibit returning credentials, but a buggy or compromised
provider must not be able to bypass that rule at runtime. Every successful
``ActionResult`` is normalized here before it reaches an API response, agent
observation, idempotency row or background-job row.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

from era.core.result import ActionResult
from era.security.redaction import REDACTED, is_secret_key

DEFAULT_MAX_RESULT_BYTES = 524_288
MAX_RESULT_DEPTH = 8
MAX_RESULT_ITEMS = 1_000
MAX_RESULT_KEY_CHARS = 256
MAX_RESULT_SUMMARY_CHARS = 4_000

_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{8,}"),
    re.compile(r"\bAKIA[A-Z0-9]{12,}"),
    re.compile(
        r"(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|secret)"
        r"\s*[:=]\s*[\"']?[^\s,;\"']{4,}"
    ),
    re.compile(r"(?i)https?://[^\s/:@]+:[^\s/@]+@"),
)


class UnsafeResultError(ValueError):
    """A provider result is non-JSON, structurally unsafe or oversized."""


def redact_sensitive_text(value: str) -> str:
    """Mask unmistakable credential-token patterns inside arbitrary text."""

    safe = value
    for pattern in _SECRET_VALUE_PATTERNS:
        safe = pattern.sub(REDACTED, safe)
    return safe


def sanitize_action_result(result: ActionResult, *,
                           max_bytes: int = DEFAULT_MAX_RESULT_BYTES) -> ActionResult:
    """Return a bounded JSON-safe, recursively redacted result.

    Invalid/non-finite/custom values and over-limit payloads raise
    :class:`UnsafeResultError`; callers fail the dispatch rather than returning
    or persisting ambiguous provider-controlled data.
    """

    if not isinstance(result, ActionResult):
        raise UnsafeResultError("provider did not return ActionResult")
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise UnsafeResultError("result byte limit must be positive")

    summary = redact_sensitive_text(result.summary)
    if len(summary) > MAX_RESULT_SUMMARY_CHARS:
        summary = summary[:MAX_RESULT_SUMMARY_CHARS] + "…"
    data = _sanitize(result.data, depth=0)
    try:
        encoded = json.dumps(
            {"summary": summary, "data": data},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise UnsafeResultError("provider result is not valid JSON") from exc
    if len(encoded) > max_bytes:
        raise UnsafeResultError(
            f"provider result exceeds configured limit ({len(encoded)} > {max_bytes} bytes)"
        )
    return ActionResult(success=result.success, summary=summary, data=data)


def _sanitize(value: Any, *, depth: int) -> Any:
    if depth > MAX_RESULT_DEPTH:
        raise UnsafeResultError("provider result nesting is too deep")
    if value is None or isinstance(value, (str, bool, int)):
        return redact_sensitive_text(value) if isinstance(value, str) else value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise UnsafeResultError("provider result contains a non-finite number")
        return value
    if isinstance(value, dict):
        if len(value) > MAX_RESULT_ITEMS:
            raise UnsafeResultError("provider result contains too many object fields")
        safe: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > MAX_RESULT_KEY_CHARS:
                raise UnsafeResultError("provider result contains an invalid object key")
            safe[key] = REDACTED if is_secret_key(key) else _sanitize(item, depth=depth + 1)
        return safe
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_RESULT_ITEMS:
            raise UnsafeResultError("provider result contains too many list items")
        return [_sanitize(item, depth=depth + 1) for item in value]
    raise UnsafeResultError(f"provider result contains unsupported type: {type(value).__name__}")
