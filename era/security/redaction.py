"""Secret/PII redaction before anything reaches the audit log.

The registry declares secret-bearing fields per action (``secret_fields``); this
module masks those *and* any key whose name matches a conservative hint list, so
secrets never appear in audit rows, logs or responses. Over-redaction is safe;
under-redaction is not.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

REDACTED = "[REDACTED]"

# Conservative substrings that mark a key as secret-bearing (lowercased).
_SECRET_HINTS = (
    "key", "token", "secret", "password", "passwd", "pin",
    "credential", "authorization", "cookie", "auth",
)


def is_secret_key(key: str, secret_fields: Collection[str] | None = None) -> bool:
    if secret_fields and key in secret_fields:
        return True
    kl = key.lower()
    return any(hint in kl for hint in _SECRET_HINTS)


def redact(value: Any, secret_fields: Collection[str] | None = None) -> Any:
    """Return a deep copy of ``value`` with secret values replaced by ``[REDACTED]``."""
    sf = set(secret_fields or ())

    def _r(v: Any) -> Any:
        if isinstance(v, dict):
            return {
                k: (REDACTED if is_secret_key(k, sf) else _r(val))
                for k, val in v.items()
            }
        if isinstance(v, (list, tuple)):
            return [_r(x) for x in v]
        return v

    return _r(value)
