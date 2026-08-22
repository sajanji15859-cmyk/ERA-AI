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

# PII/content fields are not credentials and therefore intentionally do not
# bloat the catalog's ``secret_fields`` metadata. The audit/confirmation
# boundary nevertheless treats them as confidential for real communication and
# booking actions. Keeping this mapping action-scoped avoids unexpectedly
# redacting unrelated provider payloads such as GitHub issue bodies.
_ACTION_PRIVATE_FIELDS: dict[str, frozenset[str]] = {
    "email.draft": frozenset({"body"}),
    "email.send": frozenset({"body", "attachments", "bcc"}),
    "whatsapp.send": frozenset({"message", "text", "media"}),
    "booking.hold": frozenset({"passenger_name", "passengers", "guests"}),
    "booking.confirm": frozenset({"payment_ref"}),
    "device.sms_send": frozenset({"message"}),
}


def sensitive_fields_for_action(action_type: str,
                                declared_fields: Collection[str] | None = None) -> frozenset[str]:
    """Return declared credential fields plus audited PII/content fields."""

    return frozenset(declared_fields or ()) | _ACTION_PRIVATE_FIELDS.get(action_type, frozenset())


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
