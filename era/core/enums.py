"""Core enums used across the permission and audit layers.

``StrEnum`` is used so members behave as plain strings (``RiskLevel.SAFE == "SAFE"``),
which keeps JSON serialization, DB storage and hash-canonicalisation deterministic.
"""

from __future__ import annotations

from enum import StrEnum


class RiskLevel(StrEnum):
    """Risk tier of an action type (fixed in the registry)."""

    SAFE = "SAFE"
    SENSITIVE = "SENSITIVE"
    COMMUNICATION = "COMMUNICATION"
    MUTATING = "MUTATING"
    FINANCIAL = "FINANCIAL"
    BOOKING = "BOOKING"
    DESTRUCTIVE = "DESTRUCTIVE"
    FORBIDDEN = "FORBIDDEN"


class Decision(StrEnum):
    """Outcome of permission evaluation."""

    ALLOW = "ALLOW"
    CONFIRM = "CONFIRM"
    CONFIRM_STRONG = "CONFIRM_STRONG"
    DENY = "DENY"


class Outcome(StrEnum):
    """Audit outcome of an action attempt.

    The two-phase execution model records the authorization state first
    (AUTHORIZED / PENDING / DENIED_* / EXPIRED), then — after the provider has
    executed *outside* the database transaction — the result (EXECUTED /
    FAILED / REJECTED).
    """

    AUTHORIZED = "AUTHORIZED"          # authorization durably persisted, dispatch starting
    PENDING = "PENDING"                # awaiting user confirmation
    EXECUTED = "EXECUTED"              # provider returned success
    FAILED = "FAILED"                  # provider raised / returned failure
    REJECTED = "REJECTED"              # no provider / validation failed / integrity failure
    DENIED_BY_POLICY = "DENIED_BY_POLICY"
    DENIED_BY_USER = "DENIED_BY_USER"
    EXPIRED = "EXPIRED"                # confirmation expired before resolution
