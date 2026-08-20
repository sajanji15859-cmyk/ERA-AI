"""Small shared utilities."""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow_iso() -> str:
    """Current time as an ISO-8601 UTC string.

    Timestamps are stored as ISO strings (rather than SQLAlchemy ``DateTime``) so
    they round-trip *exactly* through SQLite and can therefore be part of the
    append-only hash-chain payload deterministically. ISO-8601 UTC strings also
    compare correctly lexicographically.
    """

    return datetime.now(UTC).isoformat()
