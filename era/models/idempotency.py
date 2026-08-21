"""Idempotency persistence (Phase 3G).

An :class:`IdempotencyRecord` deduplicates replayed execute requests so a
network retry can never dispatch a side-effecting action twice. It binds the
actor + client-supplied idempotency key (stored only as a SHA-256 hash) to a
canonical hash of the request (action type + params), so the same key with a
*different* request is rejected as a conflict rather than silently returning
the wrong result.

Nothing here stores credentials: the stored response is the same redacted
payload the caller already received (with the CONFIRM_STRONG challenge phrase
stripped — see :class:`era.services.idempotency.IdempotencyService`).
"""

from __future__ import annotations

from sqlalchemy import JSON, Column, String, UniqueConstraint

from era.core.util import utcnow_iso
from era.models.base import Base


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_record"
    __table_args__ = (
        UniqueConstraint("actor_id", "key_hash", name="uq_idempotency_actor_key"),
    )

    id = Column(String, primary_key=True)  # UUID hex
    actor_id = Column(String, nullable=False, index=True)
    key_hash = Column(String, nullable=False)  # SHA-256 of (actor_id, key)
    request_hash = Column(String, nullable=False)  # canonical hash of the request
    status = Column(String, nullable=False, default="processing")  # processing|completed
    response_json = Column(JSON, nullable=True)  # stored ExecutionResponse (completed)
    created_at = Column(String, nullable=False, default=utcnow_iso)
    updated_at = Column(String, nullable=False, default=utcnow_iso)
    expires_at = Column(String, nullable=False)
