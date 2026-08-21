"""Append-only audit log model.

``created_at`` is stored as an ISO-8601 UTC string so it round-trips exactly
through SQLite and can participate in the hash-chain payload deterministically.
The table is protected by BEFORE UPDATE/DELETE triggers (installed in
``security/append_only.py``) — the repository also exposes no update/delete API.
"""

from __future__ import annotations

from sqlalchemy import JSON, Column, Integer, String

from era.core.util import utcnow_iso
from era.models.base import Base


class AuditLogEntry(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    seq = Column(Integer, unique=True, nullable=False, index=True)
    created_at = Column(String, nullable=False, default=utcnow_iso)
    actor_id = Column(String, nullable=False)
    action_type = Column(String, nullable=False, index=True)
    action_params = Column(JSON, nullable=False, default=dict)  # redacted
    risk_level = Column(String, nullable=False)
    decision = Column(String, nullable=False)
    outcome = Column(String, nullable=False, index=True)
    confirmation_id = Column(String, nullable=True, index=True)
    result = Column(String, nullable=True)
    #: Stable :class:`~era.core.result.ProviderErrorCode` for FAILED/REJECTED
    #: provider outcomes (Phase 1E). Null for successes and non-provider denials.
    error_code = Column(String, nullable=True, index=True)
    provider_id = Column(String, nullable=True)
    capability_domain = Column(String, nullable=True)
    credential_ref = Column(String, nullable=True)
    policy_version = Column(Integer, nullable=False)
    app_version = Column(String, nullable=False)
    meta = Column(JSON, nullable=False, default=dict)  # "metadata" is reserved in SQLAlchemy
    prev_hash = Column(String, nullable=False)
    entry_hash = Column(String, nullable=False)

    # Canonical field order used for hash-chain serialization. Must match
    # AuditRepo.verify() exactly.
    HASH_FIELDS = (
        "seq", "created_at", "actor_id", "action_type", "action_params",
        "risk_level", "decision", "outcome", "confirmation_id", "result",
        "error_code", "provider_id", "capability_domain", "credential_ref",
        "policy_version", "app_version", "meta", "prev_hash",
    )
