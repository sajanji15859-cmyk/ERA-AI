"""Pending confirmation model (mutable lifecycle — NOT append-only).

Only the audit log is append-only; confirmations legitimately transition state
(PENDING -> USED / DENIED / EXPIRED).
"""

from __future__ import annotations

from sqlalchemy import JSON, Column, Integer, String

from era.core.util import utcnow_iso
from era.models.base import Base

STATUS_PENDING = "PENDING"
STATUS_USED = "USED"
STATUS_DENIED = "DENIED"
STATUS_EXPIRED = "EXPIRED"


class PendingConfirmation(Base):
    __tablename__ = "pending_confirmation"

    id = Column(String, primary_key=True)  # UUID hex
    actor_id = Column(String, nullable=True)  # initiating user (Phase 2A actor-bound)
    # Server-derived scope retained across an out-of-band approval so a
    # stateful provider resumes the exact actor/run context that requested it.
    execution_scope = Column(String, nullable=True)
    action_type = Column(String, nullable=False)
    action_hash = Column(String, nullable=False)  # canonical hash of (type+params+risk)
    risk_level = Column(String, nullable=False)
    decision = Column(String, nullable=False)  # CONFIRM or CONFIRM_STRONG
    policy_version = Column(Integer, nullable=False)
    challenge_hash = Column(String, nullable=True)  # sha256 of the challenge phrase
    action_params_redacted = Column(JSON, nullable=False, default=dict)  # for display only
    created_at = Column(String, nullable=False, default=utcnow_iso)
    expires_at = Column(String, nullable=False)
    used_at = Column(String, nullable=True)
    status = Column(String, nullable=False, default=STATUS_PENDING)
