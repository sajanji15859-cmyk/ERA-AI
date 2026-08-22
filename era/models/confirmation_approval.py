"""Phase 4E — dual-approval records for FINANCIAL / BOOKING confirmations.

A :class:`ConfirmationApproval` tracks one actor's approval (or denial) of a
``CONFIRM_STRONG`` confirmation. For FINANCIAL and BOOKING risk actions the
system requires **two distinct approvals** (primary + secondary) before the
action can be dispatched. This model records each approval with its own
timestamp and a fingerprint of the approval context (IP, user-agent hash),
so the audit trail is non-repudiable.

Invariants:
* A confirmation can have at most ``required_approvals`` used approvals.
* Each approver (actor_id) can approve at most once.
* The confirmation is dispatched iff all required approvals are collected
  before the confirmation expires.
"""

from __future__ import annotations

from sqlalchemy import Column, Integer, String

from era.core.util import utcnow_iso
from era.models.base import Base

APPROVAL_GRANTED = "GRANTED"
APPROVAL_DENIED = "DENIED"


class ConfirmationApproval(Base):
    __tablename__ = "confirmation_approval"

    id = Column(String, primary_key=True)  # UUID hex
    confirmation_id = Column(String, nullable=False, index=True)
    actor_id = Column(String, nullable=False)  # who approved / denied
    status = Column(String, nullable=False)  # GRANTED | DENIED
    sequence = Column(Integer, nullable=False, default=1)  # 1 = primary, 2 = secondary
    context_hash = Column(String, nullable=True)  # sha256 of (ip, ua_hash)
    created_at = Column(String, nullable=False, default=utcnow_iso)
