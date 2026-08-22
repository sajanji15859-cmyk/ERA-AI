"""Phase 4E — dual-approval service for FINANCIAL / BOOKING confirmations.

For ``CONFIRM_STRONG`` confirmations on FINANCIAL or BOOKING risk-level
actions, the system requires **two distinct approvals** before dispatch:

* **Primary approval** — the original requesting actor approves (or a
  cross-actor admin approves on their behalf).
* **Secondary approval** — a *different* actor (typically an admin / operator)
  must independently grant approval.

The two approvals are tracked in the ``confirmation_approval`` table. Each
approval records the approver's actor_id, sequence (1 = primary, 2 =
secondary), and a context hash (IP + UA fingerprint) for non-repudiation.

Invariants:
* A FINANCIAL/BOOKING confirmation is dispatchable iff it has exactly 2
  GRANTED approvals from 2 distinct actors, both before the confirmation
  expires.
* Any single DENY at any sequence immediately denies the confirmation.
* The same actor cannot approve twice (second attempt is rejected).
* Non-FINANCIAL/BOOKING CONFIRM_STRONG actions need only 1 approval
  (the existing single-approval flow is preserved).
"""

from __future__ import annotations

import uuid

from era.core.enums import RiskLevel
from era.core.util import utcnow_iso
from era.db import transaction
from era.models.confirmation import (
    STATUS_PENDING,
    PendingConfirmation,
)
from era.models.confirmation_approval import (
    APPROVAL_DENIED,
    APPROVAL_GRANTED,
    ConfirmationApproval,
)
from era.repositories.base import ConfirmationApprovalRepo, ConfirmationRepo
from era.security.hashing import sha256_hex

#: Risk levels that require dual approval for CONFIRM_STRONG.
DUAL_APPROVAL_RISK_LEVELS = frozenset({
    RiskLevel.FINANCIAL.value,
    RiskLevel.BOOKING.value,
})


class DualApprovalError(Exception):
    """Fail-closed dual-approval error."""


class ApprovalAlreadyExists(DualApprovalError):
    """The actor has already approved/denied this confirmation."""


class ApprovalNotRequired(DualApprovalError):
    """The confirmation does not require dual approval."""


class ConfirmationNotPending(DualApprovalError):
    """The confirmation is no longer pending."""


class DualApprovalService:
    """Track dual-approval state for FINANCIAL / BOOKING CONFIRM_STRONG."""

    def __init__(self, *, session_factory,
                 approval_repo: ConfirmationApprovalRepo,
                 confirmation_repo: ConfirmationRepo):
        self.session_factory = session_factory
        self.approval_repo = approval_repo
        self.confirmation_repo = confirmation_repo

    @staticmethod
    def requires_dual_approval(risk_level: str | RiskLevel) -> bool:
        """Return True if the risk level requires two approvals."""
        value = risk_level.value if isinstance(risk_level, RiskLevel) else risk_level
        return value in DUAL_APPROVAL_RISK_LEVELS

    def required_approvals(self, risk_level: str | RiskLevel) -> int:
        """How many GRANTED approvals are needed for dispatch."""
        return 2 if self.requires_dual_approval(risk_level) else 1

    def record_approval(self, *, confirmation_id: str, actor_id: str,
                        status: str, context_hash: str | None = None) -> ConfirmationApproval:
        """Record an approval/denial. Raises on duplicate or invalid state."""
        if status not in (APPROVAL_GRANTED, APPROVAL_DENIED):
            raise DualApprovalError(f"invalid approval status: {status!r}")

        with transaction(self.session_factory) as session:
            confirmation = self.confirmation_repo.get(session, confirmation_id)
            if confirmation is None:
                raise DualApprovalError("unknown confirmation")
            if confirmation.status != STATUS_PENDING:
                raise ConfirmationNotPending("confirmation is no longer pending")

            # Check for duplicate by the same actor.
            existing = self.approval_repo.get_by_actor(session, confirmation_id, actor_id)
            if existing is not None:
                raise ApprovalAlreadyExists(
                    f"actor {actor_id!r} has already {existing.status.lower()} this confirmation")

            # Determine sequence number.
            existing_approvals = self.approval_repo.list_for_confirmation(
                session, confirmation_id)
            sequence = len(existing_approvals) + 1

            approval = ConfirmationApproval(
                id=uuid.uuid4().hex,
                confirmation_id=confirmation_id,
                actor_id=actor_id,
                status=status,
                sequence=sequence,
                context_hash=context_hash,
                created_at=utcnow_iso(),
            )
            return self.approval_repo.create(session, approval)

    def is_dispatchable(self, confirmation: PendingConfirmation) -> bool:
        """Return True if the confirmation has enough approvals to dispatch."""
        required = self.required_approvals(confirmation.risk_level)
        with transaction(self.session_factory) as session:
            approvals = self.approval_repo.list_for_confirmation(
                session, confirmation.id)
        granted = [a for a in approvals if a.status == APPROVAL_GRANTED]
        denied = [a for a in approvals if a.status == APPROVAL_DENIED]
        # Any denial is an immediate block.
        if denied:
            return False
        # Need exactly `required` grants from distinct actors.
        distinct_actors = {a.actor_id for a in granted}
        return len(distinct_actors) >= required

    def is_denied(self, confirmation: PendingConfirmation) -> bool:
        """Return True if any approval is a denial."""
        with transaction(self.session_factory) as session:
            approvals = self.approval_repo.list_for_confirmation(
                session, confirmation.id)
        return any(a.status == APPROVAL_DENIED for a in approvals)

    def get_approvals(self, confirmation_id: str) -> list[ConfirmationApproval]:
        """List all approvals for a confirmation."""
        with transaction(self.session_factory) as session:
            return self.approval_repo.list_for_confirmation(session, confirmation_id)

    @staticmethod
    def build_context_hash(ip: str | None = None, user_agent: str | None = None) -> str:
        """Hash IP + user-agent for non-repudiation context tracking."""
        material = f"{ip or ''}:{user_agent or ''}"
        return sha256_hex(material)


__all__ = [
    "APPROVAL_DENIED",
    "APPROVAL_GRANTED",
    "DUAL_APPROVAL_RISK_LEVELS",
    "ApprovalAlreadyExists",
    "ApprovalNotRequired",
    "ConfirmationNotPending",
    "DualApprovalError",
    "DualApprovalService",
]
