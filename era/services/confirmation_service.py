"""Confirmation lifecycle: create, get, validate, resolve.

Confirmations are single-use, TTL-bound, and bound to a canonical hash of the
authorized action (type + params + risk), so a substituted action cannot ride a
stale approval. ``CONFIRM_STRONG`` additionally requires a challenge phrase.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import timedelta

from era.core.action import Action
from era.core.enums import Decision, RiskLevel
from era.core.tool_registry import ActionCatalog
from era.core.util import utcnow_iso
from era.models import PendingConfirmation
from era.repositories.base import ConfirmationRepo
from era.security.hashing import action_fingerprint, sha256_hex
from era.security.redaction import redact


class ConfirmationService:
    def __init__(self, confirmation_repo: ConfirmationRepo, catalog: ActionCatalog, settings):
        self.confirmation_repo = confirmation_repo
        self.catalog = catalog
        self.settings = settings

    def create(self, session, *, action: Action, risk_level: RiskLevel,
               decision: Decision, policy_version: int) -> tuple[PendingConfirmation, str | None]:
        challenge = None
        challenge_hash = None
        if decision == Decision.CONFIRM_STRONG:
            challenge = secrets.token_urlsafe(16)
            challenge_hash = sha256_hex(challenge)

        ttl = (
            self.settings.confirmation_ttl_strong_seconds
            if decision == Decision.CONFIRM_STRONG
            else self.settings.confirmation_ttl_seconds
        )
        now = utcnow_iso()
        spec = self.catalog.get(action.action_type)
        secret_fields = spec.secret_fields if spec else frozenset()

        confirmation = PendingConfirmation(
            id=uuid.uuid4().hex,
            action_type=action.action_type,
            action_hash=action_fingerprint(action.action_type, action.params, risk_level),
            risk_level=risk_level.value,
            decision=decision.value,
            policy_version=policy_version,
            challenge_hash=challenge_hash,
            action_params_redacted=redact(action.params, secret_fields),
            created_at=now,
            expires_at=_add_seconds(now, ttl),
            status="PENDING",
        )
        self.confirmation_repo.create(session, confirmation)
        return confirmation, challenge

    def get(self, session, confirmation_id: str) -> PendingConfirmation | None:
        return self.confirmation_repo.get(session, confirmation_id)

    def validate(self, confirmation: PendingConfirmation,
                 action: Action, challenge: str | None) -> tuple[bool, str]:
        """Return (ok, reason). Any failure is treated as deny (fail closed)."""
        if confirmation.status != "PENDING":
            return False, "already resolved"
        if confirmation.used_at is not None:
            return False, "already used"
        if confirmation.expires_at is not None and utcnow_iso() > confirmation.expires_at:
            return False, "expired"
        expected = action_fingerprint(action.action_type, action.params, confirmation.risk_level)
        if expected != confirmation.action_hash:
            return False, "action does not match confirmation (hash mismatch)"
        if confirmation.decision == Decision.CONFIRM_STRONG.value:
            if not challenge or confirmation.challenge_hash is None:
                return False, "challenge required"
            if sha256_hex(challenge) != confirmation.challenge_hash:
                return False, "challenge incorrect"
        return True, ""

    def mark_status(self, session, confirmation: PendingConfirmation, status: str) -> None:
        confirmation.status = status
        confirmation.used_at = utcnow_iso()
        self.confirmation_repo.update(session, confirmation)


def _add_seconds(iso: str, seconds: int) -> str:
    from datetime import datetime
    dt = datetime.fromisoformat(iso)
    return (dt + timedelta(seconds=seconds)).isoformat()
