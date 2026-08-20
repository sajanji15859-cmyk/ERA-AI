"""Policy versioning and the default (fail-closed) policy."""

from __future__ import annotations

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import Decision, Outcome, RiskLevel
from era.db import transaction
from era.models import PolicyVersion
from era.repositories.base import PolicyRepo
from era.schemas.policy import Policy

DEFAULT_TIER_DEFAULTS: dict[RiskLevel, Decision] = {
    RiskLevel.SAFE: Decision.ALLOW,
    RiskLevel.SENSITIVE: Decision.ALLOW,
    RiskLevel.COMMUNICATION: Decision.CONFIRM,
    RiskLevel.MUTATING: Decision.CONFIRM,
    RiskLevel.FINANCIAL: Decision.CONFIRM_STRONG,
    RiskLevel.BOOKING: Decision.CONFIRM_STRONG,
    RiskLevel.DESTRUCTIVE: Decision.CONFIRM_STRONG,
    RiskLevel.FORBIDDEN: Decision.DENY,
}


def default_policy() -> Policy:
    return Policy(version=1, tier_defaults=dict(DEFAULT_TIER_DEFAULTS))


class PolicyService:
    def __init__(self, policy_repo: PolicyRepo, session_factory, audit_service, settings):
        self.policy_repo = policy_repo
        self.session_factory = session_factory
        self.audit_service = audit_service
        self.settings = settings

    def bootstrap(self) -> None:
        """Seed the default policy if none exists (idempotent)."""
        with transaction(self.session_factory) as session:
            if self.policy_repo.get_current(session) is None:
                doc = default_policy()
                self.policy_repo.create(session, doc.version, doc.model_dump(mode="json"), "bootstrap")

    def get_current(self) -> Policy | None:
        with transaction(self.session_factory) as session:
            row = self.policy_repo.get_current(session)
            return Policy(**row.document) if row else None

    def create_version(self, document: Policy, changed_by: str) -> PolicyVersion:
        """Persist a new policy version and audit the change."""
        with transaction(self.session_factory) as session:
            current = self.policy_repo.get_current(session)
            new_version = (current.version + 1) if current else 1
            document.version = new_version
            row = self.policy_repo.create(session, new_version, document.model_dump(mode="json"), changed_by)
            self.audit_service.record(
                session,
                action=Action(action_type="policy.update", params={}),
                ctx=ExecutionContext(actor_id=changed_by),
                risk_level=RiskLevel.MUTATING,
                decision=Decision.ALLOW,
                outcome=Outcome.EXECUTED,
                policy_version=new_version,
                result=f"policy updated to version {new_version}",
                capability_domain="core",
            )
        return row
