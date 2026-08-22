"""The audit service — the ONLY writer to the audit log.

Every authorization decision and every execution result is appended here. The
service redacts params and delegates chain computation to the repository; it
never exposes update/delete (there are none).
"""

from __future__ import annotations

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import Decision, Outcome, RiskLevel
from era.core.tool_registry import ActionCatalog
from era.models import AuditLogEntry
from era.repositories.base import AuditRepo, NewAuditEntry, VerifyResult
from era.security.redaction import redact, sensitive_fields_for_action

#: Audit rows stay bounded: string param values longer than this are stored
#: as length markers (Phase 3B hardening — file content etc. must not bloat
#: the append-only log).
AUDIT_PARAM_STR_LIMIT = 2000


class AuditService:
    def __init__(self, audit_repo: AuditRepo, catalog: ActionCatalog, settings):
        self.audit_repo = audit_repo
        self.catalog = catalog
        self.settings = settings

    # -- write (sole writer) --------------------------------------------------
    def record(self, session, *, action: Action, ctx: ExecutionContext,
               risk_level: RiskLevel | str | None, decision: Decision,
               outcome: Outcome, policy_version: int,
               confirmation_id: str | None = None, result: str | None = None,
               error_code: str | None = None,
               provider_id: str | None = None, capability_domain: str | None = None,
               credential_ref: str | None = None,
               meta: dict | None = None) -> AuditLogEntry:
        spec = self.catalog.get(action.action_type)
        secret_fields = sensitive_fields_for_action(
            action.action_type,
            spec.secret_fields if spec else frozenset(),
        )
        entry = NewAuditEntry(
            actor_id=ctx.actor_id,
            action_type=action.action_type,
            action_params=_cap_strings(redact(action.params, secret_fields)),
            risk_level=_str(risk_level),
            decision=decision.value,
            outcome=outcome.value,
            policy_version=policy_version,
            app_version=self.settings.app_version,
            confirmation_id=confirmation_id,
            result=result,
            error_code=error_code,
            provider_id=provider_id,
            capability_domain=capability_domain,
            credential_ref=credential_ref,
            meta=dict(meta or {}),
        )
        return self.audit_repo.append(session, entry)

    # -- read (immutable) -----------------------------------------------------
    def list(self, session, *, limit: int = 100, offset: int = 0,
             action_type: str | None = None, outcome: str | None = None,
             confirmation_id: str | None = None) -> list[AuditLogEntry]:
        return self.audit_repo.list(
            session, limit=limit, offset=offset,
            action_type=action_type, outcome=outcome,
            confirmation_id=confirmation_id,
        )

    def get(self, session, entry_id: int) -> AuditLogEntry | None:
        return self.audit_repo.get(session, entry_id)

    def verify(self, session) -> VerifyResult:
        return self.audit_repo.verify(session)


def _cap_strings(value, limit: int = AUDIT_PARAM_STR_LIMIT, depth: int = 0):
    """Truncate long string values so audit rows stay bounded."""
    if depth > 6:
        return "[truncated]"
    if isinstance(value, str):
        return value if len(value) <= limit else f"<truncated:{len(value)} chars>"
    if isinstance(value, dict):
        return {k: _cap_strings(v, limit, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_cap_strings(x, limit, depth + 1) for x in value]
    return value


def _str(value: RiskLevel | str | None) -> str:
    if value is None:
        return "UNKNOWN"
    return value.value if isinstance(value, RiskLevel) else str(value)
