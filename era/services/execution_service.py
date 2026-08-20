"""The execution service — the single choke point for all action execution.

Two-phase, fail-closed execution model:

* **Phase A (authorization)** — the decision is evaluated, and the authorization
  state is durably persisted to the audit log **and committed** in one
  transaction. If this write fails, the action is NOT executed.
* **Phase B (dispatch)** — the provider is invoked **outside** any database
  transaction (external network/device work must never hold a DB transaction).
* **Phase C (result)** — the resulting EXECUTED/FAILED/REJECTED event is
  appended in a fresh transaction.

The engine and this service are the only route to execution; providers are never
directly invokable by routes or the agent loop.
"""

from __future__ import annotations

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import Decision, Outcome
from era.core.result import ActionResult, ToolError
from era.core.tool_registry import ActionCatalog, ToolRegistry
from era.db import transaction
from era.models.confirmation import STATUS_DENIED, STATUS_EXPIRED, STATUS_USED
from era.schemas.actions import ExecutionResponse


class ExecutionService:
    def __init__(self, *, session_factory, catalog: ActionCatalog, registry: ToolRegistry,
                 permission_engine, audit_service, confirmation_service, policy_service, settings):
        self.session_factory = session_factory
        self.catalog = catalog
        self.registry = registry
        self.permission_engine = permission_engine
        self.audit_service = audit_service
        self.confirmation_service = confirmation_service
        self.policy_service = policy_service
        self.settings = settings

    # -- public entry points --------------------------------------------------
    def request(self, action: Action, ctx: ExecutionContext) -> ExecutionResponse:
        policy = self.policy_service.get_current()
        policy_version = policy.version if policy else 0
        risk_level, domain, provider_id, credential_ref = self._meta(action.action_type, ctx)

        try:
            decision = self.permission_engine.evaluate(action, policy)
        except Exception as exc:  # noqa: BLE001 — fail closed: never assume allow
            self._record(action, ctx, risk_level, Decision.DENY, Outcome.DENIED_BY_POLICY,
                         policy_version, domain, provider_id, credential_ref,
                         result=f"engine error: {type(exc).__name__}")
            return ExecutionResponse(status="denied", decision=Decision.DENY,
                                     message="engine error (fail closed)")

        if decision == Decision.DENY:
            self._record(action, ctx, risk_level, decision, Outcome.DENIED_BY_POLICY,
                         policy_version, domain, provider_id, credential_ref)
            return ExecutionResponse(status="denied", decision=decision, message="denied by policy")

        if decision in (Decision.CONFIRM, Decision.CONFIRM_STRONG):
            return self._require_confirmation(action, ctx, risk_level, decision,
                                              policy_version, domain, provider_id, credential_ref)

        return self._authorize_and_dispatch(action, ctx, risk_level, decision, policy_version,
                                            domain, provider_id, credential_ref, None)

    def approve(self, confirmation_id: str, action: Action, ctx: ExecutionContext,
                challenge: str | None = None) -> ExecutionResponse:
        with transaction(self.session_factory) as session:
            confirmation = self.confirmation_service.get(session, confirmation_id)
            if confirmation is None:
                self.audit_service.record(
                    session, action=action, ctx=ctx, risk_level=None,
                    decision=Decision.DENY, outcome=Outcome.REJECTED, policy_version=0,
                    result="unknown confirmation",
                )
                return ExecutionResponse(status="denied", decision=Decision.DENY,
                                         message="unknown confirmation")

            ok, reason = self.confirmation_service.validate(confirmation, action, challenge)
            if not ok:
                status = STATUS_EXPIRED if reason == "expired" else STATUS_DENIED
                outcome = Outcome.EXPIRED if reason == "expired" else Outcome.REJECTED
                self.confirmation_service.mark_status(session, confirmation, status)
                self.audit_service.record(
                    session, action=action, ctx=ctx,
                    risk_level=confirmation.risk_level,
                    decision=Decision(confirmation.decision), outcome=outcome,
                    policy_version=confirmation.policy_version,
                    confirmation_id=confirmation.id, result=reason,
                )
                return ExecutionResponse(status="denied", decision=Decision(confirmation.decision),
                                         message=reason)

            # Valid: mark used + persist authorization in ONE transaction.
            decision = Decision(confirmation.decision)
            policy_version = confirmation.policy_version
            cid = confirmation.id
            self.confirmation_service.mark_status(session, confirmation, STATUS_USED)
            _, domain, provider_id, credential_ref = self._meta(confirmation.action_type, ctx)
            self.audit_service.record(
                session, action=action, ctx=ctx, risk_level=confirmation.risk_level,
                decision=decision, outcome=Outcome.AUTHORIZED,
                policy_version=policy_version, confirmation_id=cid,
                provider_id=provider_id, capability_domain=domain, credential_ref=credential_ref,
            )

        # Dispatch OUTSIDE the transaction, then record the result.
        return self._dispatch_and_record(action, ctx, decision, policy_version, cid)

    def deny(self, confirmation_id: str, ctx: ExecutionContext) -> ExecutionResponse:
        with transaction(self.session_factory) as session:
            confirmation = self.confirmation_service.get(session, confirmation_id)
            if confirmation is None:
                return ExecutionResponse(status="denied", decision=Decision.DENY,
                                         message="unknown confirmation")
            if confirmation.status != "PENDING":
                return ExecutionResponse(status="denied", decision=Decision(confirmation.decision),
                                         message=f"already {confirmation.status}")

            self.confirmation_service.mark_status(session, confirmation, STATUS_DENIED)
            _, domain, provider_id, credential_ref = self._meta(confirmation.action_type, ctx)
            self.audit_service.record(
                session,
                action=Action(action_type=confirmation.action_type,
                              params=confirmation.action_params_redacted),
                ctx=ctx, risk_level=confirmation.risk_level,
                decision=Decision(confirmation.decision), outcome=Outcome.DENIED_BY_USER,
                policy_version=confirmation.policy_version, confirmation_id=confirmation.id,
                provider_id=provider_id, capability_domain=domain, credential_ref=credential_ref,
            )
        return ExecutionResponse(status="denied", decision=Decision(confirmation.decision),
                                 message="denied by user")

    # -- internals ------------------------------------------------------------
    def _meta(self, action_type: str, ctx: ExecutionContext):
        spec = self.catalog.get(action_type)
        risk_level = spec.risk_level if spec else None
        domain = spec.capability_domain if spec else None
        provider = self.registry.get(action_type)
        provider_id = provider.id if provider is not None else None
        credential_ref = self._credential_ref(ctx, domain)
        return risk_level, domain, provider_id, credential_ref

    @staticmethod
    def _credential_ref(ctx: ExecutionContext, domain: str | None) -> str | None:
        refs = ctx.credentials.refs
        if not refs:
            return None
        if domain and domain in refs:
            return refs[domain]
        return next(iter(refs.values()), None)

    def _require_confirmation(self, action, ctx, risk_level, decision, policy_version,
                              domain, provider_id, credential_ref):
        with transaction(self.session_factory) as session:
            confirmation, challenge = self.confirmation_service.create(
                session, action=action, risk_level=risk_level,
                decision=decision, policy_version=policy_version,
            )
            cid = confirmation.id
            self.audit_service.record(
                session, action=action, ctx=ctx, risk_level=risk_level,
                decision=decision, outcome=Outcome.PENDING, policy_version=policy_version,
                confirmation_id=cid, provider_id=provider_id,
                capability_domain=domain, credential_ref=credential_ref,
            )
        return ExecutionResponse(status="confirmation_required", decision=decision,
                                 confirmation_id=cid, challenge=challenge)

    def _authorize_and_dispatch(self, action, ctx, risk_level, decision, policy_version,
                                domain, provider_id, credential_ref, confirmation_id):
        # Phase A: persist authorization atomically (commit inside _record).
        self._record(action, ctx, risk_level, decision, Outcome.AUTHORIZED, policy_version,
                     domain, provider_id, credential_ref, confirmation_id=confirmation_id)
        # Phase B + C.
        return self._dispatch_and_record(action, ctx, decision, policy_version, confirmation_id)

    def _dispatch_and_record(self, action, ctx, decision, policy_version, confirmation_id):
        provider = self.registry.get(action.action_type)
        if provider is None:
            outcome, success, summary = Outcome.REJECTED, False, "no provider registered for action"
        else:
            outcome, success, summary = self._run_provider(provider, action, ctx)

        risk_level, domain, provider_id, credential_ref = self._meta(action.action_type, ctx)
        self._record(action, ctx, risk_level, decision, outcome, policy_version,
                     domain, provider_id, credential_ref, confirmation_id=confirmation_id,
                     result=summary)

        status = {Outcome.EXECUTED: "executed", Outcome.FAILED: "failed",
                  Outcome.REJECTED: "rejected"}[outcome]
        return ExecutionResponse(status=status, decision=decision,
                                 result=ActionResult(success=success, summary=summary),
                                 message=None if success else summary)

    def _run_provider(self, provider, action, ctx) -> tuple[Outcome, bool, str]:
        try:
            provider.validate(action)
        except ToolError as e:
            return Outcome.REJECTED, False, str(e)
        except Exception as e:  # noqa: BLE001 — a buggy provider must not crash the gate
            return Outcome.REJECTED, False, f"validation error: {type(e).__name__}"
        try:
            result = provider.execute(action, ctx)
            if result.success:
                return Outcome.EXECUTED, True, result.summary
            return Outcome.FAILED, False, result.summary or "provider returned failure"
        except ToolError as e:
            return Outcome.FAILED, False, str(e)
        except Exception as e:  # noqa: BLE001
            return Outcome.FAILED, False, f"provider error: {type(e).__name__}"

    def _record(self, action, ctx, risk_level, decision, outcome, policy_version,
                domain, provider_id, credential_ref, confirmation_id=None, result=None):
        with transaction(self.session_factory) as session:
            self.audit_service.record(
                session, action=action, ctx=ctx, risk_level=risk_level,
                decision=decision, outcome=outcome, policy_version=policy_version,
                confirmation_id=confirmation_id, result=result, provider_id=provider_id,
                capability_domain=domain, credential_ref=credential_ref,
            )
