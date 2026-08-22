"""The execution service — the single choke point for all action execution.

Two-phase, fail-closed execution model:

* **Phase A (authorization)** — the decision is evaluated, and the authorization
  state is durably persisted to the audit log **and committed** in one
  transaction. If this write fails, the action is NOT executed.
* **Phase B (dispatch)** — the provider is invoked **outside** any database
  transaction (external network/device work must never hold a DB transaction),
  bounded by a hard wall-clock timeout (Phase 1E). Phase 1F adds a reliability
  layer here: a circuit-breaker gate and bounded, deadline-aware retries, both
  strictly after the authorization record is committed.
* **Phase C (result)** — the resulting EXECUTED/FAILED/REJECTED event is
  appended in a fresh transaction, carrying a stable
  :class:`~era.core.result.ProviderErrorCode` on failure.

Dispatch order (never reordered):

    AUTHORIZATION -> AUDIT AUTHORIZATION COMMITTED -> RELIABILITY / DISPATCH
    LAYER -> PROVIDER EXECUTE -> RECORD EXECUTED / FAILED / REJECTED

The engine and this service are the only route to execution; providers are never
directly invokable by routes or the agent loop.
"""

from __future__ import annotations

import time
from dataclasses import replace

from era.core.action import Action
from era.core.circuit_breaker import CircuitBreakerConfig, CircuitBreakerRegistry
from era.core.context import ExecutionContext
from era.core.enums import Decision, Outcome, RiskLevel
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.core.retry import RetryPolicy, with_retry
from era.core.timeout import run_with_timeout
from era.core.tool_registry import ActionCatalog, ToolRegistry
from era.db import transaction
from era.models.confirmation import STATUS_DENIED, STATUS_EXPIRED, STATUS_USED
from era.schemas.actions import ExecutionResponse
from era.security.result_safety import (
    UnsafeResultError,
    redact_sensitive_text,
    sanitize_action_result,
)
from era.security.validation import ValidationError_, validate_param_schema, validate_params


def _retry_policy_from_settings(settings) -> RetryPolicy:
    """Build the default retry policy from settings (safe bounded defaults)."""
    return RetryPolicy(
        max_attempts=int(getattr(settings, "provider_retry_max_attempts", 3)),
        base_backoff_seconds=float(getattr(settings, "provider_retry_base_backoff_seconds", 0.1)),
        max_backoff_seconds=float(getattr(settings, "provider_retry_max_backoff_seconds", 2.0)),
        backoff_factor=float(getattr(settings, "provider_retry_backoff_factor", 2.0)),
    )


def _breaker_registry_from_settings(settings) -> CircuitBreakerRegistry:
    """Build the default per-provider circuit-breaker registry from settings."""
    return CircuitBreakerRegistry(CircuitBreakerConfig(
        failure_threshold=int(getattr(settings, "circuit_breaker_failure_threshold", 5)),
        cooldown_seconds=float(getattr(settings, "circuit_breaker_cooldown_seconds", 30.0)),
    ))


class ExecutionService:
    def __init__(self, *, session_factory, catalog: ActionCatalog, registry: ToolRegistry,
                 permission_engine, audit_service, confirmation_service, policy_service, settings,
                 retry_policy: RetryPolicy | None = None,
                 circuit_breakers: CircuitBreakerRegistry | None = None):
        self.session_factory = session_factory
        self.catalog = catalog
        self.registry = registry
        self.permission_engine = permission_engine
        self.audit_service = audit_service
        self.confirmation_service = confirmation_service
        self.policy_service = policy_service
        self.settings = settings
        # Phase 1F reliability layer (provider-agnostic; defaults from settings).
        self.retry_policy = retry_policy or _retry_policy_from_settings(settings)
        self.circuit_breakers = circuit_breakers or _breaker_registry_from_settings(settings)

    # -- public entry points --------------------------------------------------
    def request(self, action: Action, ctx: ExecutionContext) -> ExecutionResponse:
        policy = self.policy_service.get_current()
        policy_version = policy.version if policy else 0
        risk_level, domain, provider_id, credential_ref = self._meta(action.action_type, ctx)

        if self._forbidden(action.action_type):
            self._record(action, ctx, RiskLevel.FORBIDDEN, Decision.DENY, Outcome.DENIED_BY_POLICY,
                         policy_version, domain, provider_id, credential_ref,
                         result="forbidden action")
            return ExecutionResponse(status="denied", decision=Decision.DENY,
                                     message="forbidden")

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

            if self._forbidden(confirmation.action_type) or self._forbidden(action.action_type):
                self.confirmation_service.mark_status(session, confirmation, STATUS_DENIED)
                self.audit_service.record(
                    session, action=action, ctx=ctx,
                    risk_level=RiskLevel.FORBIDDEN,
                    decision=Decision.DENY, outcome=Outcome.DENIED_BY_POLICY,
                    policy_version=confirmation.policy_version,
                    confirmation_id=confirmation.id, result="forbidden action",
                )
                return ExecutionResponse(status="denied", decision=Decision.DENY,
                                         message="forbidden")

            # Phase 2A: confirmations are actor-bound — only the initiating
            # actor may approve. A different actor is a deny (fail closed).
            if confirmation.actor_id is not None and confirmation.actor_id != ctx.actor_id:
                self.confirmation_service.mark_status(session, confirmation, STATUS_DENIED)
                self.audit_service.record(
                    session, action=action, ctx=ctx,
                    risk_level=confirmation.risk_level,
                    decision=Decision(confirmation.decision), outcome=Outcome.REJECTED,
                    policy_version=confirmation.policy_version,
                    confirmation_id=confirmation.id,
                    result="confirmation belongs to another actor",
                )
                return ExecutionResponse(status="denied", decision=Decision(confirmation.decision),
                                         message="denied")

            ok, reason = self.confirmation_service.validate(confirmation, action, challenge)
            if not ok:
                if confirmation.status in (STATUS_USED, STATUS_DENIED, STATUS_EXPIRED):
                    # Already terminal: record the redundant attempt WITHOUT
                    # mutating the confirmation (a duplicate approve/deny must
                    # never overwrite the real outcome — Phase 3B fix).
                    self.audit_service.record(
                        session, action=action, ctx=ctx,
                        risk_level=confirmation.risk_level,
                        decision=Decision(confirmation.decision), outcome=Outcome.REJECTED,
                        policy_version=confirmation.policy_version,
                        confirmation_id=confirmation.id,
                        result=f"redundant resolution attempt: {reason}",
                    )
                else:
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
            # Restore the server-derived stateful-provider scope that initiated
            # the confirmation. The approving HTTP request has its own API-key
            # session, but browser dispatch must resume the original agent run.
            dispatch_ctx = ctx.model_copy(update={
                "execution_scope": confirmation.execution_scope or ctx.execution_scope,
            })
            self.confirmation_service.mark_status(session, confirmation, STATUS_USED)
            _, domain, provider_id, credential_ref = self._meta(
                confirmation.action_type, dispatch_ctx,
            )
            self.audit_service.record(
                session, action=action, ctx=dispatch_ctx,
                risk_level=confirmation.risk_level,
                decision=decision, outcome=Outcome.AUTHORIZED,
                policy_version=policy_version, confirmation_id=cid,
                provider_id=provider_id, capability_domain=domain, credential_ref=credential_ref,
            )

        # Dispatch OUTSIDE the transaction, then record the result.
        return self._dispatch_and_record(action, dispatch_ctx, decision, policy_version, cid)

    def deny(self, confirmation_id: str, ctx: ExecutionContext) -> ExecutionResponse:
        with transaction(self.session_factory) as session:
            confirmation = self.confirmation_service.get(session, confirmation_id)
            if confirmation is None:
                return ExecutionResponse(status="denied", decision=Decision.DENY,
                                         message="unknown confirmation")
            if confirmation.status != "PENDING":
                return ExecutionResponse(status="denied", decision=Decision(confirmation.decision),
                                         message=f"already {confirmation.status}")

            # Phase 2A: only the initiating actor may deny (admin can still act
            # on their own confirmations; cross-actor denial is rejected).
            if confirmation.actor_id is not None and confirmation.actor_id != ctx.actor_id:
                return ExecutionResponse(status="denied", decision=Decision(confirmation.decision),
                                         message="denied")

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
    def _forbidden(self, action_type: str) -> bool:
        spec = self.catalog.get(action_type)
        return spec is not None and spec.risk_level is RiskLevel.FORBIDDEN

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
            # Bind identity and the server-derived provider scope. Actor binding
            # controls who may approve; scope binding restores the exact
            # stateful browser context after an out-of-band approval.
            confirmation.actor_id = ctx.actor_id
            confirmation.execution_scope = ctx.execution_scope
            self.confirmation_service.confirmation_repo.update(session, confirmation)
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
            outcome = Outcome.REJECTED
            result = ActionResult(success=False, summary="no provider registered for action")
            error_code = ProviderErrorCode.NOT_IMPLEMENTED
        else:
            outcome, result, error_code = self._run_provider(provider, action, ctx)

        summary = result.summary
        risk_level, domain, provider_id, credential_ref = self._meta(action.action_type, ctx)
        self._record(action, ctx, risk_level, decision, outcome, policy_version,
                     domain, provider_id, credential_ref, confirmation_id=confirmation_id,
                     result=summary, error_code=error_code.value if error_code else None)

        status = {Outcome.EXECUTED: "executed", Outcome.FAILED: "failed",
                  Outcome.REJECTED: "rejected"}[outcome]
        return ExecutionResponse(status=status, decision=decision, result=result,
                                 message=None if result.success else summary,
                                 error_code=error_code.value if error_code else None)

    def _timeout_budget(self) -> float:
        return float(getattr(self.settings, "provider_timeout_seconds", 0.0) or 0.0)

    def _retry_policy_for(self, provider, action_type: str) -> RetryPolicy:
        """Disable transport retries for provider-declared side effects."""

        no_retry = getattr(provider, "non_retryable_action_types", frozenset())
        if action_type in no_retry and self.retry_policy.max_attempts != 1:
            return replace(self.retry_policy, max_attempts=1)
        return self.retry_policy

    def _dispatch_context(self, ctx: ExecutionContext) -> ExecutionContext:
        """Return a context advertising an absolute monotonic deadline."""
        budget = self._timeout_budget()
        if budget <= 0 or ctx.deadline is not None:
            return ctx
        return ctx.model_copy(update={"deadline": time.monotonic() + budget})

    def _run_provider(self, provider, action, ctx) -> tuple[
        Outcome, ActionResult, ProviderErrorCode | None,
    ]:
        budget = self._timeout_budget()
        dispatch_ctx = self._dispatch_context(ctx)
        breaker = self.circuit_breakers.get(provider.id)

        # Reliability gate (Phase 1F). Consulted ONLY after Phase A has durably
        # committed the authorization record and outside any DB transaction, so
        # it can never bypass the permission engine or audit-before-execute —
        # it can only block dispatch. OPEN -> deterministic UNAVAILABLE failure.
        if not breaker.allow_request():
            return (
                Outcome.FAILED,
                ActionResult(
                    success=False,
                    summary=f"provider {provider.id} circuit open: dispatch blocked",
                ),
                ProviderErrorCode.UNAVAILABLE,
            )

        # validate -----------------------------------------------------------------
        # Phase 3H: Action-aware schema enforcement (fail closed before dispatch).
        spec = self.catalog.get(action.action_type)
        if spec is not None and spec.param_schema is not None:
            try:
                validate_param_schema(action.params, spec.param_schema)
            except ValidationError_ as e:
                return (
                    Outcome.REJECTED,
                    ActionResult(success=False, summary=f"parameter validation failed: {e}"),
                    ProviderErrorCode.VALIDATION,
                )
            except Exception as e:  # noqa: BLE001
                return (
                    Outcome.REJECTED,
                    ActionResult(success=False, summary=f"parameter validation error: {e}"),
                    ProviderErrorCode.VALIDATION,
                )

        try:
            validate_params(action.params, action_type=action.action_type)
        except ValidationError_ as e:
            return (
                Outcome.REJECTED,
                ActionResult(success=False, summary=f"parameter validation failed: {e}"),
                ProviderErrorCode.VALIDATION,
            )

        # Single attempt: a validation rejection is REJECTED (bad input), never
        # retried and never fed to the circuit breaker (it is not a health
        # signal). Preserve the provider's code when it already classifies the
        # rejection, but never let a non-validation code masquerade as a
        # successful validate.
        try:
            run_with_timeout(
                lambda: provider.validate(action),
                timeout_seconds=budget, provider_id=provider.id, stage="validate",
            )
        except ToolError as e:
            code = e.code if e.code in (
                ProviderErrorCode.VALIDATION, ProviderErrorCode.FORBIDDEN,
                ProviderErrorCode.NOT_FOUND, ProviderErrorCode.TIMEOUT,
            ) else ProviderErrorCode.VALIDATION
            safe_error = redact_sensitive_text(str(e))
            return Outcome.REJECTED, ActionResult(success=False, summary=safe_error), code

        # execute (retryable, deadline-aware) ----------------------------------------
        # with_retry only retries explicitly retryable codes (UNAVAILABLE /
        # PROVIDER_ERROR), respects the cooperative dispatch deadline and is
        # additionally bounded by the same hard wall-clock timeout as Phase 1E
        # — a timeout can never cause an unbounded retry loop.
        try:
            retry_policy = self._retry_policy_for(provider, action.action_type)
            result = run_with_timeout(
                lambda: with_retry(
                    lambda: provider.execute(action, dispatch_ctx),
                    policy=retry_policy,
                    deadline=dispatch_ctx.deadline,
                    provider_id=provider.id,
                ),
                timeout_seconds=budget, provider_id=provider.id, stage="execute",
            )
            try:
                result = sanitize_action_result(
                    result,
                    max_bytes=int(getattr(
                        self.settings, "provider_result_max_bytes", 524_288,
                    )),
                )
            except UnsafeResultError:
                # Result sanitization is after provider invocation and never
                # enters the retry loop: a mutating side effect may already
                # have happened, and unsafe output must not be surfaced.
                breaker.record_failure(ProviderErrorCode.INTERNAL)
                return (
                    Outcome.FAILED,
                    ActionResult(success=False, summary="provider returned an unsafe result"),
                    ProviderErrorCode.INTERNAL,
                )
            if result.success:
                breaker.record_success()
                return Outcome.EXECUTED, result, None
            # Failure result (no exception): treat as PROVIDER_ERROR — eligible
            # for the breaker, but not retried (no code to classify it on).
            breaker.record_failure(ProviderErrorCode.PROVIDER_ERROR)
            failed = ActionResult(
                success=False,
                summary=result.summary or "provider returned failure",
            )
            return Outcome.FAILED, failed, ProviderErrorCode.PROVIDER_ERROR
        except ToolError as e:
            # Timeouts, retry exhaustion and provider-authored failures are FAILED.
            # record_failure ignores ineligible codes (AUTH, FORBIDDEN, TIMEOUT,
            # ...), so authorization/policy failures never trip the breaker.
            breaker.record_failure(e.code)
            safe_error = redact_sensitive_text(str(e))
            return Outcome.FAILED, ActionResult(success=False, summary=safe_error), e.code
        except Exception as e:  # noqa: BLE001
            # INTERNAL is never breaker-eligible, so this is a no-op for the
            # breaker; kept explicit for readability.
            breaker.record_failure(ProviderErrorCode.INTERNAL)
            failed = ActionResult(
                success=False,
                summary=f"provider error: {type(e).__name__}",
            )
            return Outcome.FAILED, failed, ProviderErrorCode.INTERNAL

    def _record(self, action, ctx, risk_level, decision, outcome, policy_version,
                domain, provider_id, credential_ref, confirmation_id=None, result=None,
                error_code=None):
        with transaction(self.session_factory) as session:
            self.audit_service.record(
                session, action=action, ctx=ctx, risk_level=risk_level,
                decision=decision, outcome=outcome, policy_version=policy_version,
                confirmation_id=confirmation_id, result=result, error_code=error_code,
                provider_id=provider_id,
                capability_domain=domain, credential_ref=credential_ref,
            )
