"""Phase 4C + 4D — the durable, resumable, exactly-once workflow engine.

The engine is an *ExecutionService-only* orchestrator: every inner step is
dispatched through :class:`era.services.execution_service.ExecutionService`,
so each step still passes the permission engine, confirmation, audit and
reliability gates independently. The engine itself never calls a provider
directly and never invents a browser reference — targets are re-acquired by
re-inspecting the current page at run time.

Phase 4D extends the engine with a *bounded declarative DAG* (``depends_on``,
``condition``, ``parallel``), deterministic governance admission, immutable
template versions and an operator review/observability surface. These additions
do not weaken the durability/resumability/exactly-once/fail-closed guarantees.

Durability / resumability:

* every run and per-step result is persisted to ``workflow_run`` /
  ``workflow_step_run``;
* a paused run (waiting for a confirmation) is resumed from its durable
  checkpoint; a process-restarted run is resumed the same way;
* on resume the engine re-inspects the current page and re-acquires targets
  fail-closed — it never trusts persisted browser state and never re-executes
  a mutating step;
* resume is actor-bound and preserves the original ``execution_scope``.

Fail-closed semantics:

* a step's ``expect`` post-condition is a hard gate (the browser provider
  already enforces it inside the action);
* ``SIDE_EFFECT_UNKNOWN`` maps to a workflow-level ``ambiguous`` state that
  requires explicit operator resolution (never auto-continue / auto-retry);
* drift, stale refs, multi-match, denied/expired confirmations and budget
  breaches stop the workflow deterministically.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import Decision, Outcome
from era.core.result import ProviderErrorCode
from era.core.tool_registry import ActionCatalog
from era.db import transaction
from era.models.confirmation import (
    STATUS_DENIED as CONF_DENIED,
)
from era.models.confirmation import (
    STATUS_EXPIRED as CONF_EXPIRED,
)
from era.models.confirmation import (
    STATUS_PENDING as CONF_PENDING,
)
from era.models.confirmation import (
    STATUS_USED as CONF_USED,
)
from era.models.workflow import (
    STATUS_AMBIGUOUS,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    STATUS_WAITING,
    WorkflowRun,
    WorkflowStepRun,
)
from era.repositories.base import WorkflowRunRepo
from era.security.redaction import redact
from era.workflows.catalog import WorkflowCatalog
from era.workflows.definition import (
    WorkflowDefinition,
    WorkflowDefinitionError,
    WorkflowStep,
    redact_definition,
    redact_run_params,
    render_step_expect,
    render_workflow_params,
    validate_workflow_definition,
)

_NON_RETRYABLE = frozenset({
    "browser.click", "browser.fill", "browser.submit",
    "browser.download", "browser.upload",
})

logger = logging.getLogger(__name__)


class WorkflowServiceError(Exception):
    """Fail-closed workflow service error surfaced to the API layer."""


class WorkflowNotAllowed(WorkflowServiceError):
    """The actor/role is not allowed to run a workflow or one of its steps."""


class WorkflowNotFound(WorkflowServiceError):
    """Unknown run id."""


class WorkflowAlreadyTerminal(WorkflowServiceError):
    """Resume/cancel/resolve on a terminal run."""


class WorkflowStateError(WorkflowServiceError):
    """Actor mismatch / invalid transition."""


#: Statuses that mean a step's outcome is settled.
_TERMINAL_STEP_STATUSES = frozenset({
    STATUS_COMPLETED, STATUS_FAILED, STATUS_AMBIGUOUS, STATUS_CANCELLED,
    "skipped", "skipped_conditional",
})


class WorkflowService:
    def __init__(
        self,
        *,
        session_factory,
        catalog: ActionCatalog,
        workflow_catalog: WorkflowCatalog,
        workflow_repo: WorkflowRunRepo,
        execution_service,
        confirmation_service,
        audit_service,
        settings,
        idempotency_service=None,
        governance_service=None,
        template_service=None,
    ):
        self.session_factory = session_factory
        self.catalog = catalog
        self.workflow_catalog = workflow_catalog
        self.repo = workflow_repo
        self.execution_service = execution_service
        self.confirmation_service = confirmation_service
        self.audit_service = audit_service
        self.idempotency_service = idempotency_service
        self.settings = settings
        self.governance_service = governance_service
        self.template_service = template_service

    # -- settings -------------------------------------------------------------
    @property
    def max_steps(self) -> int:
        return int(getattr(self.settings, "workflow_max_steps", 50))

    @property
    def max_wallclock_seconds(self) -> float:
        return float(getattr(self.settings, "workflow_max_wallclock_seconds", 600.0))

    @property
    def max_pending_confirmations(self) -> int:
        return int(getattr(self.settings, "workflow_max_pending_confirmations", 1))

    @property
    def max_parallel_concurrency(self) -> int:
        return int(getattr(self.settings, "workflow_max_parallel_concurrency", 4))

    # -- public API -----------------------------------------------------------
    def start(
        self,
        *,
        definition: WorkflowDefinition | str,
        params: dict[str, Any],
        ctx: ExecutionContext,
        run_token: str,
        domain_allowed: Callable[[str], bool],
        template_name: str | None = None,
        template_version: int | None = None,
        scheduled: bool = False,
        schedule_id: str | None = None,
        source: str | None = None,
    ) -> WorkflowRun:
        """Register-or-resolve a definition and begin a run.

        ``run_token`` is the exactly-once key (unique per actor): starting a run
        with a token that already produced a run returns the existing run and
        never re-executes anything.

        When ``template_name`` is given the run is pinned to the exact immutable
        template version; the definition is rehydrated from that template on
        resume so a later template version never silently changes the run.
        """
        if not isinstance(domain_allowed, Callable):
            raise WorkflowServiceError("domain_allowed is required")
        resolved = self._resolve_definition(definition, template_name=template_name,
                                            template_version=template_version)

        # Workflow-level RBAC gate: the actor must be allowed to run the
        # workflow action and every inner step domain.
        if not domain_allowed("browser.workflow_run"):
            raise WorkflowNotAllowed("role is not allowed to run browser workflows")
        # If the caller pinned an explicit version, it must match the definition.
        if template_version is not None and resolved.version != template_version:
            raise WorkflowServiceError(
                f"template {resolved.name!r} is not at version {template_version}")
        for step in resolved.steps:
            if not domain_allowed(step.action):
                raise WorkflowNotAllowed(
                    f"role is not allowed to run workflow step {step.action!r}")

        run_token = (run_token or "").strip() or uuid.uuid4().hex
        now = _utcnow()
        with transaction(self.session_factory) as session:
            existing = self.repo.get_run_by_token(session, ctx.actor_id, run_token)
            if existing is not None:
                return existing  # exactly-once: never start the same run twice

        # Deterministic governance admission before any run row is started.
        governance_code: str | None = None
        if self.governance_service is not None:
            try:
                self.governance_service.claim_start(
                    actor_id=ctx.actor_id, workflow_name=resolved.name)
            except Exception as exc:  # noqa: BLE001 — map to machine code
                governance_code = getattr(exc, "code", "BUDGET_EXCEEDED")
                return self._create_failed_run(
                    resolved, params, ctx, run_token, governance_code,
                    template_name=template_name,
                    template_version=resolved.version,
                    scheduled=scheduled, schedule_id=schedule_id, source=source)

        with transaction(self.session_factory) as session:
            run_id = uuid.uuid4().hex
            run = WorkflowRun(
                id=run_id,
                workflow_name=resolved.name,
                workflow_version=resolved.version,
                actor_id=ctx.actor_id,
                execution_scope=ctx.execution_scope,
                status=STATUS_PENDING,
                current_step=0,
                run_token=run_token,
                resume_token=uuid.uuid4().hex,
                definition_checksum=self.workflow_catalog.checksum(resolved),
                definition_redacted=redact_definition(resolved),
                run_params=redact_run_params(params),
                created_at=now,
                updated_at=now,
                template_name=template_name,
                template_version=resolved.version if template_name else None,
                template_checksum=self.workflow_catalog.checksum(resolved)
                if template_name else None,
                started_at=now,
                source=source,
                parallel_cap=self._max_parallel_cap(resolved),
                scheduled=bool(scheduled),
                schedule_id=schedule_id,
            )
            # Isolate the run's own ephemeral browser context and preserve the
            # original scope across approval + resume (Phase 4A.1 design).
            run.execution_scope = ctx.execution_scope or f"workflow:{run.id}"
            self.repo.create_run(session, run)
            self._create_step_rows(session, run_id, resolved)

        dispatch_ctx = ctx.model_copy(
            update={"execution_scope": run.execution_scope})
        return self._advance(run_id, dispatch_ctx, domain_allowed)

    def _create_failed_run(
        self, resolved: WorkflowDefinition, params: dict[str, Any],
        ctx: ExecutionContext, run_token: str, governance_code: str,
        *, template_name: str | None = None,
        template_version: int | None = None,
        scheduled: bool = False, schedule_id: str | None = None,
        source: str | None = None,
    ) -> WorkflowRun:
        """Create a deterministic FAILED run row for an admission cap breach."""
        now = _utcnow()
        with transaction(self.session_factory) as session:
            run_id = uuid.uuid4().hex
            run = WorkflowRun(
                id=run_id,
                workflow_name=resolved.name,
                workflow_version=resolved.version,
                actor_id=ctx.actor_id,
                execution_scope=ctx.execution_scope,
                status=STATUS_FAILED,
                current_step=0,
                run_token=run_token,
                resume_token=uuid.uuid4().hex,
                definition_checksum=self.workflow_catalog.checksum(resolved),
                definition_redacted=redact_definition(resolved),
                run_params=redact_run_params(params),
                created_at=now,
                updated_at=now,
                template_name=template_name,
                template_version=template_version,
                template_checksum=self.workflow_catalog.checksum(resolved)
                if template_name else None,
                started_at=now,
                finished_at=now,
                error=f"governance admission denied ({governance_code})",
                governance_code=governance_code,
                parallel_cap=self._max_parallel_cap(resolved),
                scheduled=bool(scheduled),
                schedule_id=schedule_id,
                source=source,
            )
            self.repo.create_run(session, run)
        return run

    def resume(self, run_id: str, ctx: ExecutionContext,
               domain_allowed: Callable[[str], bool]) -> WorkflowRun:
        """Resume a paused / interrupted run from its durable checkpoint."""
        run = self._load_owned(run_id, ctx.actor_id)
        if run.status in (STATUS_COMPLETED, STATUS_CANCELLED):
            return run
        if run.status in (STATUS_FAILED, STATUS_AMBIGUOUS):
            raise WorkflowAlreadyTerminal(
                f"run is {run.status}; use resolve/cancel for ambiguous runs")
        dispatch_ctx = ctx.model_copy(
            update={"execution_scope": run.execution_scope or ctx.execution_scope})
        return self._advance(run_id, dispatch_ctx, domain_allowed)

    def cancel(self, run_id: str, ctx: ExecutionContext) -> WorkflowRun:
        run = self._load_owned(run_id, ctx.actor_id)
        if run.status in (STATUS_COMPLETED, STATUS_CANCELLED, STATUS_FAILED,
                          STATUS_AMBIGUOUS):
            return run
        with transaction(self.session_factory) as session:
            run.status = STATUS_CANCELLED
            run.error = "cancelled by operator"
            run.finished_at = _utcnow()
            run.updated_at = _utcnow()
            self.repo.update_run(session, run)
        self._release_governance(run)
        return run

    def resolve_ambiguous(self, run_id: str, ctx: ExecutionContext,
                          decision: str) -> WorkflowRun:
        """Operator resolution for an ambiguous run: ``"continue"`` or ``"abort"``."""
        run = self._load_owned(run_id, ctx.actor_id)
        if run.status != STATUS_AMBIGUOUS:
            raise WorkflowStateError(f"run is not ambiguous (status={run.status})")
        if decision not in ("continue", "abort"):
            raise WorkflowStateError("resolution decision must be 'continue' or 'abort'")
        if decision == "abort":
            with transaction(self.session_factory) as session:
                run.status = STATUS_CANCELLED
                run.error = "ambiguous outcome aborted by operator"
                run.finished_at = _utcnow()
                run.updated_at = _utcnow()
                self.repo.update_run(session, run)
            self._release_governance(run)
            return run
        # continue: mark the ambiguous step resolved and advance WITHOUT
        # re-running it (its outcome is unknown; we never guess).
        with transaction(self.session_factory) as session:
            steps = self.repo.list_steps(session, run_id)
            target = next((s for s in steps if s.step_index == run.current_step), None)
            if target is not None and target.status == STATUS_AMBIGUOUS:
                target.status = STATUS_COMPLETED
                target.result_receipt = {
                    "resolved": "operator_continue",
                    "outcome_unknown": True,
                }
                target.error_message = None
                target.finished_at = _utcnow()
                self.repo.update_step(session, target)
            run.status = STATUS_RUNNING
            run.current_step = run.current_step + 1
            run.error = None
            run.updated_at = _utcnow()
            self.repo.update_run(session, run)
        dispatch_ctx = ctx.model_copy(
            update={"execution_scope": run.execution_scope or ctx.execution_scope})
        return self._advance(run_id, dispatch_ctx, lambda at: True)

    def get_run(self, run_id: str, ctx: ExecutionContext) -> tuple[WorkflowRun, list[WorkflowStepRun]]:
        run = self._load_owned(run_id, ctx.actor_id)
        with transaction(self.session_factory) as session:
            steps = self.repo.list_steps(session, run_id)
        return run, steps

    def list_runs(self, ctx: ExecutionContext) -> list[WorkflowRun]:
        with transaction(self.session_factory) as session:
            return self.repo.list_runs_by_actor(session, ctx.actor_id)

    # -- operator review / observability -------------------------------------
    def list_awaiting_runs(self, *, limit: int = 50) -> list[WorkflowRun]:
        with transaction(self.session_factory) as session:
            return self.repo.list_awaiting_runs(session, limit=limit)

    def list_runs_filtered(
        self,
        *,
        ctx: ExecutionContext,
        status: str | None = None,
        workflow_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
        admin: bool = False,
    ) -> list[WorkflowRun]:
        actor_id = None if admin else ctx.actor_id
        limit = min(max(int(limit), 1), 200)
        offset = max(int(offset), 0)
        with transaction(self.session_factory) as session:
            return self.repo.list_runs_filtered(
                session, actor_id=actor_id, status=status,
                workflow_name=workflow_name, limit=limit, offset=offset)

    def aggregate_runs(
        self,
        *,
        ctx: ExecutionContext,
        workflow_name: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
        admin: bool = False,
    ) -> dict[str, Any]:
        actor_id = None if admin else ctx.actor_id
        statuses = [STATUS_COMPLETED, STATUS_FAILED, STATUS_AMBIGUOUS, STATUS_WAITING,
                    STATUS_CANCELLED, STATUS_RUNNING, STATUS_PENDING]
        result: dict[str, Any] = {"workflow": workflow_name, "total": 0,
                                  "by_status": {}, "durations": {}}
        for status in statuses:
            with transaction(self.session_factory) as session:
                count = self.repo.count_runs_filtered(
                    session, actor_id=actor_id, status=status,
                    workflow_name=workflow_name, start_at=start_at, end_at=end_at)
            result["by_status"][status] = count
            result["total"] += count
        durations: list[float] = []
        with transaction(self.session_factory) as session:
            runs = self.repo.list_runs_filtered(
                session, actor_id=actor_id, status=STATUS_COMPLETED,
                workflow_name=workflow_name, limit=500, offset=0)
        for run in runs:
            if run.finished_at and run.started_at:
                try:
                    from datetime import datetime as _dt
                    started = _dt.fromisoformat(run.started_at)
                    finished = _dt.fromisoformat(run.finished_at)
                    durations.append((finished - started).total_seconds())
                except Exception:  # malformed timestamps are skipped
                    logger.debug("skipping malformed workflow duration timestamp",
                                 exc_info=True)
                    continue
        if durations:
            ordered = sorted(durations)
            result["durations"] = {
                "count": len(ordered),
                "mean": sum(ordered) / len(ordered),
                "p50": ordered[len(ordered) // 2],
                "p95": ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))],
                "p99": ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))],
            }
        return result

    def run_timeline(self, run_id: str, ctx: ExecutionContext,
                     *, admin: bool = False) -> list[dict[str, Any]]:
        self._load_run(run_id, ctx, admin=admin)  # owner/admin authorization gate
        with transaction(self.session_factory) as session:
            steps = self.repo.list_steps(session, run_id)
        events: list[dict[str, Any]] = []
        for step in steps:
            if step.started_at:
                events.append({"at": step.started_at, "kind": "step_started",
                               "step_id": step.step_id, "status": step.status})
            if step.status == STATUS_WAITING:
                events.append({"at": step.finished_at or step.started_at,
                               "kind": "step_paused", "step_id": step.step_id,
                               "confirmation_id": step.confirmation_id})
            if step.status == STATUS_AMBIGUOUS:
                events.append({"at": step.finished_at or step.started_at,
                               "kind": "step_ambiguous", "step_id": step.step_id,
                               "error_code": step.error_code})
            if step.status in (STATUS_COMPLETED, STATUS_FAILED, "skipped",
                               "skipped_conditional"):
                events.append({"at": step.finished_at or step.started_at,
                               "kind": "step_finished", "step_id": step.step_id,
                               "status": step.status})
        events.sort(key=lambda e: e.get("at") or "")
        return events[:200]

    def admin_resolve_ambiguous(self, run_id: str, admin_ctx: ExecutionContext,
                                decision: str, reason: str) -> WorkflowRun:
        run = self._load_run_any(run_id)
        if run.status != STATUS_AMBIGUOUS:
            raise WorkflowStateError(f"run is not ambiguous (status={run.status})")
        with transaction(self.session_factory) as session:
            self.audit_service.record(
                session, action=Action(action_type="workflow.operator.resolve",
                                       params={"run_id": run_id, "decision": decision}),
                ctx=admin_ctx, risk_level=None, decision=Decision.ALLOW,
                outcome=Outcome.AUTHORIZED, policy_version=0,
                meta={"operator": True, "reason": reason})
        return self.resolve_ambiguous(run_id, _ctx_for_run(run), decision)

    def admin_cancel(self, run_id: str, admin_ctx: ExecutionContext,
                     reason: str) -> WorkflowRun:
        run = self._load_run_any(run_id)
        with transaction(self.session_factory) as session:
            self.audit_service.record(
                session, action=Action(action_type="workflow.operator.cancel",
                                       params={"run_id": run_id}),
                ctx=admin_ctx, risk_level=None, decision=Decision.ALLOW,
                outcome=Outcome.AUTHORIZED, policy_version=0,
                meta={"operator": True, "reason": reason})
        return self.cancel(run_id, _ctx_for_run(run))

    def admin_approve(self, confirmation_id: str, admin_ctx: ExecutionContext,
                      action: Action, reason: str):
        with transaction(self.session_factory) as session:
            self.audit_service.record(
                session, action=Action(action_type="workflow.operator.approve",
                                       params={"confirmation_id": confirmation_id}),
                ctx=admin_ctx, risk_level=None, decision=Decision.ALLOW,
                outcome=Outcome.AUTHORIZED, policy_version=0,
                meta={"operator": True, "reason": reason})
        return self.execution_service.approve(
            confirmation_id, action, admin_ctx, allow_cross_actor=True)

    # -- definition handling ---------------------------------------------------
    def _resolve_definition(self, definition: WorkflowDefinition | str,
                            *, template_name: str | None = None,
                            template_version: int | None = None) -> WorkflowDefinition:
        if isinstance(definition, str):
            resolved = self.workflow_catalog.get(definition)
            if resolved is None and self.template_service is not None:
                # Fall back to an exact published template version if it exists.
                try:
                    resolved = self.template_service.instantiate(
                        definition, {}, version=template_version)
                except Exception:  # noqa: BLE001 — unknown template/user error
                    resolved = None
            if resolved is None:
                raise WorkflowServiceError(f"unknown workflow: {definition!r}")
            return resolved
        if isinstance(definition, WorkflowDefinition):
            validate_workflow_definition(definition, self.catalog,
                                         max_steps=self.max_steps)
            existing = self.workflow_catalog.get(definition.name)
            if existing is None:
                self.workflow_catalog.register(definition, max_steps=self.max_steps)
            return definition
        raise WorkflowServiceError("workflow must be a registered name or definition")

    def _definition_for_run(self, run: WorkflowRun) -> WorkflowDefinition | None:
        """Rehydrate the exact definition a run started with.

        Template runs reload from the immutable template (pinned version);
        catalog runs reload from the catalog. Either way a checksum mismatch is
        fail-closed.
        """
        if run.template_name and self.template_service is not None:
            try:
                template = self.template_service.get(run.template_name,
                                                     run.template_version or 1)
            except Exception:  # noqa: BLE001
                template = None
            if template is None:
                return None
            definition = WorkflowDefinition.model_validate(
                dict(template.definition_redacted or {}))
            if self.workflow_catalog.checksum(definition) != run.definition_checksum:
                return None
            return definition
        return self.workflow_catalog.get(run.workflow_name)

    # -- engine ----------------------------------------------------------------
    def _advance(self, run_id: str, ctx: ExecutionContext,
                 domain_allowed: Callable[[str], bool]) -> WorkflowRun:
        run = self._load_owned(run_id, ctx.actor_id)
        definition = self._definition_for_run(run)
        if definition is None:
            self._set_run_failed(run, "workflow is no longer registered or template missing")
            return run
        if self.workflow_catalog.checksum(definition) != run.definition_checksum:
            self._set_run_failed(
                run, "workflow definition changed since the run started (checksum)")
            return run

        with transaction(self.session_factory) as session:
            step_rows = {s.step_index: s for s in self.repo.list_steps(session, run_id)}
        by_id = {step.id: idx for idx, step in enumerate(definition.steps)}

        deadline = time.monotonic() + self.max_wallclock_seconds
        running_indices: set[int] = set()
        while True:
            if time.monotonic() > deadline:
                self._set_run_failed(run, "workflow wall-clock budget exceeded")
                return run
            with transaction(self.session_factory) as session:
                step_rows = {s.step_index: s for s in self.repo.list_steps(session, run_id)}

            # Reconcile waiting steps BEFORE any new step is dispatched. An
            # approved confirmation must be recorded once and then the next
            # pending step may run; a still-pending confirmation keeps the run
            # paused (confirmation continuity per step).
            waiting_rows = [s for s in step_rows.values() if s.status == STATUS_WAITING]
            if waiting_rows:
                changed = False
                for row in waiting_rows:
                    outcome = self._handle_waiting_step(run, row, ctx)
                    if outcome in ("next", "denied_skip"):
                        changed = True
                    elif outcome in ("failed", "denied_stop"):
                        return run
                if changed:
                    continue
                run.status = STATUS_WAITING
                run.updated_at = _utcnow()
                self._persist_run(run)
                return run

            # Reconcile terminal / ambiguous overall state.
            if self._refresh_run_status(run, definition, step_rows):
                return run

            ready = self._ready_indices(definition, step_rows, by_id,
                                        running_indices, run_id)
            if not ready:
                # All steps terminal (completed/skipped) -> complete.
                if all(step_rows.get(idx) is not None
                       and step_rows[idx].status in _TERMINAL_STEP_STATUSES
                       for idx in range(len(definition.steps))):
                    run.status = STATUS_COMPLETED
                    run.current_step = len(definition.steps)
                    run.error = None
                    run.finished_at = _utcnow()
                    run.updated_at = _utcnow()
                    self._persist_run(run)
                    self._release_governance(run)
                    return run
                # Process confirmed / resolved waiting steps (resume).
                waiting_rows = [s for s in step_rows.values()
                                if s.status == STATUS_WAITING]
                if waiting_rows:
                    changed = False
                    for row in waiting_rows:
                        outcome = self._handle_waiting_step(run, row, ctx)
                        if outcome == "next" or outcome == "denied_skip":
                            changed = True
                        elif outcome in ("failed", "denied_stop"):
                            return run
                        # "still_waiting": keep the run paused.
                    if changed:
                        continue
                    run.status = STATUS_WAITING
                    run.updated_at = _utcnow()
                    self._persist_run(run)
                    return run
                return run

            batch = self._choose_batch(definition, step_rows, ready, by_id)
            if len(batch) > 1:
                self._execute_parallel_batch(
                    run, definition, step_rows, batch, ctx)
            else:
                idx = batch[0]
                self._set_current(run, idx)
                run = self._load_owned(run_id, ctx.actor_id)
                run.status = STATUS_RUNNING
                run.started_at = run.started_at or _utcnow()
                self._persist_run(run)
                step_def = definition.steps[idx]
                if not domain_allowed(step_def.action):
                    self._set_run_failed(
                        run, f"step {step_def.action!r} is not allowed for this role")
                    return run
                row = step_rows.get(idx)
                if row is not None and row.status == STATUS_WAITING:
                    outcome = self._handle_waiting_step(run, row, ctx)
                    if outcome == "next":
                        continue
                    if outcome == "still_waiting":
                        return run
                    if outcome == "denied_skip":
                        continue
                    if outcome == "denied_stop":
                        self._set_run_failed(run, "a required confirmation was denied")
                        return run
                    return run
                # Skip a step whose condition is false (conditional divergence).
                status = row.status if row is not None else STATUS_PENDING
                if status == STATUS_PENDING and step_def.condition is not None:
                    should_run = self._evaluate_condition(step_def, definition,
                                                          step_rows, by_id)
                    if should_run is False:
                        with transaction(self.session_factory) as session:
                            cur = self.repo.get_step(session, row.id) if row else None
                            if cur is not None and cur.status == STATUS_PENDING:
                                cur.status = "skipped_conditional"
                                cur.finished_at = _utcnow()
                                self.repo.update_step(session, cur)
                        continue
                row = self._execute_step(run, step_def, idx, ctx)
                outcome = self._classify_step_outcome(run, row, definition, step_rows)
                if outcome == "idle":
                    continue
                if outcome == "waiting":
                    return run
                if outcome == "ambiguous":
                    return run
                if outcome == "failed":
                    return run

            # After a parallel batch or a single step, reconcile status.
            with transaction(self.session_factory) as session:
                step_rows = {s.step_index: s for s in self.repo.list_steps(session, run_id)}
            if self._refresh_run_status(run, definition, step_rows):
                return run

    # -- parallel / condition helpers -----------------------------------------
    def _max_parallel_cap(self, definition: WorkflowDefinition) -> int:
        caps = [b.max_concurrency for b in definition.parallel]
        return max(caps) if caps else 1

    def _parallel_group(self, definition: WorkflowDefinition,
                        idx: int) -> tuple[str | None, int]:
        for block in definition.parallel:
            if definition.steps[idx].id in block.steps:
                return block.max_concurrency and block.steps and block.steps[0] or \
                    None, block.max_concurrency
        return None, 1

    def _ready_indices(self, definition: WorkflowDefinition,
                       step_rows: dict[int, WorkflowStepRun],
                       by_id: dict[str, int],
                       running_indices: set[int], run_id: str) -> list[int]:
        ready: list[int] = []
        for idx, step in enumerate(definition.steps):
            row = step_rows.get(idx)
            status = row.status if row is not None else STATUS_PENDING
            if status in _TERMINAL_STEP_STATUSES or status in (
                    STATUS_RUNNING, STATUS_WAITING) or idx in running_indices:
                continue
            deps_ok = True
            for dep_id in (step.depends_on or []):
                dep_idx = by_id.get(dep_id)
                if dep_idx is None:
                    deps_ok = False
                    break
                dep_row = step_rows.get(dep_idx)
                dep_status = dep_row.status if dep_row is not None else STATUS_PENDING
                if dep_status not in (STATUS_COMPLETED, "skipped", "skipped_conditional"):
                    deps_ok = False
                    break
            if deps_ok:
                ready.append(idx)
        return ready

    def _choose_batch(self, definition: WorkflowDefinition,
                      step_rows: dict[int, WorkflowStepRun],
                      ready: list[int], by_id: dict[str, int]) -> list[int]:
        if not ready:
            return []
        # Parallel groups: if multiple ready steps share a block with max>1, run
        # up to that block's concurrency cap.
        for block in definition.parallel:
            if block.max_concurrency <= 1:
                continue
            group_indices = [i for i in ready if definition.steps[i].id in block.steps]
            if len(group_indices) > 1:
                # Never exceed the configured pending-confirmation bound: a
                # parallel dispatch is bounded by both the block cap and the
                # workflow-wide confirmation hold limit.
                cap = min(block.max_concurrency, self.max_pending_confirmations)
                return group_indices[:cap]
        # Sequential, ordered execution preserves the existing behavior.
        return [min(ready)]

    def _execute_parallel_batch(self, run: WorkflowRun,
                                definition: WorkflowDefinition,
                                step_rows: dict[int, WorkflowStepRun],
                                batch: list[int], ctx: ExecutionContext) -> dict[int, str]:
        rows: dict[int, WorkflowStepRun] = {}
        # Claim all but one; the caller cannot bypass the run's wall-clock cap.
        if self.governance_service is not None:
            try:
                for _idx in batch:
                    self.governance_service.claim_step_budget(run_id=run.id)
            except Exception as exc:  # noqa: BLE001
                self._set_run_budget_failed(run, str(exc))
                return rows
        executor = ThreadPoolExecutor(max_workers=min(len(batch), 4),
                                      thread_name_prefix="era-wf-parallel")
        futures = {}
        try:
            for idx in batch:
                self._set_current(run, idx)
                futures[executor.submit(self._execute_step, run,
                                        definition.steps[idx], idx, ctx)] = idx
            for fut, idx in futures.items():
                try:
                    rows[idx] = fut.result()
                except Exception:  # noqa: BLE001
                    rows[idx] = self._mark_step(
                        str(run.id), STATUS_FAILED,
                        error_code=ProviderErrorCode.INTERNAL.value,
                        error_message="parallel step engine error")
        finally:
            executor.shutdown(wait=True)
        return rows

    # -- condition evaluation --------------------------------------------------
    def _evaluate_condition(self, step: WorkflowStep,
                            definition: WorkflowDefinition,
                            step_rows: dict[int, WorkflowStepRun],
                            by_id: dict[str, int]) -> bool | None:
        """Evaluate a pure predicate over prior receipts; returns None if unknown."""
        cond = step.condition
        if cond is None:
            return None
        dep_idx = by_id.get(cond.step_id) if cond.step_id else None
        dep_idx_final = dep_idx
        if cond.kind == "step_result":
            if dep_idx_final is None:
                return None
            row = step_rows.get(dep_idx_final)
            if row is None or row.result_receipt is None:
                return None
            try:
                value = self._result_value(row.result_receipt)
                if cond.op == "!=":
                    return bool(value != cond.value)
                return bool(value == cond.value)
            except Exception:  # noqa: BLE001
                return None
        if cond.kind == "url_contains":
            observed = self._recent_observation_url(step_rows)
            if observed is None:
                return None
            return bool(cond.value in observed)
        if cond.kind == "element_present":
            if dep_idx_final is None:
                return None
            row = step_rows.get(dep_idx_final)
            return bool(row is not None and row.result_receipt is not None
                        and isinstance(row.result_receipt, dict)
                        and row.result_receipt.get("elements_present") is not None)
        return None

    @staticmethod
    def _result_value(receipt: Any) -> Any:
        if isinstance(receipt, dict):
            if "result" in receipt:
                return receipt["result"]
            if "value" in receipt:
                return receipt["value"]
            if "url" in receipt:
                return receipt["url"]
            if "status" in receipt:
                return receipt["status"]
            # Fall through to scalar values for backwards compat.
            scalars = [v for v in receipt.values() if isinstance(v, (str, bool, int, float))]
            return scalars[0] if scalars else None
        return receipt

    @staticmethod
    def _recent_observation_url(step_rows: dict[int, WorkflowStepRun]) -> str | None:
        for idx in sorted(step_rows, reverse=True):
            row = step_rows[idx]
            if row.status != STATUS_COMPLETED:
                continue
            if row.result_receipt and isinstance(row.result_receipt, dict):
                url = row.result_receipt.get("url")
                if isinstance(url, str) and url:
                    return url
        return None

    # -- run status helpers -----------------------------------------------------
    def _refresh_run_status(self, run: WorkflowRun, definition: WorkflowDefinition,
                            step_rows: dict[int, WorkflowStepRun]) -> bool:
        """Sync run status from step rows. Returns True if the run is settled.

        ``waiting_for_user`` is intentionally NOT treated as settled here: a
        resume must re-enter the engine to reconcile approved confirmations.
        """
        ambiguous = [s for s in step_rows.values() if s.status == STATUS_AMBIGUOUS]
        failed = [s for s in step_rows.values()
                  if s.status == STATUS_FAILED and s.error_code]
        if ambiguous:
            run.status = STATUS_AMBIGUOUS
            run.error = "a step has an unknown outcome; operator resolution required"
            run.updated_at = _utcnow()
            self._persist_run(run)
            return True
        if failed and not any(s.status == STATUS_PENDING for s in step_rows.values()):
            run.status = STATUS_FAILED
            run.error = failed[0].error_message or "workflow step failed"
            run.finished_at = _utcnow()
            run.updated_at = _utcnow()
            self._persist_run(run)
            self._release_governance(run)
            return True
        return False

    def _classify_step_outcome(self, run: WorkflowRun, row: WorkflowStepRun,
                               definition: WorkflowDefinition,
                               step_rows: dict[int, WorkflowStepRun]) -> str:
        if row.status == STATUS_COMPLETED or row.status in ("skipped", "skipped_conditional"):
            with transaction(self.session_factory) as session:
                rows = self.repo.list_steps(session, run.id)
            pending = [idx for idx, s in enumerate(rows)
                       if s.status in (STATUS_PENDING, STATUS_RUNNING)]
            run.current_step = min(pending) if pending else len(rows)
            self._persist_run(run)
            return "idle"
        if row.status == STATUS_WAITING:
            run.status = STATUS_WAITING
            run.current_step = row.step_index
            run.updated_at = _utcnow()
            self._persist_run(run)
            return "waiting"
        if row.status == STATUS_AMBIGUOUS:
            run.status = STATUS_AMBIGUOUS
            run.error = "a step has an unknown outcome; operator resolution required"
            run.updated_at = _utcnow()
            self._persist_run(run)
            return "ambiguous"
        run.status = STATUS_FAILED
        run.error = row.error_message or "workflow step failed"
        run.finished_at = _utcnow()
        run.updated_at = _utcnow()
        self._persist_run(run)
        self._release_governance(run)
        return "failed"

    def _execute_step(self, run: WorkflowRun, step_def: WorkflowStep,
                      idx: int, ctx: ExecutionContext) -> WorkflowStepRun:
        # Load / create the step row and mark running.
        with transaction(self.session_factory) as session:
            existing = next((s for s in self.repo.list_steps(session, run.id)
                             if s.step_index == idx), None)
            if existing is None:
                existing = WorkflowStepRun(
                    id=uuid.uuid4().hex, run_id=run.id, step_id=step_def.id,
                    step_index=idx, action_type=step_def.action,
                    params_redacted=redact(step_def.params),
                    status=STATUS_PENDING, attempt=0,
                )
                self.repo.create_step(session, existing)
            existing.status = STATUS_RUNNING
            existing.attempt = existing.attempt + 1
            existing.started_at = _utcnow()
            existing.finished_at = None
            existing.depends_on = list(step_def.depends_on or [])
            if step_def.condition is not None:
                existing.condition = step_def.condition.model_dump(mode="json")
            group, _cap = self._parallel_group_from_definition(run, step_def)
            existing.parallel_group = group
            existing.parallel_index = idx
            self.repo.update_step(session, existing)
            step_id = existing.id

        # Deterministic per-step governance budget.
        if self.governance_service is not None:
            try:
                self.governance_service.claim_step_budget(run_id=run.id)
            except Exception as exc:  # noqa: BLE001
                self._set_run_budget_failed(run, str(exc))
                return self._mark_step(step_id, STATUS_FAILED,
                                       error_code="BUDGET_EXCEEDED",
                                       error_message=str(exc))
        try:
            rendered = render_workflow_params(step_def, run.run_params or {})
            if step_def.target is not None:
                rendered["element_ref"] = self._acquire_target(run, step_def, ctx)
            if step_def.expect is not None:
                rendered["expect"] = render_step_expect(step_def, run.run_params or {})
            action = Action(action_type=step_def.action, params=rendered)

            response = self.execution_service.request(action, ctx)

            if response.status == "executed":
                receipt = self._sanitize_receipt(
                    response.result.data if response.result else None)
                if step_def.outputs:
                    receipt = self._capture_outputs(receipt, step_def, run)
                return self._mark_step(
                    step_id, STATUS_COMPLETED,
                    receipt=receipt,
                    error_code=None, error_message=None)
            if response.status == "confirmation_required":
                with transaction(self.session_factory) as session:
                    row = self.repo.get_step(session, step_id)
                    if row is None:
                        raise WorkflowServiceError("step row missing")
                    row.status = STATUS_WAITING
                    row.confirmation_id = response.confirmation_id
                    self.repo.update_step(session, row)
                return row
            if response.status == "denied":
                if step_def.on_denied == "skip":
                    return self._mark_step(step_id, "skipped",
                                           error_message="step denied and skipped")
                return self._mark_step(step_id, STATUS_FAILED,
                                       error_message="step denied by policy")
            if response.error_code == ProviderErrorCode.SIDE_EFFECT_UNKNOWN.value:
                return self._mark_step(
                    step_id, STATUS_AMBIGUOUS,
                    error_code=ProviderErrorCode.SIDE_EFFECT_UNKNOWN.value,
                    error_message="step outcome is unknown (SIDE_EFFECT_UNKNOWN)")
            # failed / rejected
            code = response.error_code or ProviderErrorCode.PROVIDER_ERROR.value
            msg = response.message or "workflow step failed"
            if code == ProviderErrorCode.SIDE_EFFECT_UNKNOWN.value:
                return self._mark_step(step_id, STATUS_AMBIGUOUS,
                                       error_code=code, error_message=msg)
            return self._mark_step(step_id, STATUS_FAILED,
                                   error_code=code, error_message=msg)
        except WorkflowDefinitionError as exc:
            return self._mark_step(step_id, STATUS_FAILED,
                                   error_code=ProviderErrorCode.VALIDATION.value,
                                   error_message=str(exc))
        except WorkflowServiceError as exc:
            return self._mark_step(step_id, STATUS_FAILED,
                                   error_code=ProviderErrorCode.VALIDATION.value,
                                   error_message=str(exc))
        except Exception as exc:  # noqa: BLE001 - fail closed on engine errors
            return self._mark_step(step_id, STATUS_FAILED,
                                   error_code=ProviderErrorCode.INTERNAL.value,
                                   error_message=f"workflow engine error: "
                                                 f"{type(exc).__name__}: {exc}")

    def _capture_outputs(self, receipt: dict[str, Any] | None,
                         step_def: WorkflowStep, run: WorkflowRun) -> dict[str, Any]:
        safe = dict(receipt or {})
        for key, source in (step_def.outputs or {}).items():
            if isinstance(safe, dict):
                safe[key] = self._sanitize_receipt(safe.get(source))
        return safe

    def _create_step_rows(self, session, run_id: str,
                          definition: WorkflowDefinition) -> None:
        for idx, step in enumerate(definition.steps):
            row = WorkflowStepRun(
                id=uuid.uuid4().hex,
                run_id=run_id,
                step_id=step.id,
                step_index=idx,
                action_type=step.action,
                params_redacted=redact(step.params),
                status=STATUS_PENDING,
                attempt=0,
                depends_on=list(step.depends_on or []),
                condition=step.condition.model_dump(mode="json")
                if step.condition is not None else None,
            )
            group, _cap = self._parallel_group_from_definition(run=None,
                                                               step_def=step,
                                                               definition=definition)
            row.parallel_group = group
            row.parallel_index = idx
            self.repo.create_step(session, row)

    def _parallel_group_from_definition(self, run, step_def: WorkflowStep,
                                        definition: WorkflowDefinition | None = None):
        definition = definition or (self.workflow_catalog.get(run.workflow_name)
                                    if run is not None else None)
        if definition is None:
            return None, 1
        for block in definition.parallel:
            if step_def.id in block.steps:
                return block.steps and block.steps[0] or None, block.max_concurrency
        return None, 1

    def _acquire_target(self, run: WorkflowRun, step_def: WorkflowStep,
                        ctx: ExecutionContext) -> str:
        response = self.execution_service.request(
            Action(action_type="browser.inspect", params={}), ctx)
        if response.status != "executed" or response.result is None \
                or not response.result.success:
            raise WorkflowServiceError(
                "could not inspect the page to acquire a fresh element reference")
        elements = response.result.data.get("elements", []) if response.result.data else []
        matches = [e for e in elements if step_def.target.matches(e)]  # type: ignore[union-attr]
        index = step_def.target.index if step_def.target else None  # type: ignore[union-attr]
        if len(matches) == 0:
            raise WorkflowServiceError(
                "no element matches the step's target descriptor (re-inspect)")
        if index is None:
            if len(matches) > 1:
                raise WorkflowServiceError(
                    "target descriptor matched multiple elements (ambiguous)")
            chosen = matches[0]
        else:
            if index >= len(matches):
                raise WorkflowServiceError(
                    "target descriptor matched fewer elements than the requested index")
            chosen = matches[index]
        ref = chosen.get("element_ref")
        if not isinstance(ref, str) or not ref:
            raise WorkflowServiceError("fresh element reference is missing")
        return ref

    def _handle_waiting_step(self, run: WorkflowRun, row: WorkflowStepRun,
                             ctx: ExecutionContext) -> str:
        cid = row.confirmation_id
        if not cid:
            self._set_run_failed(run, "waiting step has no confirmation record")
            return "failed"
        with transaction(self.session_factory) as session:
            confirmation = self.confirmation_service.get(session, cid)
        if confirmation is None:
            self._set_run_failed(run, "confirmation record is missing")
            return "failed"
        if confirmation.status == CONF_PENDING:
            return "still_waiting"
        if confirmation.status == CONF_USED:
            outcome = self._confirmation_dispatch_outcome(cid)
            if outcome in ("FAILED", "REJECTED", "DENIED_BY_USER", "DENIED_BY_POLICY"):
                self._set_run_failed(
                    run, f"approved step dispatch did not succeed (outcome={outcome})")
                return "failed"
            if outcome is None or outcome not in ("EXECUTED", "AUTHORIZED"):
                self._set_run_failed(
                    run, "approved step has no recorded dispatch outcome")
                return "failed"
            ok = self._revalidate_post_condition(run, row, ctx)
            if not ok:
                self._set_run_failed(
                    run, "approved step failed post-condition revalidation")
                return "failed"
            with transaction(self.session_factory) as session:
                current = self.repo.get_step(session, row.id)
                if current is not None:
                    current.status = STATUS_COMPLETED
                    current.result_receipt = {
                        "approved": True,
                        "executed_once": True,
                        "confirmation_id": cid,
                    }
                    current.finished_at = _utcnow()
                    self.repo.update_step(session, current)
            return "next"
        if confirmation.status == CONF_DENIED:
            step_def = self._step_def_for(run, row.step_index)
            if step_def is not None and step_def.on_denied == "skip":
                with transaction(self.session_factory) as session:
                    current = self.repo.get_step(session, row.id)
                    if current is not None:
                        current.status = "skipped"
                        current.error_message = "confirmation denied; step skipped"
                        current.finished_at = _utcnow()
                        self.repo.update_step(session, current)
                return "denied_skip"
            return "denied_stop"
        if confirmation.status == CONF_EXPIRED:
            self._set_run_failed(run, "confirmation expired")
            return "failed"
        self._set_run_failed(run, f"confirmation in unexpected state {confirmation.status}")
        return "failed"

    def _revalidate_post_condition(self, run: WorkflowRun, row: WorkflowStepRun,
                                   ctx: ExecutionContext) -> bool:
        step_def = self._step_def_for(run, row.step_index)
        if step_def is None or step_def.expect is None:
            return True
        try:
            rendered_expect = render_step_expect(step_def, run.run_params or {}) or {}
            response = self.execution_service.request(
                Action(action_type="browser.inspect", params={}), ctx)
            if response.status != "executed" or response.result is None:
                return False
            url = str(response.result.data.get("url", "")) if response.result.data else ""
            tab_count = int(response.result.data.get("tab_count", 0)
                            if response.result.data else 0)
            kind = rendered_expect.get("kind")
            if kind == "navigation":
                target = str(rendered_expect.get("url_contains") or "")
                return bool(target) and target in url
            if kind == "tab_opened":
                return tab_count >= 2
            if kind == "element_detached":
                elements = response.result.data.get("elements", []) \
                    if response.result.data else []
                return not any(step_def.target.matches(e) for e in elements) \
                    if step_def.target else True
            return False
        except Exception:  # noqa: BLE001 - fail closed
            return False

    def _confirmation_dispatch_outcome(self, confirmation_id: str) -> str | None:
        with transaction(self.session_factory) as session:
            entries = self.audit_service.list(
                session, confirmation_id=confirmation_id, limit=50)
        terminal = [
            e.outcome for e in entries
            if e.outcome in ("EXECUTED", "FAILED", "REJECTED",
                             "DENIED_BY_USER", "DENIED_BY_POLICY")
        ]
        return terminal[-1] if terminal else None

    def _step_def_for(self, run: WorkflowRun, idx: int) -> WorkflowStep | None:
        definition = self._definition_for_run(run)
        if definition is None or not (0 <= idx < len(definition.steps)):
            return None
        return definition.steps[idx]

    # -- helpers ---------------------------------------------------------------
    def _mark_step(self, step_id: str, status: str, *,
                   receipt: Any = None, error_code: str | None = None,
                   error_message: str | None = None) -> WorkflowStepRun:
        with transaction(self.session_factory) as session:
            row = self.repo.get_step(session, step_id)
            if row is None:
                raise WorkflowServiceError("step row missing")
            row.status = status
            row.result_receipt = receipt
            row.error_code = error_code
            row.error_message = error_message
            row.finished_at = _utcnow()
            self.repo.update_step(session, row)
            return row

    def _set_current(self, run: WorkflowRun, idx: int) -> None:
        run.current_step = idx
        run.updated_at = _utcnow()
        self._persist_run(run)

    def _persist_run(self, run: WorkflowRun) -> None:
        with transaction(self.session_factory) as session:
            self.repo.update_run(session, run)

    def _set_run_failed(self, run: WorkflowRun, message: str) -> None:
        run.status = STATUS_FAILED
        run.error = message
        run.finished_at = _utcnow()
        run.updated_at = _utcnow()
        self._persist_run(run)
        self._release_governance(run)

    def _set_run_budget_failed(self, run: WorkflowRun, message: str) -> None:
        run.status = STATUS_FAILED
        run.error = message
        run.governance_code = "BUDGET_EXCEEDED"
        run.finished_at = _utcnow()
        run.updated_at = _utcnow()
        self._persist_run(run)
        self._release_governance(run)

    def _release_governance(self, run: WorkflowRun) -> None:
        if self.governance_service is not None:
            try:
                self.governance_service.release_start(
                    actor_id=run.actor_id, workflow_name=run.workflow_name)
            except Exception:  # release is best-effort; a leak is recorded but
                # must not crash a run that is already terminal.
                logger.debug("governance release failed for run %s", run.id,
                             exc_info=True)

    def _load_owned(self, run_id: str, actor_id: str) -> WorkflowRun:
        with transaction(self.session_factory) as session:
            run = self.repo.get_run(session, run_id)
        if run is None:
            raise WorkflowNotFound(f"workflow run {run_id!r} not found")
        if run.actor_id != actor_id:
            raise WorkflowStateError("workflow run belongs to another actor")
        return run

    def _load_run_any(self, run_id: str) -> WorkflowRun:
        with transaction(self.session_factory) as session:
            run = self.repo.get_run(session, run_id)
        if run is None:
            raise WorkflowNotFound(f"workflow run {run_id!r} not found")
        return run

    def _load_run(self, run_id: str, ctx: ExecutionContext, *,
                  admin: bool = False) -> WorkflowRun:
        run = self._load_run_any(run_id)
        if not admin and run.actor_id != ctx.actor_id:
            raise WorkflowStateError("workflow run belongs to another actor")
        return run

    @staticmethod
    def _sanitize_receipt(data: Any) -> Any:
        """Strip refs and secrets from a step result receipt, bounded and JSON-safe."""
        if not isinstance(data, dict):
            return {}
        safe: dict[str, Any] = {}
        for key, value in data.items():
            if key in ("element_ref", "snapshot_id") or "ref" == key.lower():
                continue
            if _is_secret_key(key):
                continue
            if isinstance(value, dict):
                value = WorkflowService._sanitize_receipt(value)
            elif isinstance(value, list):
                value = [
                    WorkflowService._sanitize_receipt(item)
                    if isinstance(item, dict) else item
                    for item in value
                ]
            safe[key] = value
        return safe


def _ctx_for_run(run: WorkflowRun) -> ExecutionContext:
    return ExecutionContext(actor_id=run.actor_id, execution_scope=run.execution_scope)


def _is_secret_key(key: str) -> bool:
    from era.security.redaction import is_secret_key as _isk
    return _isk(key)


def _utcnow() -> str:
    from era.core.util import utcnow_iso
    return utcnow_iso()


__all__ = [
    "STATUS_AMBIGUOUS",
    "STATUS_CANCELLED",
    "STATUS_COMPLETED",
    "STATUS_FAILED",
    "STATUS_PENDING",
    "STATUS_RUNNING",
    "STATUS_WAITING",
    "WorkflowAlreadyTerminal",
    "WorkflowNotAllowed",
    "WorkflowNotFound",
    "WorkflowService",
    "WorkflowServiceError",
    "WorkflowStateError",
]
