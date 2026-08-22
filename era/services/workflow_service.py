"""Phase 4C — the durable, resumable, exactly-once workflow engine.

The engine is an *ExecutionService-only* orchestrator: every inner step is
dispatched through :class:`era.services.execution_service.ExecutionService`,
so each step still passes the permission engine, confirmation, audit and
reliability gates independently. The engine itself never calls a provider
directly and never invents a browser reference — targets are re-acquired by
re-inspecting the current page at run time.

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

import time
import uuid
from collections.abc import Callable
from typing import Any

from era.core.action import Action
from era.core.context import ExecutionContext
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

#: Non-retryable browser mutations (mirrors the provider declaration). The
#: engine never retries these — the ExecutionService already declines retries
#: via the provider's ``non_retryable_action_types``.
_NON_RETRYABLE = frozenset({
    "browser.click", "browser.fill", "browser.submit",
    "browser.download", "browser.upload",
})


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

    # -- public API ------------------------------------------------------------
    def start(self, *, definition: WorkflowDefinition | str,
              params: dict[str, Any], ctx: ExecutionContext, run_token: str,
              domain_allowed: Callable[[str], bool]) -> WorkflowRun:
        """Register-or-resolve a definition and begin a run.

        ``run_token`` is the exactly-once key (unique per actor): starting a run
        with a token that already produced a run returns the existing run and
        never re-executes anything.
        """
        if not isinstance(domain_allowed, Callable):
            raise WorkflowServiceError("domain_allowed is required")
        resolved = self._resolve_definition(definition)
        # Workflow-level RBAC gate: the actor must be allowed to run the
        # workflow action and every inner step domain.
        if not domain_allowed("browser.workflow_run"):
            raise WorkflowNotAllowed("role is not allowed to run browser workflows")
        for step in resolved.steps:
            if not domain_allowed(step.action):
                raise WorkflowNotAllowed(
                    f"role is not allowed to run workflow step {step.action!r}")

        run_token = (run_token or "").strip() or uuid.uuid4().hex
        with transaction(self.session_factory) as session:
            existing = self.repo.get_run_by_token(session, ctx.actor_id, run_token)
            if existing is not None:
                return existing  # exactly-once: never start the same run twice

            now = _utcnow()
            run = WorkflowRun(
                id=uuid.uuid4().hex,
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
            )
            # Isolate the run's own ephemeral browser context and preserve the
            # original scope across approval + resume (Phase 4A.1 design).
            run.execution_scope = ctx.execution_scope or f"workflow:{run.id}"
            self.repo.create_run(session, run)
            run_id = run.id
            for idx, step in enumerate(resolved.steps):
                self.repo.create_step(session, WorkflowStepRun(
                    id=uuid.uuid4().hex,
                    run_id=run_id,
                    step_id=step.id,
                    step_index=idx,
                    action_type=step.action,
                    params_redacted=redact(step.params),
                    status=STATUS_PENDING,
                    attempt=0,
                ))

        dispatch_ctx = ctx.model_copy(
            update={"execution_scope": run.execution_scope})
        return self._advance(run_id, dispatch_ctx, domain_allowed)

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
            run.updated_at = _utcnow()
            self.repo.update_run(session, run)
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
                run.updated_at = _utcnow()
                self.repo.update_run(session, run)
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

    # -- definition handling ---------------------------------------------------
    def _resolve_definition(self, definition: WorkflowDefinition | str) -> WorkflowDefinition:
        if isinstance(definition, str):
            resolved = self.workflow_catalog.get(definition)
            if resolved is None:
                raise WorkflowServiceError(f"unknown workflow: {definition!r}")
            return resolved
        if isinstance(definition, WorkflowDefinition):
            validate_workflow_definition(definition, self.catalog, max_steps=self.max_steps)
            # Register the validated inline definition so both the initial run
            # and any resume/revalidation can resolve it by name.
            existing = self.workflow_catalog.get(definition.name)
            if existing is None:
                self.workflow_catalog.register(definition, max_steps=self.max_steps)
            return definition
        raise WorkflowServiceError("workflow must be a registered name or definition")

    # -- engine ----------------------------------------------------------------
    def _advance(self, run_id: str, ctx: ExecutionContext,
                 domain_allowed: Callable[[str], bool]) -> WorkflowRun:
        run = self._load_owned(run_id, ctx.actor_id)
        definition = self.workflow_catalog.get(run.workflow_name)
        if definition is None:
            self._set_run_failed(run, "workflow is no longer registered")
            return run
        if self.workflow_catalog.checksum(definition) != run.definition_checksum:
            self._set_run_failed(
                run, "workflow definition changed since the run started (checksum)")
            return run

        with transaction(self.session_factory) as session:
            step_rows = {s.step_index: s for s in self.repo.list_steps(session, run_id)}

        deadline = time.monotonic() + self.max_wallclock_seconds
        idx = run.current_step
        steps = definition.steps

        while idx < len(steps):
            if time.monotonic() > deadline:
                self._set_run_failed(run, "workflow wall-clock budget exceeded")
                return run
            if run.status == STATUS_CANCELLED:
                return run
            step_def = steps[idx]
            if not domain_allowed(step_def.action):
                self._set_run_failed(
                    run, f"step {step_def.action!r} is not allowed for this role")
                return run

            row = step_rows.get(idx)
            if row is not None and row.status in (STATUS_COMPLETED, "skipped"):
                idx += 1
                self._set_current(run, idx)
                continue
            if row is not None and row.status == STATUS_WAITING:
                outcome = self._handle_waiting_step(run, row, ctx)
                if outcome == "next":
                    idx += 1
                    self._set_current(run, idx)
                    continue
                if outcome == "still_waiting":
                    return run
                if outcome == "denied_skip":
                    idx += 1
                    self._set_current(run, idx)
                    continue
                if outcome == "denied_stop":
                    self._set_run_failed(run, "a required confirmation was denied")
                    return run
                if outcome == "ambiguous":
                    return run
                # "failed" -> _handle_waiting_step already set a specific error.
                return run

            self._set_current(run, idx)
            run = self._load_owned(run_id, ctx.actor_id)
            run.status = STATUS_RUNNING
            self._persist_run(run)

            row = self._execute_step(run, step_def, idx, ctx)
            row_status = row.status
            if row_status == STATUS_COMPLETED:
                idx += 1
                self._set_current(run, idx)
                continue
            if row_status == "skipped":
                idx += 1
                self._set_current(run, idx)
                continue
            if row_status == STATUS_WAITING:
                run = self._load_owned(run_id, ctx.actor_id)
                run.status = STATUS_WAITING
                run.updated_at = _utcnow()
                self._persist_run(run)
                return run
            if row_status == STATUS_AMBIGUOUS:
                run = self._load_owned(run_id, ctx.actor_id)
                run.status = STATUS_AMBIGUOUS
                run.error = "a step has an unknown outcome; operator resolution required"
                run.updated_at = _utcnow()
                self._persist_run(run)
                return run
            # failed
            run = self._load_owned(run_id, ctx.actor_id)
            run.status = STATUS_FAILED
            run.error = row.error_message or "workflow step failed"
            run.updated_at = _utcnow()
            self._persist_run(run)
            return run

        run = self._load_owned(run_id, ctx.actor_id)
        run.status = STATUS_COMPLETED
        run.current_step = len(steps)
        run.error = None
        run.updated_at = _utcnow()
        self._persist_run(run)
        return run

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
            self.repo.update_step(session, existing)
            step_id = existing.id

        try:
            rendered = render_workflow_params(step_def, run.run_params or {})
            if step_def.target is not None:
                rendered["element_ref"] = self._acquire_target(run, step_def, ctx)
            if step_def.expect is not None:
                rendered["expect"] = render_step_expect(step_def, run.run_params or {})
            action = Action(action_type=step_def.action, params=rendered)

            # Non-retryable steps are dispatched once (ExecutionService already
            # disables transport retries for them).
            response = self.execution_service.request(action, ctx)

            if response.status == "executed":
                return self._mark_step(
                    step_id, STATUS_COMPLETED,
                    receipt=self._sanitize_receipt(response.result.data
                                                   if response.result else None),
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
                                   error_message=f"workflow engine error: {type(exc).__name__}")

    def _acquire_target(self, run: WorkflowRun, step_def: WorkflowStep,
                        ctx: ExecutionContext) -> str:
        """Re-inspect the current page and resolve the descriptor to a fresh ref."""
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
        """Reconcile a step awaiting confirmation against its confirmation state."""
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
            # Approved and dispatched once by the existing approval flow. Do NOT
            # re-run. First, consult the audit log for the actual dispatch
            # outcome (a drift-failed or rejected dispatch must stop the run,
            # never be treated as a success). Then revalidate any declared
            # post-condition fail-closed.
            outcome = self._confirmation_dispatch_outcome(cid)
            if outcome in ("FAILED", "REJECTED", "DENIED_BY_USER", "DENIED_BY_POLICY"):
                self._set_run_failed(
                    run, f"approved step dispatch did not succeed (outcome={outcome})")
                return "failed"
            if outcome is None or outcome not in ("EXECUTED", "AUTHORIZED"):
                # No dispatch outcome was recorded — treat as unknown and stop.
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
        """Re-check a confirmed step's declared post-condition against the page."""
        step_def = self._step_def_for(run, row.step_index)
        if step_def is None or step_def.expect is None:
            return True  # nothing declared to revalidate
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
                # Re-inspect and require the target element to be gone.
                elements = response.result.data.get("elements", []) \
                    if response.result.data else []
                return not any(step_def.target.matches(e) for e in elements) \
                    if step_def.target else True
            return False
        except Exception:  # noqa: BLE001 - fail closed
            return False

    def _confirmation_dispatch_outcome(self, confirmation_id: str) -> str | None:
        """Return the terminal dispatch outcome for a confirmation, or ``None``."""
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
        definition = self.workflow_catalog.get(run.workflow_name)
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
        run.updated_at = _utcnow()
        self._persist_run(run)

    def _load_owned(self, run_id: str, actor_id: str) -> WorkflowRun:
        with transaction(self.session_factory) as session:
            run = self.repo.get_run(session, run_id)
        if run is None:
            raise WorkflowNotFound(f"workflow run {run_id!r} not found")
        if run.actor_id != actor_id:
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
