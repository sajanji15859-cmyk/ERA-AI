"""Phase 4D — workflow operations & governance service.

This service is the operations layer around the Phase 4C durable engine:

* **Scheduling** reuses the Phase 3H cron/interval semantics (through
  ``era.core.cron.compute_next_run``) but stores workflow-specific redacted
  params and an ``actor_role`` so a due schedule starts through the *same*
  WorkflowService gates as an interactive run (never a confirmation bypass).
* **Templates** publish immutable, validated definitions with an explicit
  ``params_schema`` and version; instantiation validates the caller params and
  the run pins the exact template+version+checksum it started with.
* **Governance** applies deterministic, DB-backed admission and budget caps
  (concurrency per actor/workflow, rolling per-window rate, step/cost budget)
  before a run starts and re-checks while it runs. A cap breach starts or fails
  the run with a machine-readable ``governance_code``.
* **Operator review** exposes awaiting runs + run timelines and admin-scoped
  cross-actor resolution/approval with an audit trail and sanitized receipts.
* **Observability** provides bounded, actor-scoped filter/aggregation queries.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from era.core.context import ExecutionContext
from era.core.cron import compute_next_run
from era.core.enums import RiskLevel
from era.db import transaction
from era.models.workflow import (
    STATUS_AMBIGUOUS,
    STATUS_WAITING,
    WorkflowRun,
    WorkflowStepRun,
)
from era.models.workflow_ops import (
    WorkflowGovernanceCounter,
    WorkflowSchedule,
    WorkflowTemplate,
)
from era.repositories.base import (
    WorkflowGovernanceRepo,
    WorkflowRunRepo,
    WorkflowScheduleRepo,
    WorkflowTemplateRepo,
)
from era.security.hashing import canonical_json, sha256_hex
from era.security.rbac import role_domain_allowed
from era.security.validation import (
    MAX_NAME_LEN,
    validate_param_schema,
    validate_params,
)
from era.workflows.catalog import WorkflowCatalog
from era.workflows.definition import (
    WorkflowDefinition,
    redact_run_params,
)

logger = logging.getLogger(__name__)

#: Statuses a run may be awaiting operator attention in.
AWAITING_STATUSES = (STATUS_WAITING, STATUS_AMBIGUOUS)


class WorkflowOpsError(Exception):
    """Fail-closed operations-layer error surfaced to the API."""


class WorkflowScheduleError(WorkflowOpsError):
    """Schedule registration/update failed."""


class WorkflowTemplateError(WorkflowOpsError):
    """Template publish/instantiate failed."""


class WorkflowGovernanceError(WorkflowOpsError):
    """A deterministic governance admission/budget cap was exceeded."""

    def __init__(self, message: str, *, code: str = "BUDGET_EXCEEDED"):
        super().__init__(message)
        self.code = code


class WorkflowOperatorError(WorkflowOpsError):
    """Operator review action failed."""


def _utcnow() -> str:
    from era.core.util import utcnow_iso
    return utcnow_iso()


def _hash(name: str) -> str:
    return sha256_hex(canonical_json({"name": name}))


class WorkflowGovernanceService:
    """Deterministic admission/quota enforcement (DB-backed caps)."""

    def __init__(
        self,
        *,
        session_factory,
        repo: WorkflowGovernanceRepo,
        settings,
    ):
        self.session_factory = session_factory
        self.repo = repo
        self.settings = settings

    # -- admission -----------------------------------------------------------
    def claim_start(self, *, actor_id: str, workflow_name: str) -> None:
        """Claim admission slots for a new run; raises on any cap breach.

        The claim is atomic within a single DB transaction: if any of the three
        caps is exceeded the transaction is rolled back, so a failing run never
        partially consumes a counter.
        """
        max_actor = int(getattr(self.settings, "workflow_max_concurrent_per_actor", 2))
        max_wf = int(getattr(self.settings, "workflow_max_concurrent_per_workflow", 2))
        max_window = int(getattr(self.settings, "workflow_max_runs_per_window", 10))
        window = int(getattr(self.settings, "workflow_rate_window_seconds", 3600))
        now = datetime.now(UTC)
        window_start = int(now.timestamp() // max(window, 1)) * max(window, 1)

        with transaction(self.session_factory) as session:
            _count, actor_ok = self.repo.bump(
                session, kind="concurrency.actor", scope=actor_id, cap=max_actor)
            if not actor_ok:
                raise WorkflowGovernanceError(
                    "concurrent-run cap exceeded for actor",
                    code="CONCURRENCY_EXCEEDED")
            _count, wf_ok = self.repo.bump(
                session, kind="concurrency.workflow", scope=workflow_name,
                cap=max_wf)
            if not wf_ok:
                raise WorkflowGovernanceError(
                    "concurrent-run cap exceeded for workflow",
                    code="CONCURRENCY_EXCEEDED")
            _count, rate_ok = self.repo.bump(
                session, kind="rate",
                scope=f"{workflow_name}:{window_start}", cap=max_window)
            if not rate_ok:
                raise WorkflowGovernanceError(
                    "per-window run rate exceeded for workflow",
                    code="RATE_LIMIT_EXCEEDED")

    def release_start(self, *, actor_id: str, workflow_name: str) -> None:
        with transaction(self.session_factory) as session:
            self.repo.bump(session, kind="concurrency.actor",
                           scope=actor_id, delta=-1)
            self.repo.bump(session, kind="concurrency.workflow",
                           scope=workflow_name, delta=-1)

    def claim_step_budget(self, *, run_id: str) -> None:
        """Claim one step/cost unit for a run; raises BUDGET_EXCEEDED."""
        max_steps = int(getattr(self.settings, "workflow_max_steps_per_run", 120))
        max_cost = int(getattr(self.settings, "workflow_max_cost_units", 1000))
        with transaction(self.session_factory) as session:
            count, steps_ok = self.repo.bump(
                session, kind="steps", scope=f"run:{run_id}", cap=max_steps)
            if not steps_ok or count > max_steps:
                raise WorkflowGovernanceError(
                    "step budget exceeded for run", code="BUDGET_EXCEEDED")
            _count, cost_ok = self.repo.bump(
                session, kind="cost", scope=f"run:{run_id}", cap=max_cost)
            if not cost_ok:
                raise WorkflowGovernanceError(
                    "cost/quota budget exceeded for run", code="BUDGET_EXCEEDED")


class WorkflowScheduleService:
    """Workflow schedule registration and due-run dispatch (Phase 4D P1)."""

    def __init__(
        self,
        *,
        session_factory,
        repo: WorkflowScheduleRepo,
        workflow_service,
        workflow_catalog: WorkflowCatalog,
        settings,
        template_service=None,
    ):
        self.session_factory = session_factory
        self.repo = repo
        self.workflow_service = workflow_service
        self.workflow_catalog = workflow_catalog
        self.template_service = template_service
        self.settings = settings

    # -- CRUD ----------------------------------------------------------------
    def create(
        self,
        *,
        actor_id: str,
        actor_role: str | None,
        name: str,
        workflow_name: str,
        params: dict[str, Any],
        cron_expr: str | None = None,
        interval_seconds: int | None = None,
        enabled: bool = True,
        workflow_version: int | None = None,
        domain_allowed: Callable[[str], bool] | None = None,
    ) -> WorkflowSchedule:
        if not (0 < len(name) <= MAX_NAME_LEN):
            raise WorkflowScheduleError("schedule name must be 1-128 chars")
        definition = self._resolve_workflow(workflow_name)
        if workflow_version is not None and definition.version != workflow_version:
            raise WorkflowScheduleError(
                f"workflow {workflow_name!r} is not at version {workflow_version}")
        # Per-step RBAC gate at registration time: a role that cannot run an
        # inner step cannot schedule the workflow either.
        if domain_allowed is not None:
            for step in definition.steps:
                if not domain_allowed(step.action):
                    raise WorkflowScheduleError(
                        f"role is not allowed to run workflow step {step.action!r}")
        now_dt = datetime.now(UTC)
        next_dt = compute_next_run(
            cron_expr=cron_expr, interval_seconds=interval_seconds,
            from_dt=now_dt) if enabled else None

        schedule = WorkflowSchedule(
            id=uuid.uuid4().hex,
            actor_id=actor_id,
            actor_role=actor_role,
            name=name,
            workflow_name=workflow_name,
            workflow_version=definition.version,
            params_redacted=redact_run_params(params),
            cron_expr=cron_expr,
            interval_seconds=interval_seconds,
            enabled=enabled,
            next_run_at=next_dt.isoformat() if next_dt else None,
            created_at=_utcnow(),
            updated_at=_utcnow(),
        )
        with transaction(self.session_factory) as session:
            existing = self.repo.get_by_name(session, actor_id, name)
            if existing is not None:
                raise WorkflowScheduleError("schedule name already exists for actor")
            return self.repo.create(session, schedule)

    def _resolve_workflow(self, workflow_name: str) -> WorkflowDefinition:
        definition = self.workflow_catalog.get(workflow_name)
        if definition is None and self.template_service is not None:
            try:
                definition = self.template_service.instantiate(workflow_name, {})
            except WorkflowTemplateError:
                definition = None
        if definition is None:
            raise WorkflowScheduleError(f"unknown workflow: {workflow_name!r}")
        return definition

    def get(self, schedule_id: str, actor_id: str) -> WorkflowSchedule | None:
        with transaction(self.session_factory) as session:
            row = self.repo.get(session, schedule_id)
            if row is None or row.actor_id != actor_id:
                return None
            return row

    def list(self, actor_id: str, *, limit: int = 50) -> list[WorkflowSchedule]:
        with transaction(self.session_factory) as session:
            return self.repo.list_by_actor(session, actor_id, limit=limit)

    def update(
        self,
        schedule_id: str,
        actor_id: str,
        *,
        name: str | None = None,
        params: dict[str, Any] | None = None,
        cron_expr: str | None = None,
        interval_seconds: int | None = None,
        workflow_version: int | None = None,
        enabled: bool | None = None,
    ) -> WorkflowSchedule | None:
        with transaction(self.session_factory) as session:
            row = self.repo.get(session, schedule_id)
            if row is None or row.actor_id != actor_id:
                return None
            if name is not None:
                if not (0 < len(name) <= MAX_NAME_LEN):
                    raise WorkflowScheduleError("schedule name must be 1-128 chars")
                row.name = name
            if params is not None:
                row.params_redacted = redact_run_params(params)
            if cron_expr is not None:
                row.cron_expr = cron_expr or None
            if interval_seconds is not None:
                row.interval_seconds = interval_seconds if interval_seconds > 0 else None
            if workflow_version is not None:
                row.workflow_version = workflow_version
            if enabled is not None:
                row.enabled = enabled
            if enabled is not None or cron_expr is not None or interval_seconds is not None:
                if row.enabled and (row.cron_expr or row.interval_seconds):
                    next_dt = compute_next_run(
                        cron_expr=row.cron_expr,
                        interval_seconds=row.interval_seconds,
                        from_dt=datetime.now(UTC))
                    row.next_run_at = next_dt.isoformat()
                else:
                    row.next_run_at = None
            row.updated_at = _utcnow()
            self.repo.update(session, row)
            return row

    def delete(self, schedule_id: str, actor_id: str) -> bool:
        with transaction(self.session_factory) as session:
            row = self.repo.get(session, schedule_id)
            if row is None or row.actor_id != actor_id:
                return False
            self.repo.delete(session, row)
            return True

    # -- due dispatch --------------------------------------------------------
    def tick(self, now_iso: str | None = None) -> list[str]:
        """Start every due workflow schedule (deterministic, exactly-once).

        The run token is derived from ``(actor, schedule_id, due_time)`` so the
        Phase 4C exactly-once guarantee holds across scheduler retries/crashes.
        """
        current_iso = now_iso or _utcnow()
        now_dt = datetime.fromisoformat(current_iso)
        if now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=UTC)

        due: list[WorkflowSchedule] = []
        with transaction(self.session_factory) as session:
            due = self.repo.list_due(session, current_iso, limit=50)

        run_ids: list[str] = []
        for schedule in due:
            due_stamp = schedule.next_run_at or current_iso
            run_token = self._run_token(schedule, due_stamp)
            ctx = ExecutionContext(actor_id=schedule.actor_id)

            def guard(action_type: str, _role=schedule.actor_role) -> bool:
                spec = self.workflow_service.catalog.get(action_type)
                if spec is None or spec.risk_level is RiskLevel.FORBIDDEN:
                    return False
                return role_domain_allowed(_role, spec.capability_domain)

            # Crash/double-due dedup: if this deterministic token already
            # produced a run (e.g. the previous tick crashed before advancing
            # next_run_at), advance the schedule without starting it again.
            with transaction(self.session_factory) as session:
                existing = self.workflow_service.repo.get_run_by_token(
                    session, schedule.actor_id, run_token)
            if existing is not None:
                with transaction(self.session_factory) as session:
                    refreshed = self.repo.get(session, schedule.id)
                    if refreshed is not None:
                        try:
                            next_dt = compute_next_run(
                                cron_expr=refreshed.cron_expr,
                                interval_seconds=refreshed.interval_seconds,
                                from_dt=now_dt)
                            next_iso = next_dt.isoformat()
                        except Exception:  # noqa: BLE001
                            next_iso = None
                        refreshed.last_run_at = current_iso
                        refreshed.last_run_id = existing.id
                        refreshed.next_run_at = next_iso
                        refreshed.updated_at = _utcnow()
                        self.repo.update(session, refreshed)
                continue

            try:
                run = self.workflow_service.start(
                    definition=schedule.workflow_name,
                    params=dict(schedule.params_redacted or {}),
                    ctx=ctx,
                    run_token=run_token,
                    domain_allowed=guard,
                    scheduled=True,
                    schedule_id=schedule.id,
                )
            except WorkflowOpsError:
                # A governed/schedule error is surfaced on the next tick without
                # marking the schedule disabled; the exact-once token prevents a
                # repeated *successful* dispatch.
                continue
            run_ids.append(run.id)
            try:
                next_dt = compute_next_run(
                    cron_expr=schedule.cron_expr,
                    interval_seconds=schedule.interval_seconds,
                    from_dt=now_dt)
                next_iso = next_dt.isoformat()
            except Exception:  # noqa: BLE001 - fail closed to no next run
                next_iso = None
            with transaction(self.session_factory) as session:
                refreshed = self.repo.get(session, schedule.id)
                if refreshed is not None:
                    refreshed.last_run_at = current_iso
                    refreshed.last_run_id = run.id
                    refreshed.next_run_at = next_iso
                    refreshed.updated_at = _utcnow()
                    self.repo.update(session, refreshed)
        return run_ids

    @staticmethod
    def _run_token(schedule: WorkflowSchedule, due_stamp: str) -> str:
        material = f"{schedule.actor_id}:{schedule.id}:{due_stamp}"
        return "sched:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


class WorkflowTemplateService:
    """Immutable workflow template versioning (Phase 4D P4)."""

    def __init__(
        self,
        *,
        session_factory,
        repo: WorkflowTemplateRepo,
        workflow_catalog: WorkflowCatalog,
        settings,
    ):
        self.session_factory = session_factory
        self.repo = repo
        self.workflow_catalog = workflow_catalog
        self.settings = settings

    def publish(self, definition: WorkflowDefinition, *, created_by: str) -> WorkflowTemplate:
        """Validate and publish a new immutable version of a template.

        Publishing a definition identical to the latest published version is
        idempotent (returns the existing row). A genuinely different definition
        for the same name creates the next immutable version. The name-keyed
        catalog is intentionally not overwritten: a later version can exist in
        the template store without silently changing an in-flight run that
        pinned an earlier version.
        """
        with transaction(self.session_factory) as session:
            latest = self.repo.get_latest(session, definition.name)
            checksum = self.workflow_catalog.checksum(definition)
            if latest is not None and latest.checksum == checksum:
                return latest
            version = (latest.version + 1) if latest is not None else 1
            template = WorkflowTemplate(
                id=uuid.uuid4().hex,
                name=definition.name,
                version=version,
                # Definitions already forbid plaintext secrets (fills use opaque
                # vault refs), so the exact JSON is a safe immutable source of
                # truth for version-pinned runs.
                definition_redacted=definition.model_dump(mode="json"),
                params_schema=dict(definition.params_schema or {}),
                checksum=checksum,
                status="published",
                created_by=created_by,
                created_at=_utcnow(),
                published_at=_utcnow(),
            )
            return self.repo.create(session, template)

    def get_latest(self, name: str) -> WorkflowTemplate | None:
        with transaction(self.session_factory) as session:
            return self.repo.get_latest(session, name)

    def get(self, name: str, version: int) -> WorkflowTemplate | None:
        with transaction(self.session_factory) as session:
            return self.repo.get(session, name, version)

    def list(self, *, limit: int = 100) -> list[WorkflowTemplate]:
        with transaction(self.session_factory) as session:
            return self.repo.list(session, limit=limit)

    def instantiate(self, name: str, params: dict[str, Any], *,
                    version: int | None = None) -> WorkflowDefinition:
        """Return the exact immutable template definition for a version."""
        template = None
        if version is not None:
            template = self.get(name, version)
            if template is None:
                raise WorkflowTemplateError(f"unknown template version: {name}@{version}")
        else:
            template = self.get_latest(name)
            if template is None:
                raise WorkflowTemplateError(f"unknown template: {name!r}")
        definition = WorkflowDefinition.model_validate(
            dict(template.definition_redacted or {}))
        # Instantiation validates the caller params against the template schema.
        validate_params(params)
        validate_param_schema(params, template.params_schema or {})
        if self.workflow_catalog.checksum(definition) != template.checksum:
            raise WorkflowTemplateError(
                "template definition drifted from published checksum (fail closed)")
        # Pin the returned definition to the exact published version.
        definition.version = template.version
        return definition

    @staticmethod
    def checksum(definition: WorkflowDefinition) -> str:
        return WorkflowCatalog.checksum(definition)


class WorkflowReviewService:
    """Operator review + observability read surface (Phase 4D P5/P6)."""

    def __init__(
        self,
        *,
        session_factory,
        workflow_repo: WorkflowRunRepo,
    ):
        self.session_factory = session_factory
        self.repo = workflow_repo

    def list_awaiting(self, *, limit: int = 50) -> list[WorkflowRun]:
        with transaction(self.session_factory) as session:
            return self.repo.list_awaiting_runs(
                session, statuses=list(AWAITING_STATUSES), limit=limit)

    def list_runs(
        self,
        *,
        ctx: ExecutionContext | None = None,
        status: str | None = None,
        workflow_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
        admin: bool = False,
    ) -> list[WorkflowRun]:
        actor_id = None if admin else (ctx.actor_id if ctx else None)
        limit = min(max(int(limit), 1), 200)
        offset = max(int(offset), 0)
        with transaction(self.session_factory) as session:
            return self.repo.list_runs_filtered(
                session, actor_id=actor_id, status=status,
                workflow_name=workflow_name, limit=limit, offset=offset)

    def aggregate(
        self,
        *,
        ctx: ExecutionContext | None = None,
        workflow_name: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
        admin: bool = False,
    ) -> dict[str, Any]:
        actor_id = None if admin else (ctx.actor_id if ctx else None)
        statuses = ["completed", "failed", "ambiguous", "waiting_for_user",
                    "cancelled", "running", "pending"]
        result: dict[str, Any] = {"workflow": workflow_name, "total": 0,
                                  "by_status": {}, "durations": {}}
        for status in statuses:
            with transaction(self.session_factory) as session:
                count = self.repo.count_runs_filtered(
                    session, actor_id=actor_id, status=status,
                    workflow_name=workflow_name, start_at=start_at, end_at=end_at)
            result["by_status"][status] = count
            result["total"] += count
        # Bounded, offline-friendly duration summary from the current window.
        durations: list[float] = []
        with transaction(self.session_factory) as session:
            runs = self.repo.list_runs_filtered(
                session, actor_id=actor_id, status="completed",
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
        else:
            result["durations"] = {"count": 0, "mean": 0.0, "p50": 0.0,
                                   "p95": 0.0, "p99": 0.0}
        return result

    def timeline(self, run: WorkflowRun, steps: list[WorkflowStepRun]) -> list[dict[str, Any]]:
        """Ordered, bounded run timeline (no secrets / raw refs / page content)."""
        events: list[dict[str, Any]] = []
        for step in (steps or []):
            status = step.status
            if step.started_at:
                events.append({
                    "at": step.started_at, "kind": "step_started",
                    "step_id": step.step_id, "status": status,
                })
            if status == "waiting_for_user":
                events.append({
                    "at": step.finished_at or step.started_at,
                    "kind": "step_paused", "step_id": step.step_id,
                    "confirmation_id": step.confirmation_id,
                })
            if status == "ambiguous":
                events.append({
                    "at": step.finished_at or step.started_at,
                    "kind": "step_ambiguous", "step_id": step.step_id,
                    "error_code": step.error_code,
                })
            if status in ("completed", "skipped", "failed"):
                events.append({
                    "at": step.finished_at or step.started_at,
                    "kind": "step_finished", "step_id": step.step_id,
                    "status": status,
                })
        events.sort(key=lambda e: e.get("at") or "")
        return events[:200]


#: Shared static helper used by templates.
def rstrip_json(value: Any) -> Any:
    return value


__all__ = [
    "AWAITING_STATUSES",
    "WorkflowGovernanceCounter",
    "WorkflowGovernanceError",
    "WorkflowGovernanceService",
    "WorkflowOperatorError",
    "WorkflowOpsError",
    "WorkflowReviewService",
    "WorkflowSchedule",
    "WorkflowScheduleError",
    "WorkflowScheduleService",
    "WorkflowTemplate",
    "WorkflowTemplateError",
    "WorkflowTemplateService",
]
