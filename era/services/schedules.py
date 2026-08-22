"""ScheduleService — recurring job management and in-process scheduler (Phase 3H).

Provides durable schedule management and an in-process scheduler thread that
periodically checks for due schedules and queues them via
:class:`~era.services.jobs.JobService`.

Invariants:
* Scheduled actions execute through the exact SAME
  :class:`~era.services.execution_service.ExecutionService` gate as interactive
  executions (permission engine, confirmation requirements, audit logging,
  circuit breaker, retry).
* Schedulers are actor-scoped.
* Idempotent submission: ``sched:<schedule_id>:<due_next_run_at>`` key prevents
  duplicate execution across crashes or clock adjustments.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import UTC, datetime
from typing import Any

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.cron import compute_next_run
from era.core.enums import RiskLevel
from era.core.tool_registry import ActionCatalog
from era.core.util import utcnow_iso
from era.db import transaction
from era.models.schedule import Schedule
from era.repositories.base import ScheduleRepo
from era.security.exceptions import AuthorizationError
from era.security.redaction import redact
from era.services.jobs import JobService

logger = logging.getLogger(__name__)


class ScheduleService:
    def __init__(self, *, session_factory, schedule_repo: ScheduleRepo,
                 job_service: JobService, catalog: ActionCatalog, settings):
        self.session_factory = session_factory
        self.repo = schedule_repo
        self.job_service = job_service
        self.catalog = catalog
        self.settings = settings
        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None

    # -- lifecycle ------------------------------------------------------------
    def start(self, interval_seconds: float = 1.0) -> None:
        """Start the in-process background scheduler worker."""
        if self._worker_thread is not None and self._worker_thread.is_alive():
            return
        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._run_loop,
            args=(interval_seconds,),
            name="era-scheduler",
            daemon=True,
        )
        self._worker_thread.start()

    def shutdown(self) -> None:
        """Stop the in-process background scheduler worker."""
        self._stop_event.set()
        if self._worker_thread is not None and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
            self._worker_thread = None

    def _run_loop(self, interval_seconds: float) -> None:
        while not self._stop_event.is_set():
            try:
                self.tick()
            except Exception:
                logger.exception("error in scheduler loop tick")
            self._stop_event.wait(timeout=interval_seconds)

    # -- schedule CRUD --------------------------------------------------------
    def create(self, actor_id: str, name: str, action_type: str,
               action_params: dict[str, Any] | None = None,
               cron_expr: str | None = None,
               interval_seconds: int | None = None,
               enabled: bool = True) -> Schedule:
        spec = self.catalog.get(action_type)
        if spec is None or spec.risk_level is RiskLevel.FORBIDDEN:
            raise AuthorizationError(f"action_type {action_type!r} cannot be scheduled")

        secret_fields = spec.secret_fields if spec else frozenset()
        clean_params = redact(action_params or {}, secret_fields)

        now_dt = datetime.now(UTC)
        next_dt = compute_next_run(cron_expr=cron_expr,
                                   interval_seconds=interval_seconds,
                                   from_dt=now_dt) if enabled else None

        schedule = Schedule(
            id=uuid.uuid4().hex,
            actor_id=actor_id,
            name=name,
            cron_expr=cron_expr,
            interval_seconds=interval_seconds,
            action_type=action_type,
            action_params=clean_params,
            enabled=enabled,
            last_run_at=None,
            next_run_at=next_dt.isoformat() if next_dt else None,
            last_job_id=None,
            created_at=utcnow_iso(),
            updated_at=utcnow_iso(),
        )

        with transaction(self.session_factory) as session:
            return self.repo.create(session, schedule)

    def get(self, schedule_id: str, actor_id: str) -> Schedule | None:
        with transaction(self.session_factory) as session:
            schedule = self.repo.get(session, schedule_id)
            if schedule is None or schedule.actor_id != actor_id:
                return None
            return schedule

    def list(self, actor_id: str, *, limit: int = 50) -> list[Schedule]:
        with transaction(self.session_factory) as session:
            return self.repo.list_by_actor(session, actor_id, limit=limit)

    def update(self, schedule_id: str, actor_id: str, *,
               name: str | None = None,
               cron_expr: str | None = None,
               interval_seconds: int | None = None,
               action_params: dict[str, Any] | None = None,
               enabled: bool | None = None) -> Schedule | None:
        with transaction(self.session_factory) as session:
            schedule = self.repo.get(session, schedule_id)
            if schedule is None or schedule.actor_id != actor_id:
                return None

            recalc_needed = False
            if name is not None:
                schedule.name = name
            if cron_expr is not None:
                schedule.cron_expr = cron_expr if cron_expr else None
                recalc_needed = True
            if interval_seconds is not None:
                schedule.interval_seconds = interval_seconds if interval_seconds > 0 else None
                recalc_needed = True
            if action_params is not None:
                spec = self.catalog.get(schedule.action_type)
                secret_fields = spec.secret_fields if spec else frozenset()
                schedule.action_params = redact(action_params, secret_fields)
            if enabled is not None:
                schedule.enabled = enabled
                recalc_needed = True

            if recalc_needed:
                if schedule.enabled and (schedule.cron_expr or schedule.interval_seconds):
                    now_dt = datetime.now(UTC)
                    next_dt = compute_next_run(cron_expr=schedule.cron_expr,
                                               interval_seconds=schedule.interval_seconds,
                                               from_dt=now_dt)
                    schedule.next_run_at = next_dt.isoformat()
                else:
                    schedule.next_run_at = None

            schedule.updated_at = utcnow_iso()
            self.repo.update(session, schedule)
            return schedule

    def delete(self, schedule_id: str, actor_id: str) -> bool:
        with transaction(self.session_factory) as session:
            schedule = self.repo.get(session, schedule_id)
            if schedule is None or schedule.actor_id != actor_id:
                return False
            self.repo.delete(session, schedule)
            return True

    # -- scheduler tick -------------------------------------------------------
    def tick(self, now_iso: str | None = None) -> list[str]:
        """Trigger due schedules and queue them via JobService.

        Returns the list of submitted background job IDs.
        """
        current_iso = now_iso or utcnow_iso()
        now_dt = datetime.fromisoformat(current_iso)
        if now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=UTC)

        due_schedules: list[Schedule] = []
        with transaction(self.session_factory) as session:
            due_schedules = self.repo.list_due(session, current_iso, limit=50)

        job_ids: list[str] = []
        for schedule in due_schedules:
            due_stamp = schedule.next_run_at or current_iso
            idempotency_key = f"sched:{schedule.id}:{due_stamp}"
            action = Action(
                action_type=schedule.action_type,
                params=dict(schedule.action_params or {}),
            )
            ctx = ExecutionContext(actor_id=schedule.actor_id)
            job = self.job_service.submit(action, ctx, idempotency_key=idempotency_key)
            job_ids.append(job.id)

            # Compute next run
            try:
                next_dt = compute_next_run(
                    cron_expr=schedule.cron_expr,
                    interval_seconds=schedule.interval_seconds,
                    from_dt=now_dt,
                )
                next_iso = next_dt.isoformat()
            except Exception:  # noqa: BLE001
                next_iso = None

            with transaction(self.session_factory) as session:
                refreshed = self.repo.get(session, schedule.id)
                if refreshed is not None:
                    refreshed.last_run_at = current_iso
                    refreshed.last_job_id = job.id
                    refreshed.next_run_at = next_iso
                    refreshed.updated_at = utcnow_iso()
                    self.repo.update(session, refreshed)

        return job_ids
