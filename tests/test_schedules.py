"""Tests for ScheduleService and recurring job scheduling (Phase 3H)."""

from __future__ import annotations

from datetime import datetime

import pytest

from era.core.action import Action
from era.core.result import ActionResult
from era.core.tool_provider import ToolProvider
from era.db import transaction
from era.models.schedule import Schedule
from tests.conftest import make_container


class DummyWorkerProvider(ToolProvider):
    id = "dummy-worker"
    action_types = frozenset({"stub.noop", "web.search"})

    def __init__(self):
        self.executed_actions: list[Action] = []

    def validate(self, action):
        pass

    def execute(self, action, ctx):
        self.executed_actions.append(action)
        return ActionResult(success=True, summary="executed ok", data={"test": True})


def test_schedule_crud(tmp_path):
    c = make_container(tmp_path)
    svc = c.schedule_service

    # Create schedule with interval
    sched = svc.create(
        actor_id="actor-1",
        name="Hourly backup",
        action_type="stub.noop",
        action_params={"task": "backup"},
        interval_seconds=3600,
        enabled=True,
    )
    assert isinstance(sched, Schedule)
    assert sched.name == "Hourly backup"
    assert sched.next_run_at is not None
    assert sched.actor_id == "actor-1"

    # Get schedule
    fetched = svc.get(sched.id, "actor-1")
    assert fetched is not None
    assert fetched.id == sched.id

    # List schedules
    schedules = svc.list("actor-1")
    assert len(schedules) == 1
    assert schedules[0].id == sched.id

    # Cross-actor isolation
    assert svc.get(sched.id, "actor-2") is None
    assert len(svc.list("actor-2")) == 0

    # Update schedule
    updated = svc.update(sched.id, "actor-1", name="Updated backup", interval_seconds=1800)
    assert updated is not None
    assert updated.name == "Updated backup"
    assert updated.interval_seconds == 1800

    # Delete schedule
    assert svc.delete(sched.id, "actor-1") is True
    assert svc.get(sched.id, "actor-1") is None


def test_schedule_cron_next_run(tmp_path):
    c = make_container(tmp_path)
    svc = c.schedule_service

    sched = svc.create(
        actor_id="actor-1",
        name="Daily at 8am",
        action_type="stub.noop",
        cron_expr="0 8 * * *",
        enabled=True,
    )
    assert sched.next_run_at is not None
    dt = datetime.fromisoformat(sched.next_run_at)
    assert dt.hour == 8
    assert dt.minute == 0


def test_schedule_tick_submits_job(tmp_path):
    dummy = DummyWorkerProvider()
    c = make_container(tmp_path, providers=[dummy])
    svc = c.schedule_service

    # Create schedule due in the past
    past_iso = "2026-01-01T00:00:00+00:00"
    sched = svc.create(
        actor_id="actor-1",
        name="Due check",
        action_type="stub.noop",
        action_params={"check": 1},
        interval_seconds=60,
        enabled=True,
    )

    # Force next_run_at to the past
    with transaction(c.session_factory) as session:
        row = c.repositories.schedule.get(session, sched.id)
        row.next_run_at = past_iso
        c.repositories.schedule.update(session, row)

    job_ids = svc.tick(now_iso="2026-01-01T00:01:00+00:00")
    assert len(job_ids) == 1
    job_id = job_ids[0]

    # Verify Job was submitted to JobService
    job = c.job_service.get(job_id, "actor-1")
    assert job is not None
    assert job.action_type == "stub.noop"

    # Verify Schedule was updated with last_run_at and last_job_id
    updated_sched = svc.get(sched.id, "actor-1")
    assert updated_sched.last_run_at == "2026-01-01T00:01:00+00:00"
    assert updated_sched.last_job_id == job_id


def test_schedule_tick_idempotency_prevents_duplicate(tmp_path):
    c = make_container(tmp_path)
    svc = c.schedule_service

    past_iso = "2026-01-01T00:00:00+00:00"
    sched = svc.create(
        actor_id="actor-1",
        name="Idempotent check",
        action_type="stub.noop",
        interval_seconds=300,
        enabled=True,
    )

    with transaction(c.session_factory) as session:
        row = c.repositories.schedule.get(session, sched.id)
        row.next_run_at = past_iso
        c.repositories.schedule.update(session, row)

    # First tick
    job_ids_1 = svc.tick(now_iso="2026-01-01T00:00:30+00:00")
    assert len(job_ids_1) == 1

    # Second tick immediately without new due schedule produces no duplicates
    job_ids_2 = svc.tick(now_iso="2026-01-01T00:00:35+00:00")
    assert len(job_ids_2) == 0


def test_schedule_cannot_schedule_forbidden(tmp_path):
    c = make_container(tmp_path)
    svc = c.schedule_service

    from era.security.exceptions import AuthorizationError

    with pytest.raises(AuthorizationError):
        svc.create(
            actor_id="actor-1",
            name="Forbidden delete",
            action_type="account.delete",
            interval_seconds=60,
        )
