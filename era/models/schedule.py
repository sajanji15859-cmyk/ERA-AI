"""Scheduled recurring job model (Phase 3H).

A :class:`Schedule` represents a recurring execution definition (cron expression
or interval) owned by an actor. When due, an in-process scheduler thread triggers
the execution through :class:`~era.services.jobs.JobService` under the SAME
permission, authorization, confirmation and audit gates as interactive execution.

Idempotency: Each run submission uses a deterministic idempotency key
(``sched:<schedule_id>:<due_next_run_at>``) so process restarts or crashes never
double-execute a scheduled run.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Column, Integer, String

from era.core.util import utcnow_iso
from era.models.base import Base


class Schedule(Base):
    __tablename__ = "schedule"

    id = Column(String, primary_key=True)  # UUID hex
    actor_id = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False)
    cron_expr = Column(String, nullable=True)  # e.g. "0 8 * * *"
    interval_seconds = Column(Integer, nullable=True)  # e.g. 3600
    action_type = Column(String, nullable=False)
    action_params = Column(JSON, nullable=False, default=dict)  # redacted
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    last_run_at = Column(String, nullable=True)  # ISO UTC
    next_run_at = Column(String, nullable=True, index=True)  # ISO UTC
    last_job_id = Column(String, nullable=True)  # UUID of the most recently submitted job
    created_at = Column(String, nullable=False, default=utcnow_iso)
    updated_at = Column(String, nullable=False, default=utcnow_iso)
