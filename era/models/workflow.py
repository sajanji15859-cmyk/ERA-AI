"""Durable workflow run state (Phase 4C).

These rows let a paused or process-interrupted workflow be resumed from the
last durable checkpoint. They NEVER persist raw ``element_ref`` values,
plaintext fill values, cookies, headers or page content — only step intent and
redacted params (see :mod:`era.workflows.definition`). Element references are
re-acquired by re-inspecting the page on resume, so no browser state is trusted
across a restart.

Exactly-once: a ``run_token`` is unique per actor; a mutating step's outcome is
recorded in ``workflow_step_run`` and never re-executed on resume. A step whose
outcome is uncertain (``SIDE_EFFECT_UNKNOWN``) leaves the run in ``ambiguous``
and requires explicit operator resolution.
"""

from __future__ import annotations

from sqlalchemy import JSON, Column, ForeignKey, Integer, String, UniqueConstraint

from era.core.util import utcnow_iso
from era.models.base import Base

#: Workflow run lifecycle states.
STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_WAITING = "waiting_for_user"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_AMBIGUOUS = "ambiguous"
STATUS_CANCELLED = "cancelled"


class WorkflowRun(Base):
    __tablename__ = "workflow_run"
    __table_args__ = (
        UniqueConstraint("actor_id", "run_token", name="uq_workflow_actor_run_token"),
    )

    id = Column(String, primary_key=True)  # UUID hex
    workflow_name = Column(String, nullable=False)
    workflow_version = Column(Integer, nullable=False)
    actor_id = Column(String, nullable=False, index=True)
    # Server-derived stateful provider scope; preserved across resume so the
    # browser context resumes the exact run that requested it.
    execution_scope = Column(String, nullable=True)
    status = Column(String, nullable=False, default=STATUS_PENDING)
    #: Index of the current (first not-finished) step in the definition list.
    current_step = Column(Integer, nullable=False, default=0)
    error = Column(String, nullable=True)
    resume_token = Column(String, nullable=True)
    #: Caller/server run token — exactly-once key, unique per actor.
    run_token = Column(String, nullable=False)
    definition_checksum = Column(String, nullable=False)
    #: Redacted workflow definition used for this run (opaque vault refs only).
    definition_redacted = Column(JSON, nullable=False, default=dict)
    #: Redacted caller-supplied run params (renders step templates on resume).
    run_params = Column(JSON, nullable=False, default=dict)
    created_at = Column(String, nullable=False, default=utcnow_iso)
    updated_at = Column(String, nullable=False, default=utcnow_iso)


class WorkflowStepRun(Base):
    __tablename__ = "workflow_step_run"

    id = Column(String, primary_key=True)  # UUID hex
    run_id = Column(String, ForeignKey("workflow_run.id"), nullable=False, index=True)
    step_id = Column(String, nullable=False)
    step_index = Column(Integer, nullable=False)
    action_type = Column(String, nullable=False)
    #: Redacted params template (opaque vault refs only, no element_ref).
    params_redacted = Column(JSON, nullable=False, default=dict)
    status = Column(String, nullable=False, default="pending")
    attempt = Column(Integer, nullable=False, default=0)
    confirmation_id = Column(String, nullable=True)
    #: Sanitized result receipt (never secrets / cookies / refs).
    result_receipt = Column(JSON, nullable=True)
    error_code = Column(String, nullable=True)
    error_message = Column(String, nullable=True)
    started_at = Column(String, nullable=True)
    finished_at = Column(String, nullable=True)
