"""Background job persistence (Phase 3G).

A :class:`Job` is the durable record of an async execution submitted through
``POST /v1/actions/execute`` with ``async=true``. The row stores the *redacted*
action params (never secret fields) and, once finished, the resulting
:class:`~era.schemas.actions.ExecutionResponse`. The raw action is held only in
memory by the worker thread, so a process crash never leaves secret material in
the database — interrupted jobs are failed on the next startup.

An optional ``idempotency_key_hash`` (SHA-256 of the actor + key) deduplicates
re-submissions: re-submitting the same key returns the already-queued/running/
finished job instead of dispatching a second one. ``NULL`` means "no key" and
allows any number of independent jobs.
"""

from __future__ import annotations

from sqlalchemy import JSON, Column, String, UniqueConstraint

from era.core.util import utcnow_iso
from era.models.base import Base


class Job(Base):
    __tablename__ = "job"
    __table_args__ = (
        UniqueConstraint("actor_id", "idempotency_key_hash",
                         name="uq_job_actor_idem_key"),
    )

    id = Column(String, primary_key=True)  # UUID hex
    actor_id = Column(String, nullable=False, index=True)
    kind = Column(String, nullable=False, default="action.execute")
    idempotency_key_hash = Column(String, nullable=True, index=True)
    request_hash = Column(String, nullable=True)  # canonical hash of the request
    status = Column(String, nullable=False, default="queued")  # queued|running|completed|failed
    action_type = Column(String, nullable=False)
    action_params = Column(JSON, nullable=False, default=dict)  # redacted
    session_id = Column(String, nullable=True)
    credential_refs = Column(JSON, nullable=False, default=dict)  # opaque refs only
    response_json = Column(JSON, nullable=True)  # stored ExecutionResponse
    error = Column(String, nullable=True)
    created_at = Column(String, nullable=False, default=utcnow_iso)
    updated_at = Column(String, nullable=False, default=utcnow_iso)
    expires_at = Column(String, nullable=True)
