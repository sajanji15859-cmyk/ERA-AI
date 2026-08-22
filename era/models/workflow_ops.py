"""Phase 4D operations models: workflow schedules, templates, governance counters.

These tables store the operations layer around the Phase 4C workflow engine.
All definitions are redacted before storage; governance counters are the only
mutable admission state (and are intentionally bounded).
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Column, Integer, String, UniqueConstraint

from era.core.util import utcnow_iso
from era.models.base import Base


class WorkflowSchedule(Base):
    """A recurring workflow run (Phase 4D Priority 1).

    Reuses the Phase 3H cron/interval machinery semantics but carries a fixed,
    redacted params template plus the exact-once run-token derivation inputs.
    A due schedule is started through the same WorkflowService gates as an
    interactive run, so a schedule is never a confirmation bypass.
    """

    __tablename__ = "workflow_schedule"
    __table_args__ = (
        UniqueConstraint("actor_id", "name", name="uq_workflow_schedule_actor_name"),
    )

    id = Column(String, primary_key=True)
    actor_id = Column(String, nullable=False, index=True)
    actor_role = Column(String, nullable=True)
    name = Column(String, nullable=False)
    workflow_name = Column(String, nullable=False)
    workflow_version = Column(Integer, nullable=True)
    #: Fixed, redacted params template (vault refs preserved).
    params_redacted = Column(JSON, nullable=False, default=dict)
    cron_expr = Column(String, nullable=True)
    interval_seconds = Column(Integer, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    last_run_at = Column(String, nullable=True)
    next_run_at = Column(String, nullable=True, index=True)
    last_run_id = Column(String, nullable=True)
    created_at = Column(String, nullable=False, default=utcnow_iso)
    updated_at = Column(String, nullable=False, default=utcnow_iso)


class WorkflowTemplate(Base):
    """Immutable published workflow template version (Phase 4D Priority 4).

    Publish creates a new version row; published rows are never mutated. A run
    records exactly the template+version it used and the definition checksum,
    so a later version bump can never silently change a started run.
    """

    __tablename__ = "workflow_template"
    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_workflow_template_name_version"),
    )

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False, index=True)
    version = Column(Integer, nullable=False)
    #: Redacted definition JSON (opaque vault refs only).
    definition_redacted = Column(JSON, nullable=False, default=dict)
    params_schema = Column(JSON, nullable=False, default=dict)
    checksum = Column(String, nullable=False)
    status = Column(String, nullable=False, default="published")  # draft|published
    created_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False, default=utcnow_iso)
    published_at = Column(String, nullable=False, default=utcnow_iso)


class WorkflowGovernanceCounter(Base):
    """Admission / rate-limit / budget counter (Phase 4D Priority 3).

    ``kind`` distinguishes concurrency, rate, steps and cost budgets; ``scope``
    is the deterministic scoping key (e.g. ``actor:<id>``, ``workflow:<name>``,
    ``rate:<name>:<window>``). ``(kind, scope)`` is unique so a counter row is
    an atomic mutex for admission decisions.
    """

    __tablename__ = "workflow_governance_counter"
    __table_args__ = (
        UniqueConstraint("kind", "scope", name="uq_workflow_gov_kind_scope"),
    )

    id = Column(String, primary_key=True)
    kind = Column(String, nullable=False)
    scope = Column(String, nullable=False)
    count = Column(Integer, nullable=False, default=0)
    updated_at = Column(String, nullable=False, default=utcnow_iso)


__all__ = [
    "WorkflowGovernanceCounter",
    "WorkflowSchedule",
    "WorkflowTemplate",
]
