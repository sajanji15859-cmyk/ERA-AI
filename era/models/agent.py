"""Agent persistence models (Phase 3A).

* ``AgentRun`` — one agent run (goal → plan/tasks → result), persisted so runs
  survive a pause/resume (user approval) and a server restart.
* ``MemoryEntry`` — long-term per-actor knowledge (exact-key JSON store).

Neither table stores credentials; the agent layer only ever holds opaque
references.
"""

from __future__ import annotations

from sqlalchemy import JSON, Column, String, UniqueConstraint

from era.core.util import utcnow_iso
from era.models.base import Base


class AgentRun(Base):
    __tablename__ = "agent_run"

    id = Column(String, primary_key=True)  # UUID hex
    actor_id = Column(String, nullable=False, index=True)
    goal = Column(String, nullable=False)
    status = Column(String, nullable=False, default="running")
    plan_json = Column(JSON, nullable=True)
    tasks_json = Column(JSON, nullable=True)
    result_json = Column(JSON, nullable=True)
    pending_confirmations_json = Column(JSON, nullable=True)
    error = Column(String, nullable=True)
    created_at = Column(String, nullable=False, default=utcnow_iso)
    updated_at = Column(String, nullable=False, default=utcnow_iso)


class MemoryEntry(Base):
    __tablename__ = "memory_entry"
    __table_args__ = (UniqueConstraint("actor_id", "namespace", "key",
                                       name="uq_memory_actor_namespace_key"),)

    id = Column(String, primary_key=True)  # UUID hex
    actor_id = Column(String, nullable=False, index=True)
    namespace = Column(String, nullable=False, default="default")
    key = Column(String, nullable=False)
    value_json = Column(JSON, nullable=False)
    updated_at = Column(String, nullable=False, default=utcnow_iso)
