"""Phase 4E — scheduler leader election row (DB-backed coordination).

A single row in :class:`SchedulerLeader` acts as a distributed mutex for the
in-process scheduler worker. Only one process at a time is the "leader" — it
runs ticks. A stale leader (heartbeat older than ``heartbeat_timeout``) is
forcibly replaced. This allows multiple ERA processes to run side-by-side
(e.g. multiple workers behind a load balancer) without duplicating schedule
ticks.

Invariants:
* Only one row in the table (singleton).
* ``leader_id`` is a unique opaque token per process (UUID).
* ``heartbeat_at`` is updated every tick; a stale heartbeat allows takeover.
* Takeover uses optimistic concurrency: ``WHERE version = ?`` so two
  processes cannot both claim leadership in the same instant.
"""

from __future__ import annotations

from sqlalchemy import Column, Integer, String

from era.core.util import utcnow_iso
from era.models.base import Base


class SchedulerLeader(Base):
    __tablename__ = "scheduler_leader"

    id = Column(String, primary_key=True, default="singleton")
    leader_id = Column(String, nullable=False)
    heartbeat_at = Column(String, nullable=False, default=utcnow_iso)
    version = Column(Integer, nullable=False, default=1)
