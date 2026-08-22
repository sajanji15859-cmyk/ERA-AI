"""Phase 4E — DB-backed scheduler leader election.

The in-process scheduler (:class:`~era.services.schedules.ScheduleService`)
periodically ticks to fire due schedules. In a multi-worker deployment
(multiple ERA processes) every worker would tick — causing duplicate
schedule dispatches. The :class:`SchedulerLeaderService` uses a singleton DB
row with optimistic concurrency (``version`` column) so exactly one process
at a time is the leader:

* On startup the process tries to **claim** leadership by writing its
  ``leader_id`` (a UUID). If the row already exists with a fresh heartbeat
  the claim is rejected — another process is already leading.
* Every tick the leader **heartbeats** — updates ``heartbeat_at`` + bumps
  ``version``. A heartbeat uses optimistic locking: ``WHERE version = ?``.
* A standby process checks the heartbeat periodically. If the heartbeat is
  older than ``heartbeat_timeout_seconds`` the leader is considered stale
  and the standby can **take over** by updating ``leader_id`` with a fresh
  version.
* On shutdown the leader **releases** by clearing its ``leader_id``.

Invariants:
* At most one leader at any time.
* A stale leader (heartbeat older than timeout) is forcibly replaceable.
* Schedule dispatch is idempotent (sched:<id>:<due> key) — even if two
  processes accidentally both tick a due schedule, the idempotency key
  prevents duplicate execution. The leader election is belt-and-suspenders.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from era.core.util import utcnow_iso
from era.db import transaction
from era.models.scheduler_leader import SchedulerLeader


class SchedulerLeaderService:
    """DB-backed single-leader election for the scheduler worker."""

    SINGLETON_ID = "singleton"

    def __init__(self, *, session_factory, heartbeat_timeout_seconds: float = 30.0):
        self.session_factory = session_factory
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self._leader_id: str = uuid.uuid4().hex

    @property
    def leader_id(self) -> str:
        return self._leader_id

    def is_leader(self) -> bool:
        """Return True if this process is the current leader."""
        with transaction(self.session_factory) as session:
            row = session.get(SchedulerLeader, self.SINGLETON_ID)
            return row is not None and row.leader_id == self._leader_id

    def try_claim(self) -> bool:
        """Try to become the leader. Returns True if successful.

        If the row doesn't exist, creates it. If it exists with a stale
        heartbeat, takes over. If it exists with a fresh heartbeat from
        another leader, returns False.
        """
        now = utcnow_iso()
        with transaction(self.session_factory) as session:
            row = session.get(SchedulerLeader, self.SINGLETON_ID)
            if row is None:
                # First claim: insert the singleton row.
                row = SchedulerLeader(
                    id=self.SINGLETON_ID,
                    leader_id=self._leader_id,
                    heartbeat_at=now,
                    version=1,
                )
                session.add(row)
                session.flush()
                return True

            if row.leader_id == self._leader_id:
                # Already the leader: just heartbeat.
                row.heartbeat_at = now
                row.version += 1
                session.flush()
                return True

            # Another process holds leadership. Check if stale.
            if self._is_stale(row.heartbeat_at):
                # Stale heartbeat: take over.
                row.leader_id = self._leader_id
                row.heartbeat_at = now
                row.version += 1
                session.flush()
                return True

            return False

    def heartbeat(self) -> bool:
        """Update the heartbeat. Returns True if this process is still leader.

        Uses optimistic concurrency: only updates if version matches.
        """
        now = utcnow_iso()
        with transaction(self.session_factory) as session:
            row = session.get(SchedulerLeader, self.SINGLETON_ID)
            if row is None:
                return False
            if row.leader_id != self._leader_id:
                return False
            row.heartbeat_at = now
            row.version += 1
            session.flush()
            return True

    def release(self) -> None:
        """Release leadership (called on graceful shutdown)."""
        with transaction(self.session_factory) as session:
            row = session.get(SchedulerLeader, self.SINGLETON_ID)
            if row is not None and row.leader_id == self._leader_id:
                row.leader_id = ""  # clear leadership
                row.heartbeat_at = utcnow_iso()
                row.version += 1
                session.flush()

    def get_leader_info(self) -> dict:
        """Return current leader info for health/observability."""
        with transaction(self.session_factory) as session:
            row = session.get(SchedulerLeader, self.SINGLETON_ID)
            if row is None:
                return {"leader_id": None, "heartbeat_at": None, "is_stale": False}
            return {
                "leader_id": row.leader_id or None,
                "heartbeat_at": row.heartbeat_at,
                "is_stale": self._is_stale(row.heartbeat_at),
                "version": row.version,
            }

    def _is_stale(self, heartbeat_at: str) -> bool:
        """Check if a heartbeat is older than the timeout."""
        if not heartbeat_at:
            return True
        try:
            hb_dt = datetime.fromisoformat(heartbeat_at)
            if hb_dt.tzinfo is None:
                from datetime import UTC
                hb_dt = hb_dt.replace(tzinfo=UTC)
            now = datetime.now(hb_dt.tzinfo)
            return (now - hb_dt) > timedelta(seconds=self.heartbeat_timeout_seconds)
        except (ValueError, TypeError):
            return True


__all__ = ["SchedulerLeaderService"]
