"""Phase 4E — confirmation expiry sweeper.

Runs periodically (co-located with the scheduler leader) to mark any
PENDING confirmations whose ``expires_at`` has passed as EXPIRED. Without
this, confirmations that time out while no client is calling the API
remain in PENDING state indefinitely, wasting storage and potentially
blocking workflow runs.

The sweeper is idempotent: it only updates rows that are still PENDING
and whose TTL has elapsed. It processes rows in batches to avoid
holding a long transaction.
"""

from __future__ import annotations

import logging

from sqlalchemy import select

from era.core.util import utcnow_iso
from era.db import transaction
from era.models.confirmation import (
    STATUS_EXPIRED,
    STATUS_PENDING,
    PendingConfirmation,
)
from era.repositories.base import ConfirmationRepo

logger = logging.getLogger(__name__)

#: Maximum confirmations to sweep in one tick (bounded batch).
BATCH_SIZE = 100


class ConfirmationSweeper:
    """Mark expired PENDING confirmations as EXPIRED."""

    def __init__(self, *, session_factory, confirmation_repo: ConfirmationRepo):
        self.session_factory = session_factory
        self.repo = confirmation_repo

    def sweep(self) -> int:
        """Find and expire all overdue PENDING confirmations. Returns count."""
        now = utcnow_iso()
        swept = 0

        with transaction(self.session_factory) as session:
            stmt = (
                select(PendingConfirmation)
                .where(PendingConfirmation.status == STATUS_PENDING)
                .where(PendingConfirmation.expires_at <= now)
                .limit(BATCH_SIZE)
            )
            rows = session.execute(stmt).scalars().all()
            for row in rows:
                row.status = STATUS_EXPIRED
                row.used_at = now
                swept += 1
            session.flush()

        if swept:
            logger.info("confirmation sweeper: marked %d confirmations as expired", swept)
        return swept


__all__ = ["ConfirmationSweeper"]
