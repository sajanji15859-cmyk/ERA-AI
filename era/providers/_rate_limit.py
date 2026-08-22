"""Small, process-local actor rate limiter for provider safety boundaries.

Provider limits are deliberately enforced *inside* providers as well as at the
HTTP edge: actions can originate from the API, workflow engine, scheduler, or
agent loop.  The limiter stores no action content and no credentials; it only
keeps monotonic timestamps keyed by actor id.

It is intentionally conservative.  A process restart resets a bucket, while a
single process cannot be used to burst past a configured rolling-window limit.
Deployments that need cluster-wide quotas should enforce the same limit at their
egress gateway as a second boundary.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class ActorRateLimiter:
    """Thread-safe rolling-window limiter keyed by opaque actor identifiers."""

    def __init__(self, *, limit: int, window_seconds: float):
        self.limit = max(1, int(limit))
        self.window_seconds = max(0.001, float(window_seconds))
        self._timestamps: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, actor_id: str | None, *, now: float | None = None) -> bool:
        """Consume one slot and return whether it is permitted."""

        return self.allow_many(actor_id, count=1, now=now)

    def allow_many(self, actor_id: str | None, *, count: int, now: float | None = None) -> bool:
        """Atomically consume ``count`` slots, or consume none when over limit.

        Missing actor ids are isolated in a stable anonymous bucket rather than
        bypassing the limit.  ``now`` is injectable for deterministic tests.
        """

        if not isinstance(count, int) or count < 1:
            return False
        current = time.monotonic() if now is None else float(now)
        key = actor_id or "<anonymous>"
        cutoff = current - self.window_seconds
        with self._lock:
            bucket = self._timestamps[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) + count > self.limit:
                return False
            bucket.extend([current] * count)
            return True

    def remaining(self, actor_id: str | None, *, now: float | None = None) -> int:
        """Return the currently available slots without consuming one."""

        current = time.monotonic() if now is None else float(now)
        key = actor_id or "<anonymous>"
        cutoff = current - self.window_seconds
        with self._lock:
            bucket = self._timestamps[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            return max(0, self.limit - len(bucket))
