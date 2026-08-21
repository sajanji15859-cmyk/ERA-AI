"""Provider-agnostic circuit breaker (Phase 1F).

A small, deterministic tripwire around provider dispatch. It lives in the
reliability layer of the execution service — strictly *after* authorization has
been durably recorded and *outside* any database transaction — and it can only
ever *block* dispatch, never perform it.

States
------
``CLOSED``
    Normal operation; every request is dispatched. Consecutive *eligible*
    provider failures (default: ``UNAVAILABLE`` / ``PROVIDER_ERROR``) beyond
    ``failure_threshold`` open the circuit.
``OPEN``
    Dispatch is blocked for ``cooldown_seconds`` (the breaker reports
    ``UNAVAILABLE``). After the cooldown, the first request transitions to
    ``HALF_OPEN`` and is admitted as a controlled probe.
``HALF_OPEN``
    A single probe is admitted; the dispatch layer reports its outcome
    synchronously. Success closes the circuit; an eligible failure reopens it.

Security invariants
-------------------
* Authorization (``AUTH``), ``FORBIDDEN``, ``VALIDATION``, ``NOT_FOUND``,
  ``CONFLICT``, ``NOT_IMPLEMENTED``, ``TIMEOUT``, ``INTERNAL`` and ``UNKNOWN``
  (an out-of-taxonomy code string) failures are **never** eligible and can
  never trip, reopen or otherwise affect breaker state — an
  authorization/policy failure can never be converted into circuit-breaker
  behavior, and an unrecognized failure is never mistaken for a transient
  outage.
* The breaker is *only* consulted by the execution service after the
  authorization record has been committed, so it cannot bypass the permission
  engine or audit-before-execute; and because it blocks rather than dispatches,
  it cannot execute anything on its own.
* Configuration has safe bounded defaults (a small threshold and a finite
  cooldown), and ``now`` is injectable so behavior is deterministic in tests.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from era.core.result import ProviderErrorCode
from era.core.retry import DEFAULT_RETRYABLE_CODES


class CircuitState(StrEnum):
    """Deterministic circuit-breaker state machine."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass(frozen=True)
class CircuitBreakerConfig:
    """Safe, bounded configuration for :class:`CircuitBreaker`.

    Attributes
    ----------
    failure_threshold:
        Consecutive *eligible* provider failures in ``CLOSED`` that open the
        circuit (>= 1).
    cooldown_seconds:
        How long ``OPEN`` blocks dispatch before a ``HALF_OPEN`` probe is
        admitted (>= 0).
    trip_codes:
        The explicit set of failure codes eligible to count toward opening the
        circuit. Codes outside this set never affect breaker state.
    """

    failure_threshold: int = 5
    cooldown_seconds: float = 30.0
    trip_codes: frozenset[ProviderErrorCode] = DEFAULT_RETRYABLE_CODES

    def __post_init__(self) -> None:
        if not isinstance(self.failure_threshold, int) or self.failure_threshold < 1:
            raise ValueError(
                f"failure_threshold must be an int >= 1, got {self.failure_threshold!r}"
            )
        if self.cooldown_seconds < 0:
            raise ValueError(f"cooldown_seconds must be >= 0, got {self.cooldown_seconds!r}")

    def is_eligible(self, code: ProviderErrorCode | str) -> bool:
        """True only for codes that may count toward opening the circuit."""
        try:
            code = ProviderErrorCode(str(code)) if not isinstance(code, ProviderErrorCode) else code
        except ValueError:
            return False
        return code in self.trip_codes


@dataclass(frozen=True)
class CircuitSnapshot:
    """Storage-neutral durable state-machine snapshot."""

    state: CircuitState
    consecutive_failures: int
    opened_at: float | None


class CircuitStateStore(Protocol):
    """Persistence boundary; SQL implementation lives in repositories."""

    def load(self, provider_id: str) -> CircuitSnapshot | None: ...

    def save(self, provider_id: str, snapshot: CircuitSnapshot) -> None: ...


class CircuitBreaker:
    """Per-provider circuit breaker, optionally backed by a durable store."""

    def __init__(
        self,
        config: CircuitBreakerConfig | None = None,
        *,
        now: Callable[[], float] = time.monotonic,
        provider_id: str | None = None,
        store: CircuitStateStore | None = None,
    ):
        if store is not None and not provider_id:
            raise ValueError("provider_id is required with a circuit state store")
        self.config = config or CircuitBreakerConfig()
        self._now = now
        self._provider_id = provider_id
        self._store = store
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._refresh()

    # -- persistence ---------------------------------------------------------
    def _refresh(self) -> None:
        if self._store is None or self._provider_id is None:
            return
        snapshot = self._store.load(self._provider_id)
        if snapshot is None:
            return
        self._state = CircuitState(snapshot.state)
        self._consecutive_failures = max(0, int(snapshot.consecutive_failures))
        self._opened_at = snapshot.opened_at

    def _persist(self) -> None:
        if self._store is None or self._provider_id is None:
            return
        self._store.save(
            self._provider_id,
            CircuitSnapshot(
                state=self._state,
                consecutive_failures=self._consecutive_failures,
                opened_at=self._opened_at,
            ),
        )

    # -- state ---------------------------------------------------------------
    @property
    def state(self) -> CircuitState:
        self._refresh()
        return self._state

    @property
    def consecutive_failures(self) -> int:
        """Consecutive eligible failures in the current closed streak."""
        self._refresh()
        return self._consecutive_failures

    # -- gate ----------------------------------------------------------------
    def allow_request(self) -> bool:
        """Consulted by the dispatch layer immediately before provider work.

        ``CLOSED`` and ``HALF_OPEN`` admit requests; ``OPEN`` blocks them until
        the cooldown elapses, at which point the *next* request transitions to
        ``HALF_OPEN`` and is admitted as a probe.
        """
        self._refresh()
        if self._state is CircuitState.CLOSED:
            return True
        if self._state is CircuitState.HALF_OPEN:
            return True
        # OPEN.
        assert self._opened_at is not None
        if self._now() - self._opened_at >= self.config.cooldown_seconds:
            self._state = CircuitState.HALF_OPEN
            self._persist()
            return True
        return False

    # -- outcome reporting ---------------------------------------------------
    def record_success(self) -> None:
        """Report a successful provider execute. Closes from HALF_OPEN and
        resets the failure streak; ignored while OPEN (no probe in flight)."""
        self._refresh()
        if self._state is CircuitState.OPEN:
            return
        self._consecutive_failures = 0
        self._opened_at = None
        if self._state is CircuitState.HALF_OPEN:
            self._state = CircuitState.CLOSED
        self._persist()

    def record_failure(self, code: ProviderErrorCode | str) -> None:
        """Report a failed provider execute with its machine-readable code.

        Ineligible codes (authorization, forbidden, validation, timeout, ...)
        are ignored entirely — they can never open, keep open or reopen the
        circuit. In ``CLOSED``, an eligible failure extends the streak and may
        open the circuit; in ``HALF_OPEN``, a failed probe reopens it.
        """
        if not self.config.is_eligible(code):
            return
        self._refresh()
        if self._state is CircuitState.OPEN:
            return
        if self._state is CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            self._consecutive_failures = 1
            self._opened_at = self._now()
            self._persist()
            return
        # CLOSED.
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.config.failure_threshold:
            self._state = CircuitState.OPEN
            self._opened_at = self._now()
        self._persist()


class CircuitBreakerRegistry:
    """One breaker per provider ``id``, sharing a default config.

    Provider isolation matters: one provider's outage must not trip another
    provider's circuit. The execution service resolves a breaker per provider
    id at dispatch time, so breakers are created lazily and deterministically.
    """

    def __init__(
        self,
        default_config: CircuitBreakerConfig | None = None,
        *,
        now: Callable[[], float] = time.monotonic,
        store: CircuitStateStore | None = None,
    ):
        self.default_config = default_config or CircuitBreakerConfig()
        self._now = now
        self._store = store
        self._breakers: dict[str, CircuitBreaker] = {}

    def get(self, provider_id: str) -> CircuitBreaker:
        """Return (creating on first use) the breaker for ``provider_id``."""
        breaker = self._breakers.get(provider_id)
        if breaker is None:
            breaker = CircuitBreaker(
                self.default_config,
                now=self._now,
                provider_id=provider_id,
                store=self._store,
            )
            self._breakers[provider_id] = breaker
        return breaker

    def all(self) -> list[CircuitBreaker]:
        """Every breaker created so far (test/diagnostics)."""
        return list(self._breakers.values())

    def reset_all(self) -> None:
        """Drop all breakers (used by tests; production breakers are long-lived)."""
        self._breakers.clear()
