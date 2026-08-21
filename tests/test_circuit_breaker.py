"""Phase 1F: circuit breaker — deterministic CLOSED/OPEN/HALF_OPEN machine.

Unit tests with an injected clock, so cooldowns are exercised in microseconds
and every transition is fully deterministic.
"""

from __future__ import annotations

import pytest

from era.core.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerRegistry,
    CircuitState,
)
from era.core.result import ProviderErrorCode

#: Codes that must never trip the circuit (authorization/policy/input etc.).
INELIGIBLE = (
    ProviderErrorCode.AUTH,
    ProviderErrorCode.FORBIDDEN,
    ProviderErrorCode.VALIDATION,
    ProviderErrorCode.NOT_FOUND,
    ProviderErrorCode.CONFLICT,
    ProviderErrorCode.TIMEOUT,
    ProviderErrorCode.NOT_IMPLEMENTED,
    ProviderErrorCode.INTERNAL,
)


class Clock:
    def __init__(self, start: float = 0.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _breaker(clock: Clock, **config) -> CircuitBreaker:
    return CircuitBreaker(CircuitBreakerConfig(**config), now=clock)


# ---------------------------------------------------------------------------
# CLOSED
# ---------------------------------------------------------------------------

def test_closed_allows_calls():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=5)
    assert cb.state is CircuitState.CLOSED
    assert cb.allow_request() is True


def test_eligible_failures_open_circuit_at_threshold():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=3)
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    assert cb.state is CircuitState.CLOSED
    assert cb.consecutive_failures == 1
    cb.record_failure(ProviderErrorCode.PROVIDER_ERROR)
    assert cb.state is CircuitState.CLOSED
    assert cb.consecutive_failures == 2
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    assert cb.state is CircuitState.OPEN
    assert cb.consecutive_failures == 3


def test_success_resets_failure_streak_in_closed():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=5)
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    cb.record_success()
    assert cb.state is CircuitState.CLOSED
    assert cb.consecutive_failures == 0


# ---------------------------------------------------------------------------
# OPEN
# ---------------------------------------------------------------------------

def test_open_blocks_calls_during_cooldown():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=1, cooldown_seconds=10.0)
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    assert cb.state is CircuitState.OPEN
    assert cb.allow_request() is False
    clock.advance(9.99)
    assert cb.allow_request() is False  # still inside cooldown
    assert cb.state is CircuitState.OPEN


def test_open_ignores_outcome_records():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=1, cooldown_seconds=10.0)
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    assert cb.state is CircuitState.OPEN
    cb.record_success()  # no probe in flight while OPEN
    assert cb.state is CircuitState.OPEN
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    assert cb.state is CircuitState.OPEN
    clock.advance(10.0)
    assert cb.allow_request() is True  # cooldown elapsed -> probe admitted


# ---------------------------------------------------------------------------
# HALF_OPEN
# ---------------------------------------------------------------------------

def test_cooldown_elapsed_admits_half_open_probe():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=1, cooldown_seconds=10.0)
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    assert cb.state is CircuitState.OPEN
    clock.advance(10.0)
    assert cb.allow_request() is True
    assert cb.state is CircuitState.HALF_OPEN


def test_successful_probe_closes_circuit():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=1, cooldown_seconds=10.0)
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    clock.advance(10.0)
    assert cb.allow_request() is True  # probe admitted
    assert cb.state is CircuitState.HALF_OPEN
    cb.record_success()
    assert cb.state is CircuitState.CLOSED
    assert cb.consecutive_failures == 0
    assert cb.allow_request() is True  # fully operational again


def test_failed_probe_reopens_circuit():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=1, cooldown_seconds=10.0)
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    clock.advance(10.0)
    assert cb.allow_request() is True
    assert cb.state is CircuitState.HALF_OPEN
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    assert cb.state is CircuitState.OPEN
    assert cb.allow_request() is False  # blocked again for a fresh cooldown


# ---------------------------------------------------------------------------
# ineligible failures never become circuit-breaker behavior
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code", INELIGIBLE)
def test_ineligible_failures_never_open_circuit(code):
    clock = Clock()
    cb = _breaker(clock, failure_threshold=2)
    for _ in range(5):  # far beyond the threshold
        cb.record_failure(code)
    assert cb.state is CircuitState.CLOSED
    assert cb.consecutive_failures == 0


def test_forbidden_and_auth_failures_never_open_circuit():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=1)  # threshold 1: any eligible failure trips
    cb.record_failure(ProviderErrorCode.FORBIDDEN)
    cb.record_failure(ProviderErrorCode.AUTH)
    assert cb.state is CircuitState.CLOSED
    assert cb.allow_request() is True


def test_ineligible_failure_during_half_open_probe_does_not_affect_state():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=1, cooldown_seconds=10.0)
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)
    clock.advance(10.0)
    assert cb.allow_request() is True
    assert cb.state is CircuitState.HALF_OPEN
    # The probe "fails" with an authorization code: the breaker must NOT turn
    # that into breaker behavior (no reopen, no re-open, no block).
    cb.record_failure(ProviderErrorCode.AUTH)
    assert cb.state is CircuitState.HALF_OPEN
    cb.record_success()  # subsequent real outcome closes normally
    assert cb.state is CircuitState.CLOSED


def test_unknown_code_never_affects_breaker():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=1)
    cb.record_failure("VENDOR_WAT")  # not a ProviderErrorCode
    assert cb.state is CircuitState.CLOSED
    assert cb.consecutive_failures == 0


# ---------------------------------------------------------------------------
# determinism / configuration / structure
# ---------------------------------------------------------------------------

def test_state_transitions_are_deterministic():
    script = [
        ("fail", ProviderErrorCode.UNAVAILABLE),
        ("fail", ProviderErrorCode.UNAVAILABLE),
        ("allow", None),
        ("allow", None),
        ("advance", 30.0),
        ("allow", None),
        ("success", None),
        ("allow", None),
    ]

    def run(clock: Clock) -> list[str]:
        cb = _breaker(clock, failure_threshold=2, cooldown_seconds=30.0)
        seen = [cb.state.value]
        for op, code in script:
            if op == "fail":
                cb.record_failure(code)
            elif op == "allow":
                cb.allow_request()
            elif op == "advance":
                clock.advance(code)
            elif op == "success":
                cb.record_success()
            seen.append(cb.state.value)
        return seen

    c1, c2 = Clock(), Clock()
    # CLOSED -> (fail) CLOSED -> (fail) OPEN -> blocked -> blocked ->
    # (cooldown) HALF_OPEN probe -> (success) CLOSED -> CLOSED.
    assert run(c1) == run(c2) == [
        "CLOSED", "CLOSED", "OPEN", "OPEN", "OPEN", "OPEN", "HALF_OPEN",
        "CLOSED", "CLOSED",
    ]


def test_config_validation():
    with pytest.raises(ValueError):
        CircuitBreakerConfig(failure_threshold=0)
    with pytest.raises(ValueError):
        CircuitBreakerConfig(failure_threshold=-3)
    with pytest.raises(ValueError):
        CircuitBreakerConfig(failure_threshold="3")
    with pytest.raises(ValueError):
        CircuitBreakerConfig(cooldown_seconds=-1.0)


def test_custom_trip_codes():
    clock = Clock()
    cb = _breaker(clock, failure_threshold=2,
                  trip_codes=frozenset({ProviderErrorCode.PROVIDER_ERROR}))
    cb.record_failure(ProviderErrorCode.UNAVAILABLE)  # not in custom trip set
    assert cb.state is CircuitState.CLOSED
    cb.record_failure(ProviderErrorCode.PROVIDER_ERROR)
    cb.record_failure(ProviderErrorCode.PROVIDER_ERROR)
    assert cb.state is CircuitState.OPEN


def test_breaker_cannot_dispatch_or_execute():
    # Structural guarantee: the breaker only gates and records outcomes. It has
    # no execute/dispatch/run capability, so it can never perform an action.
    cb = CircuitBreaker()
    assert not hasattr(cb, "execute")
    assert not hasattr(cb, "dispatch")
    assert not hasattr(cb, "run")


# ---------------------------------------------------------------------------
# registry (per-provider isolation)
# ---------------------------------------------------------------------------

def test_registry_isolates_providers():
    clock = Clock()
    reg = CircuitBreakerRegistry(
        CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=10.0), now=clock,
    )
    a = reg.get("provider-a")
    b = reg.get("provider-b")
    assert a is not b
    a.record_failure(ProviderErrorCode.UNAVAILABLE)
    assert a.state is CircuitState.OPEN
    assert b.state is CircuitState.CLOSED
    assert b.allow_request() is True  # provider-a's outage never blocks b
    assert reg.get("provider-a") is a  # stable per id


def test_registry_reset_all():
    reg = CircuitBreakerRegistry()
    assert len(reg.all()) == 0
    reg.get("x")
    reg.get("y")
    assert len(reg.all()) == 2
    reg.reset_all()
    assert len(reg.all()) == 0
