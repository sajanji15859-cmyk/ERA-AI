"""Phase 1F: retry policy/loop — deterministic, bounded, deadline-aware.

These are pure unit tests: backoff sleeps and clocks are injected, so the suite
runs in milliseconds and is fully deterministic.
"""

from __future__ import annotations

import logging

import pytest

from era.core.result import ProviderErrorCode, ToolError
from era.core.retry import (
    MAX_ATTEMPTS_BOUND,
    NEVER_RETRY_CODES,
    RetryPolicy,
    with_retry,
)


class Clock:
    """Deterministic stand-in for time.monotonic."""

    def __init__(self, start: float = 0.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _noop_sleep(_: float) -> None:
    return None


def _make_sleeper(clock: Clock, sleeps: list[float]):
    def sleeper(delay: float) -> None:
        sleeps.append(delay)
        clock.advance(delay)

    return sleeper


# ---------------------------------------------------------------------------
# basic retry semantics
# ---------------------------------------------------------------------------

def test_first_attempt_success_no_retry():
    calls = 0

    def ok():
        nonlocal calls
        calls += 1
        return "done"

    result = with_retry(
        ok, policy=RetryPolicy(max_attempts=3, base_backoff_seconds=1.0), sleep=_noop_sleep,
    )
    assert result == "done"
    assert calls == 1


def test_retryable_failure_then_success():
    calls = 0

    def flaky():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ToolError("temporary outage", code=ProviderErrorCode.UNAVAILABLE)
        return "recovered"

    result = with_retry(
        flaky, policy=RetryPolicy(max_attempts=3, base_backoff_seconds=0.0), sleep=_noop_sleep,
    )
    assert result == "recovered"
    assert calls == 2


def test_retryable_failure_until_exhaustion_raises_original_error():
    calls = 0
    original = ToolError("503", code=ProviderErrorCode.UNAVAILABLE)

    def fail():
        nonlocal calls
        calls += 1
        raise original

    with pytest.raises(ToolError) as exc:
        with_retry(
            fail, policy=RetryPolicy(max_attempts=3, base_backoff_seconds=0.0), sleep=_noop_sleep,
        )
    # Exhaustion re-raises the ORIGINAL error object with its original code.
    assert exc.value is original
    assert exc.value.code is ProviderErrorCode.UNAVAILABLE
    assert calls == 3


@pytest.mark.parametrize("code", sorted(NEVER_RETRY_CODES, key=lambda c: c.value))
def test_non_retryable_codes_never_retried(code):
    calls = 0

    def fail():
        nonlocal calls
        calls += 1
        raise ToolError(str(code), code=code)

    with pytest.raises(ToolError) as exc:
        with_retry(
            fail, policy=RetryPolicy(max_attempts=5, base_backoff_seconds=0.1), sleep=_noop_sleep,
        )
    assert calls == 1
    assert exc.value.code is code


def test_non_toolerror_propagates_immediately_not_retried():
    calls = 0

    def boom():
        nonlocal calls
        calls += 1
        raise RuntimeError("not a ToolError")

    with pytest.raises(RuntimeError):
        with_retry(
            boom, policy=RetryPolicy(max_attempts=5, base_backoff_seconds=0.1), sleep=_noop_sleep,
        )
    assert calls == 1


def test_max_attempts_respected():
    calls = 0

    def fail():
        nonlocal calls
        calls += 1
        raise ToolError("down", code=ProviderErrorCode.UNAVAILABLE)

    with pytest.raises(ToolError):
        with_retry(
            fail, policy=RetryPolicy(max_attempts=4, base_backoff_seconds=0.0), sleep=_noop_sleep,
        )
    assert calls == 4


def test_max_attempts_one_disables_retry():
    calls = 0

    def fail():
        nonlocal calls
        calls += 1
        raise ToolError("down", code=ProviderErrorCode.UNAVAILABLE)

    with pytest.raises(ToolError):
        with_retry(
            fail, policy=RetryPolicy(max_attempts=1, base_backoff_seconds=10.0), sleep=_noop_sleep,
        )
    assert calls == 1


# ---------------------------------------------------------------------------
# backoff configuration
# ---------------------------------------------------------------------------

def test_backoff_configuration_respected():
    clock = Clock()
    sleeps: list[float] = []

    def fail():
        raise ToolError("down", code=ProviderErrorCode.UNAVAILABLE)

    with pytest.raises(ToolError):
        with_retry(
            fail,
            policy=RetryPolicy(max_attempts=4, base_backoff_seconds=0.5,
                               max_backoff_seconds=2.0, backoff_factor=2.0),
            now=clock, sleep=_make_sleeper(clock, sleeps),
        )
    # Exponential: 0.5, 1.0, then capped at max_backoff_seconds.
    assert sleeps == [0.5, 1.0, 2.0]


def test_backoff_capped_at_max():
    clock = Clock()
    sleeps: list[float] = []

    def fail():
        raise ToolError("down", code=ProviderErrorCode.UNAVAILABLE)

    with pytest.raises(ToolError):
        with_retry(
            fail,
            policy=RetryPolicy(max_attempts=4, base_backoff_seconds=10.0,
                               max_backoff_seconds=1.0, backoff_factor=1.0),
            now=clock, sleep=_make_sleeper(clock, sleeps),
        )
    assert sleeps == [1.0, 1.0, 1.0]


# ---------------------------------------------------------------------------
# deadline / timeout interplay
# ---------------------------------------------------------------------------

def test_deadline_exhausted_before_first_attempt():
    clock = Clock(start=100.0)
    calls = 0

    def call():
        nonlocal calls
        calls += 1
        return "x"

    with pytest.raises(ToolError) as exc:
        with_retry(call, policy=RetryPolicy(), deadline=clock() - 1.0, now=clock)
    assert exc.value.code is ProviderErrorCode.TIMEOUT
    assert calls == 0


def test_retry_stops_when_backoff_exceeds_deadline():
    clock = Clock()
    attempts: list[float] = []
    sleeps: list[float] = []

    def fail():
        attempts.append(clock())
        raise ToolError("down", code=ProviderErrorCode.UNAVAILABLE)

    deadline = clock() + 0.5
    with pytest.raises(ToolError) as exc:
        with_retry(
            fail,
            policy=RetryPolicy(max_attempts=10, base_backoff_seconds=0.4,
                               max_backoff_seconds=0.4, backoff_factor=1.0),
            deadline=deadline, now=clock, sleep=_make_sleeper(clock, sleeps),
        )
    # Attempt at t=0, sleep 0.4 -> t=0.4, attempt again; next backoff 0.4 no
    # longer fits in the remaining 0.1s, so the loop terminates with TIMEOUT
    # instead of running the remaining 8 attempts.
    assert exc.value.code is ProviderErrorCode.TIMEOUT
    assert attempts == [0.0, 0.4]
    assert sleeps == [0.4]


def test_timeout_error_never_retried():
    calls = 0

    def slow():
        nonlocal calls
        calls += 1
        raise ToolError("slow", code=ProviderErrorCode.TIMEOUT)

    with pytest.raises(ToolError) as exc:
        with_retry(
            slow, policy=RetryPolicy(max_attempts=5, base_backoff_seconds=0.1), sleep=_noop_sleep,
        )
    assert calls == 1
    assert exc.value.code is ProviderErrorCode.TIMEOUT


# ---------------------------------------------------------------------------
# policy configuration / code matrix
# ---------------------------------------------------------------------------

def test_retryable_code_matrix():
    policy = RetryPolicy()
    assert policy.is_retryable(ProviderErrorCode.UNAVAILABLE)
    assert policy.is_retryable(ProviderErrorCode.PROVIDER_ERROR)
    assert policy.is_retryable("UNAVAILABLE")  # string coercion works
    for code in NEVER_RETRY_CODES:
        assert not policy.is_retryable(code)
    assert not policy.is_retryable("VENDOR_WAT")
    assert not policy.is_retryable("")  # unknown string -> not retried


def test_never_retry_codes_cannot_be_enabled_by_config():
    # Even if an operator misconfigures retryable_codes to include a
    # never-retry code, the carve-out wins (fail closed).
    evil = RetryPolicy(retryable_codes=frozenset({ProviderErrorCode.TIMEOUT}))
    assert not evil.is_retryable(ProviderErrorCode.TIMEOUT)
    # The configured set fully replaces the default; with only TIMEOUT listed
    # (which the carve-out then rejects), nothing is retryable.
    assert not evil.is_retryable(ProviderErrorCode.UNAVAILABLE)


def test_custom_retryable_set():
    custom = RetryPolicy(retryable_codes=frozenset({ProviderErrorCode.UNAVAILABLE}))
    assert custom.is_retryable(ProviderErrorCode.UNAVAILABLE)
    assert not custom.is_retryable(ProviderErrorCode.PROVIDER_ERROR)


def test_policy_validation_is_bounded():
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=MAX_ATTEMPTS_BOUND + 1)
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts="3")
    with pytest.raises(ValueError):
        RetryPolicy(base_backoff_seconds=-0.1)
    with pytest.raises(ValueError):
        RetryPolicy(max_backoff_seconds=-1.0)
    with pytest.raises(ValueError):
        RetryPolicy(backoff_factor=0.5)


# ---------------------------------------------------------------------------
# secrets / observability
# ---------------------------------------------------------------------------

def test_retry_loop_emits_no_logs(caplog):
    secret = "sk-SUPERSECRET-123"

    def fail():
        raise ToolError(f"down {secret}", code=ProviderErrorCode.UNAVAILABLE)

    with caplog.at_level(logging.DEBUG), pytest.raises(ToolError):
        with_retry(
            fail, policy=RetryPolicy(max_attempts=3, base_backoff_seconds=0.0),
            sleep=_noop_sleep,
        )
    # The retry loop never logs, so it cannot leak secrets into logs.
    assert caplog.text == ""


def test_retry_passes_error_through_unmodified():
    secret = "sk-SUPERSECRET-123"
    err = ToolError(f"down {secret}", code=ProviderErrorCode.UNAVAILABLE)
    calls = 0

    def fail():
        nonlocal calls
        calls += 1
        raise err

    with pytest.raises(ToolError) as exc:
        with_retry(
            fail, policy=RetryPolicy(max_attempts=3, base_backoff_seconds=0.0), sleep=_noop_sleep,
        )
    # The exact original object survives exhaustion — the retry layer adds no
    # wrapping strings and no new secret-bearing content of its own.
    assert exc.value is err
    assert str(exc.value) == f"down {secret}"
