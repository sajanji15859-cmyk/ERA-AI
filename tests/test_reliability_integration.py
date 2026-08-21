"""Phase 1F: execution reliability integration at the dispatch boundary.

These tests drive the real ExecutionService and assert the security-order
invariants: authorization is durably recorded BEFORE any dispatch (including
retry attempts), FORBIDDEN never dispatches, timeouts stay bounded, retries and
the circuit breaker can never bypass authorization or the permission engine,
audit results stay correct, and no secret material leaks through the new
reliability surface.
"""

from __future__ import annotations

import time

from era.core.action import Action
from era.core.circuit_breaker import CircuitBreakerConfig, CircuitBreakerRegistry
from era.core.context import ExecutionContext
from era.core.enums import Decision, Outcome
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.core.retry import RetryPolicy
from era.db import transaction
from era.security.redaction import REDACTED
from tests.conftest import action, make_container


class Clock:
    def __init__(self, start: float = 0.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


class FlakyOnce:
    """Fails with UNAVAILABLE on the first execute, then succeeds."""

    id = "flaky-once"
    action_types = frozenset({"stub.noop"})

    def __init__(self):
        self.calls = 0

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        self.calls += 1
        if self.calls == 1:
            raise ToolError("temporary outage", code=ProviderErrorCode.UNAVAILABLE)
        return ActionResult(success=True, summary="recovered")


class AlwaysDown:
    """Always fails with UNAVAILABLE."""

    id = "always-down"
    action_types = frozenset({"stub.noop"})

    def __init__(self):
        self.calls = 0

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        self.calls += 1
        raise ToolError("503", code=ProviderErrorCode.UNAVAILABLE)


class AuthBouncer:
    """Always fails with AUTH (never retryable, never breaker-eligible)."""

    id = "auth-bouncer"
    action_types = frozenset({"stub.noop"})

    def __init__(self):
        self.calls = 0

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        self.calls += 1
        raise ToolError("bad credential ref", code=ProviderErrorCode.AUTH)


def _audit(c, action_type: str | None = None):
    with transaction(c.session_factory) as session:
        return [e for e in c.audit_service.list(session, action_type=action_type)]


def _no_backoff(c, max_attempts: int = 3) -> None:
    c.execution_service.retry_policy = RetryPolicy(
        max_attempts=max_attempts, base_backoff_seconds=0.0,
    )


def _breaker_registry(c, threshold: int, cooldown: float, clock=None) -> CircuitBreakerRegistry:
    reg = CircuitBreakerRegistry(
        CircuitBreakerConfig(failure_threshold=threshold, cooldown_seconds=cooldown),
        now=clock or time.monotonic,
    )
    c.execution_service.circuit_breakers = reg
    return reg


def _request(c, a: Action):
    return c.execution_service.request(a, ExecutionContext(actor_id="t"))


# ---------------------------------------------------------------------------
# retry integration
# ---------------------------------------------------------------------------

def test_retryable_failure_then_success(tmp_path):
    provider = FlakyOnce()
    c = make_container(tmp_path, providers=[provider])
    _no_backoff(c)

    resp = _request(c, action("stub.noop"))
    assert resp.status == "executed"
    assert provider.calls == 2  # one retry after the transient UNAVAILABLE

    entries = _audit(c)
    assert [e.outcome for e in entries] == ["AUTHORIZED", "EXECUTED"]
    assert entries[-1].error_code is None


def test_retry_exhaustion_recorded_with_original_code(tmp_path):
    provider = AlwaysDown()
    c = make_container(tmp_path, providers=[provider])
    _no_backoff(c, max_attempts=3)

    resp = _request(c, action("stub.noop"))
    assert resp.status == "failed"
    assert provider.calls == 3  # bounded by max_attempts

    failed = [e for e in _audit(c) if e.outcome == "FAILED"]
    assert failed[-1].error_code == ProviderErrorCode.UNAVAILABLE.value
    assert "503" in (failed[-1].result or "")


def test_non_retryable_auth_failure_not_retried(tmp_path):
    provider = AuthBouncer()
    c = make_container(tmp_path, providers=[provider])
    _no_backoff(c)

    resp = _request(c, action("stub.noop"))
    assert resp.status == "failed"
    assert provider.calls == 1

    failed = [e for e in _audit(c) if e.outcome == "FAILED"]
    assert failed[-1].error_code == ProviderErrorCode.AUTH.value


def test_authorization_committed_before_every_retry_attempt(tmp_path):
    observations: list[list[str]] = []

    class ObservedRetry:
        id = "observed-retry"
        action_types = frozenset({"stub.noop"})

        def __init__(self):
            self.calls = 0

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            self.calls += 1
            with transaction(c.session_factory) as session:
                outcomes = [e.outcome for e in c.audit_service.list(session)]
            observations.append(outcomes)
            if self.calls < 2:
                raise ToolError("retry me", code=ProviderErrorCode.UNAVAILABLE)
            return ActionResult(success=True)

    c = make_container(tmp_path, providers=[ObservedRetry()])
    _no_backoff(c)

    resp = _request(c, action("stub.noop"))
    assert resp.status == "executed"
    for outcomes in observations:
        # Authorization is durably visible before the FIRST attempt and stays
        # visible for every retry — retrying can never bypass authorization,
        # and retries must not re-authorize (exactly one AUTHORIZED record).
        assert Outcome.AUTHORIZED.value in outcomes
        assert outcomes.count(Outcome.AUTHORIZED.value) == 1


# ---------------------------------------------------------------------------
# circuit breaker integration
# ---------------------------------------------------------------------------

def test_circuit_opens_and_blocks_dispatch(tmp_path):
    provider = AlwaysDown()
    c = make_container(tmp_path, providers=[provider])
    _no_backoff(c, max_attempts=1)
    reg = _breaker_registry(c, threshold=2, cooldown=999.0)

    r1 = _request(c, action("stub.noop"))
    assert r1.status == "failed"
    assert provider.calls == 1

    r2 = _request(c, action("stub.noop"))
    assert r2.status == "failed"
    assert provider.calls == 2
    assert reg.get("always-down").state.value == "OPEN"

    r3 = _request(c, action("stub.noop"))
    assert r3.status == "failed"
    assert provider.calls == 2  # OPEN blocked dispatch: no execute happened
    assert "circuit open" in (r3.message or "")
    assert r3.decision == Decision.ALLOW  # authorized, then reliability-blocked

    failed = [e for e in _audit(c) if e.outcome == "FAILED"]
    assert failed[-1].error_code == ProviderErrorCode.UNAVAILABLE.value


def test_cooldown_probe_success_closes_circuit(tmp_path):
    provider = FlakyOnce()
    c = make_container(tmp_path, providers=[provider])
    _no_backoff(c, max_attempts=1)
    clock = Clock()
    reg = _breaker_registry(c, threshold=1, cooldown=10.0, clock=clock)
    breaker = reg.get("flaky-once")

    r1 = _request(c, action("stub.noop"))  # fails once -> circuit opens
    assert r1.status == "failed"
    assert breaker.state.value == "OPEN"
    assert provider.calls == 1

    r2 = _request(c, action("stub.noop"))  # blocked inside cooldown
    assert r2.status == "failed"
    assert provider.calls == 1

    clock.advance(10.0)
    r3 = _request(c, action("stub.noop"))  # HALF_OPEN probe -> provider healthy
    assert r3.status == "executed"
    assert provider.calls == 2
    assert breaker.state.value == "CLOSED"

    r4 = _request(c, action("stub.noop"))  # fully operational again
    assert r4.status == "executed"
    assert provider.calls == 3


def test_failed_probe_reopens_circuit(tmp_path):
    provider = AlwaysDown()
    c = make_container(tmp_path, providers=[provider])
    _no_backoff(c, max_attempts=1)
    clock = Clock()
    reg = _breaker_registry(c, threshold=1, cooldown=10.0, clock=clock)
    breaker = reg.get("always-down")

    _request(c, action("stub.noop"))  # opens
    assert breaker.state.value == "OPEN"

    clock.advance(10.0)
    r2 = _request(c, action("stub.noop"))  # probe fails -> reopens
    assert r2.status == "failed"
    assert breaker.state.value == "OPEN"
    assert provider.calls == 2

    r3 = _request(c, action("stub.noop"))  # blocked again
    assert r3.status == "failed"
    assert provider.calls == 2


def test_provider_auth_and_forbidden_never_trip_breaker(tmp_path):
    class ForbiddenErr:
        id = "forbidden-err"
        action_types = frozenset({"stub.noop"})

        def __init__(self):
            self.calls = 0

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            self.calls += 1
            raise ToolError("target disallowed", code=ProviderErrorCode.FORBIDDEN)

    c = make_container(tmp_path, providers=[ForbiddenErr()])
    _no_backoff(c, max_attempts=1)
    reg = _breaker_registry(c, threshold=2, cooldown=999.0)
    breaker = reg.get("forbidden-err")

    for _ in range(5):  # far beyond the threshold
        resp = _request(c, action("stub.noop"))
        assert resp.status == "failed"
        assert resp.message == "target disallowed"  # provider code preserved

    # Provider-level FORBIDDEN is recorded as a real failure but must never be
    # converted into circuit-breaker behavior.
    assert breaker.state.value == "CLOSED"
    assert breaker.consecutive_failures == 0


def test_forbidden_never_dispatches_with_open_circuit(tmp_path):
    class ForbiddenCapable:
        id = "forbidden-capable"
        action_types = frozenset({"secret.export"})

        def __init__(self):
            self.calls = 0

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            self.calls += 1
            return ActionResult(success=True)

    provider = ForbiddenCapable()
    c = make_container(tmp_path, providers=[provider])
    _no_backoff(c, max_attempts=1)
    reg = _breaker_registry(c, threshold=1, cooldown=999.0)
    c.permission_engine.evaluate = lambda a, policy: Decision.ALLOW  # hostile engine

    # Force the provider's circuit OPEN — dispatch would be blocked if reached.
    reg.get("forbidden-capable").record_failure(ProviderErrorCode.UNAVAILABLE)

    resp = _request(c, action("secret.export"))
    assert resp.status == "denied"
    assert resp.decision == Decision.DENY
    assert provider.calls == 0
    # The DENY path never consulted the breaker (state untouched).
    assert reg.get("forbidden-capable").state.value == "OPEN"


def test_circuit_open_does_not_shortcircuit_policy_deny(tmp_path):
    provider = AlwaysDown()
    c = make_container(tmp_path, providers=[provider])
    _no_backoff(c, max_attempts=1)
    reg = _breaker_registry(c, threshold=1, cooldown=999.0)

    _request(c, action("stub.noop"))  # opens the circuit
    assert reg.get("always-down").state.value == "OPEN"

    c.permission_engine.evaluate = lambda a, policy: Decision.DENY
    resp = _request(c, action("stub.noop"))
    assert resp.status == "denied"
    assert resp.decision == Decision.DENY
    assert provider.calls == 1  # no dispatch beyond the first request

    # The deny was recorded; no AUTHORIZED/FAILED pair was appended for it.
    entries = _audit(c)
    assert entries[-1].outcome == Outcome.DENIED_BY_POLICY.value


def test_circuit_open_still_records_authorization_before_block(tmp_path):
    provider = AlwaysDown()
    c = make_container(tmp_path, providers=[provider])
    _no_backoff(c, max_attempts=1)
    reg = _breaker_registry(c, threshold=1, cooldown=999.0)

    _request(c, action("stub.noop"))  # open
    assert reg.get("always-down").state.value == "OPEN"

    r2 = _request(c, action("stub.noop"))  # blocked by the circuit
    assert r2.status == "failed"

    entries = _audit(c)
    tail = [e.outcome for e in entries[-2:]]
    assert tail == ["AUTHORIZED", "FAILED"]  # audit-before-(non)dispatch

    with transaction(c.session_factory) as session:
        verify = c.audit_service.verify(session)
    assert verify.valid is True  # hash chain intact with the reliability events


def test_circuit_breaker_cannot_bypass_confirmation_authorization(tmp_path):
    class DownEmail:
        id = "down-email"
        action_types = frozenset({"email.send"})

        def __init__(self):
            self.calls = 0

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            self.calls += 1
            raise ToolError("email down", code=ProviderErrorCode.UNAVAILABLE)

    provider = DownEmail()
    c = make_container(tmp_path, providers=[provider])
    _no_backoff(c, max_attempts=1)
    _breaker_registry(c, threshold=1, cooldown=999.0)

    a = action("email.send", to="x@example.com")
    pending = _request(c, a)
    assert pending.status == "confirmation_required"

    done = c.execution_service.approve(pending.confirmation_id, a, ExecutionContext(actor_id="t"))
    assert done.status == "failed"  # first dispatch fails -> circuit opens
    assert provider.calls == 1

    pending2 = _request(c, a)
    assert pending2.status == "confirmation_required"
    blocked = c.execution_service.approve(
        pending2.confirmation_id, a, ExecutionContext(actor_id="t"),
    )
    assert blocked.status == "failed"
    assert provider.calls == 1  # OPEN blocked the approve-path dispatch

    email_entries = [e for e in _audit(c) if e.action_type == "email.send"]
    # Every dispatch phase (including the blocked one) was preceded by a
    # durably-recorded authorization.
    assert email_entries[-2].outcome == Outcome.AUTHORIZED.value
    assert email_entries[-1].outcome == Outcome.FAILED.value
    assert email_entries[-1].error_code == ProviderErrorCode.UNAVAILABLE.value


# ---------------------------------------------------------------------------
# timeout / deadline interplay
# ---------------------------------------------------------------------------

def test_timeout_bounded_and_never_retried(tmp_path):
    class SlowDown:
        id = "slow-down"
        action_types = frozenset({"stub.noop"})

        def __init__(self):
            self.starts = 0

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            self.starts += 1
            time.sleep(1.0)
            return ActionResult(success=True)

    provider = SlowDown()
    c = make_container(tmp_path, providers=[provider])
    c.execution_service.retry_policy = RetryPolicy(max_attempts=5, base_backoff_seconds=0.05)
    c.execution_service.settings.provider_timeout_seconds = 0.05

    start = time.monotonic()
    resp = _request(c, action("stub.noop"))
    elapsed = time.monotonic() - start

    assert resp.status == "failed"
    assert elapsed < 0.8  # returned promptly, not after the full sleep
    assert provider.starts == 1  # TIMEOUT is never retried -> no retry loop

    failed = [e for e in _audit(c) if e.outcome == "FAILED"]
    assert failed[-1].error_code == ProviderErrorCode.TIMEOUT.value


def test_retry_cannot_bypass_dispatch_deadline(tmp_path):
    provider = AlwaysDown()
    c = make_container(tmp_path, providers=[provider])
    # Backoff (0.5s) is larger than the remaining dispatch budget, so the retry
    # layer must give up with TIMEOUT instead of sleeping past the deadline.
    c.execution_service.retry_policy = RetryPolicy(
        max_attempts=10, base_backoff_seconds=0.5,
        max_backoff_seconds=0.5, backoff_factor=1.0,
    )
    c.execution_service.settings.provider_timeout_seconds = 0.2

    start = time.monotonic()
    resp = _request(c, action("stub.noop"))
    elapsed = time.monotonic() - start

    assert resp.status == "failed"
    assert provider.calls == 1  # the too-long backoff was never taken
    assert elapsed < 0.5  # did not sleep past the deadline

    failed = [e for e in _audit(c) if e.outcome == "FAILED"]
    assert failed[-1].error_code == ProviderErrorCode.TIMEOUT.value


def test_timeout_failures_do_not_trip_circuit_breaker(tmp_path):
    class SlowDown:
        id = "slow-down-2"
        action_types = frozenset({"stub.noop"})

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            time.sleep(1.0)
            return ActionResult(success=True)

    c = make_container(tmp_path, providers=[SlowDown()])
    _no_backoff(c, max_attempts=1)
    reg = _breaker_registry(c, threshold=2, cooldown=999.0)
    c.execution_service.settings.provider_timeout_seconds = 0.05

    for _ in range(3):  # 3 timeout failures would exceed a threshold of 2
        resp = _request(c, action("stub.noop"))
        assert resp.status == "failed"

    # TIMEOUT is not a breaker-eligible code: repeated timeouts never open the
    # circuit (dispatch is bounded by the hard timeout instead).
    assert reg.get("slow-down-2").state.value == "CLOSED"


# ---------------------------------------------------------------------------
# audit correctness & secrets
# ---------------------------------------------------------------------------

def test_audit_records_single_authorized_and_failed_for_retry(tmp_path):
    provider = AlwaysDown()
    c = make_container(tmp_path, providers=[provider])
    _no_backoff(c)

    resp = _request(c, action("stub.noop"))
    assert resp.status == "failed"

    entries = [e for e in _audit(c) if e.action_type == "stub.noop"]
    assert [e.outcome for e in entries] == ["AUTHORIZED", "FAILED"]
    assert entries[-1].error_code == ProviderErrorCode.UNAVAILABLE.value
    assert entries[-1].provider_id == "always-down"


def test_no_secret_leakage_in_retry_surface(tmp_path):
    class SecretDown:
        id = "secret-down"
        action_types = frozenset({"web.search"})

        def __init__(self):
            self.calls = 0

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            self.calls += 1
            raise ToolError("vendor outage (sk-SUPERSECRET-777)",
                            code=ProviderErrorCode.UNAVAILABLE)

    c = make_container(tmp_path, providers=[SecretDown()])
    # Backoff larger than the dispatch budget -> the retry layer's own TIMEOUT
    # message is what surfaces (it is service-generated and must not echo the
    # provider error or any params).
    c.execution_service.retry_policy = RetryPolicy(
        max_attempts=10, base_backoff_seconds=1.0,
        max_backoff_seconds=1.0, backoff_factor=1.0,
    )
    c.execution_service.settings.provider_timeout_seconds = 0.05

    resp = _request(c, action("web.search", query="q", api_key="sk-LEAK-123"))
    assert resp.status == "failed"

    # Action-param secrets remain redacted in every audit entry.
    for e in _audit(c, action_type="web.search"):
        assert e.action_params.get("api_key") == REDACTED
        assert "sk-LEAK-123" not in str(e.action_params)
    # The retry layer's synthetic message must not echo the provider's error
    # text (which contains a secret) nor any params.
    assert "sk-SUPERSECRET-777" not in (resp.message or "")
    assert "sk-LEAK-123" not in (resp.message or "")
    failed = [e for e in _audit(c) if e.outcome == "FAILED"]
    assert "sk-SUPERSECRET-777" not in (failed[-1].result or "")
    assert "sk-LEAK-123" not in (failed[-1].result or "")
    assert failed[-1].error_code == ProviderErrorCode.TIMEOUT.value


def test_no_secret_leakage_in_circuit_open_surface(tmp_path):
    class WebSearchDown(AlwaysDown):
        id = "web-search-down"
        action_types = frozenset({"web.search"})

    c = make_container(tmp_path, providers=[WebSearchDown()])
    _no_backoff(c, max_attempts=1)
    reg = _breaker_registry(c, threshold=1, cooldown=999.0)

    _request(c, action("web.search", query="q", api_key="sk-LEAK-123"))  # opens
    assert reg.get("web-search-down").state.value == "OPEN"

    resp = _request(c, action("web.search", query="q", api_key="sk-LEAK-123"))
    assert resp.status == "failed"
    assert "sk-LEAK-123" not in (resp.message or "")
    assert "sk-LEAK-123" not in resp.model_dump_json()

    for e in _audit(c, action_type="web.search"):
        assert e.action_params.get("api_key") == REDACTED
        assert "sk-LEAK-123" not in str(e.action_params)
    failed = [e for e in _audit(c) if e.outcome == "FAILED"]
    assert failed[-1].error_code == ProviderErrorCode.UNAVAILABLE.value
    assert "sk-LEAK-123" not in (failed[-1].result or "")
