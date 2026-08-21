"""Phase 1E: provider timeout/deadline behavior at the dispatch boundary."""

from __future__ import annotations

import time

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.core.timeout import run_with_timeout
from tests.conftest import make_container


class SlowProvider:
    id = "slow"
    action_types = frozenset({"stub.noop"})

    def __init__(self, delay: float, *, observe_deadline: bool = False):
        self.delay = delay
        self.observe_deadline = observe_deadline
        self.started = False

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        self.started = True
        if self.observe_deadline and ctx.deadline is not None:
            # Cooperative provider: bail early when budget is exhausted.
            remaining = ctx.deadline - time.monotonic()
            if remaining <= 0:
                raise ToolError("cooperative timeout", code=ProviderErrorCode.TIMEOUT)
            time.sleep(min(self.delay, max(remaining, 0)))
            raise ToolError("cooperative timeout", code=ProviderErrorCode.TIMEOUT)
        time.sleep(self.delay)
        return ActionResult(success=True, summary="done")


class SlowValidateProvider:
    id = "slow-validate"
    action_types = frozenset({"stub.noop"})

    def validate(self, action):
        time.sleep(0.5)

    def execute(self, action, ctx):
        raise AssertionError("execute must not run after validate timeout")


def test_run_with_timeout_returns_result_within_budget():
    assert run_with_timeout(lambda: 42, timeout_seconds=1.0) == 42


def test_run_with_timeout_raises_toolerror_on_overrun():
    with pytest.raises(ToolError) as exc:
        run_with_timeout(lambda: time.sleep(1.0), timeout_seconds=0.05)
    assert exc.value.code is ProviderErrorCode.TIMEOUT
    assert "timed out" in str(exc.value)


def test_run_with_timeout_zero_runs_to_completion():
    # 0 / negative disables the hard timeout (stub/test paths).
    assert run_with_timeout(lambda: "ok", timeout_seconds=0) == "ok"


def test_run_with_timeout_preserves_provider_toolerror():
    def boom():
        raise ToolError("auth fail", code=ProviderErrorCode.AUTH, provider_id="web")

    with pytest.raises(ToolError) as exc:
        run_with_timeout(boom, timeout_seconds=1.0, provider_id="web")
    assert exc.value.code is ProviderErrorCode.AUTH


def test_dispatch_enforces_timeout(tmp_path):
    provider = SlowProvider(delay=1.0)
    c = make_container(tmp_path, providers=[provider])
    c.execution_service.settings.provider_timeout_seconds = 0.05

    start = time.monotonic()
    resp = c.execution_service.request(
        Action(action_type="stub.noop"), ExecutionContext(actor_id="t"),
    )
    elapsed = time.monotonic() - start

    assert resp.status == "failed"
    assert resp.decision.value == "ALLOW"
    assert elapsed < 0.9  # returned promptly, not after the full sleep
    assert "timed out" in (resp.message or "")


def test_timeout_recorded_with_error_code_in_audit(tmp_path):
    from era.db import transaction

    c = make_container(tmp_path, providers=[SlowProvider(delay=1.0)])
    c.execution_service.settings.provider_timeout_seconds = 0.05
    c.execution_service.request(Action(action_type="stub.noop"), ExecutionContext(actor_id="t"))

    with transaction(c.session_factory) as session:
        entries = [e for e in c.audit_service.list(session)
                   if e.action_type == "stub.noop" and e.outcome == "FAILED"]
    assert entries, "expected a FAILED audit entry"
    assert entries[-1].error_code == ProviderErrorCode.TIMEOUT.value


def test_validate_timeout_rejected(tmp_path):
    c = make_container(tmp_path, providers=[SlowValidateProvider()])
    c.execution_service.settings.provider_timeout_seconds = 0.05
    resp = c.execution_service.request(
        Action(action_type="stub.noop"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "rejected"


def test_deadline_is_advertised_to_provider(tmp_path):
    seen: dict = {}

    class DeadlineProbe:
        id = "probe"
        action_types = frozenset({"stub.noop"})

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            seen["deadline"] = ctx.deadline
            return ActionResult(success=True, summary="ok")

    c = make_container(tmp_path, providers=[DeadlineProbe()])
    c.execution_service.settings.provider_timeout_seconds = 5.0
    resp = c.execution_service.request(
        Action(action_type="stub.noop"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "executed"
    assert seen["deadline"] is not None
    assert seen["deadline"] > time.monotonic()


def test_explicit_context_deadline_is_not_overwritten(tmp_path):
    seen: dict = {}

    class Probe:
        id = "probe2"
        action_types = frozenset({"stub.noop"})

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            seen["deadline"] = ctx.deadline
            return ActionResult(success=True)

    c = make_container(tmp_path, providers=[Probe()])
    explicit = time.monotonic() + 99.0
    c.execution_service.request(
        Action(action_type="stub.noop"),
        ExecutionContext(actor_id="t", deadline=explicit),
    )
    assert seen["deadline"] == explicit
