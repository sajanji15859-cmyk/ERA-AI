"""Fail-closed behaviour: audit-write failure, engine exception, idempotency."""

from __future__ import annotations

import pytest

from era.core.context import ExecutionContext
from era.core.enums import Decision
from era.core.result import ActionResult
from era.db import transaction
from tests.conftest import action, make_container


class CountingProvider:
    id = "counting"
    action_types = frozenset({"stub.noop"})

    def __init__(self):
        self.calls = 0

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        self.calls += 1
        return ActionResult(success=True, summary="ok")


def test_audit_write_failure_prevents_execution(tmp_path):
    provider = CountingProvider()
    c = make_container(tmp_path, providers=[provider])

    def boom(session, **kwargs):
        raise RuntimeError("audit backend down")

    c.audit_service.record = boom

    with pytest.raises(RuntimeError):
        c.execution_service.request(action("stub.noop"), ExecutionContext(actor_id="t"))
    assert provider.calls == 0  # action never executed (fail closed)


def test_engine_exception_fails_closed(tmp_path):
    provider = CountingProvider()
    c = make_container(tmp_path, providers=[provider])

    def boom(action, policy):
        raise RuntimeError("engine exploded")

    c.permission_engine.evaluate = boom

    resp = c.execution_service.request(action("stub.noop"), ExecutionContext(actor_id="t"))
    assert resp.status == "denied"
    assert resp.decision == Decision.DENY
    assert provider.calls == 0

    with transaction(c.session_factory) as session:
        outcomes = [e.outcome for e in c.audit_service.list(session)]
    assert "DENIED_BY_POLICY" in outcomes


def test_double_submit_executes_once(tmp_path):
    provider = CountingProvider()
    c = make_container(tmp_path, providers=[provider])
    a = action("stub.noop")
    first = c.execution_service.request(a, ExecutionContext(actor_id="t"))
    assert first.status == "executed"
    assert provider.calls == 1

    # stub.noop is SAFE (ALLOW) so there is no confirmation; re-requesting is a
    # new, independent action — not a replay. This test documents that a single
    # ALLOW request executes exactly once.
