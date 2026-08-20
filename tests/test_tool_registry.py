"""ToolRegistry / SPI: registration, dispatch, unknown/unregistered handling."""

from __future__ import annotations

import pytest

from era.core.context import ExecutionContext
from era.core.result import ActionResult, ToolError
from era.core.tool_registry import ToolRegistry
from era.db import transaction
from tests.conftest import action, make_container


class NoopProvider:
    id = "noop"
    action_types = frozenset({"stub.noop"})

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        return ActionResult(success=True, summary="noop ok")


def test_register_and_get():
    reg = ToolRegistry()
    reg.register(NoopProvider())
    assert reg.get("stub.noop").id == "noop"
    assert reg.get("unknown") is None


def test_duplicate_registration_raises():
    reg = ToolRegistry()
    reg.register(NoopProvider())
    with pytest.raises(ValueError):
        reg.register(NoopProvider())


def test_unknown_action_type_denied(tmp_path):
    c = make_container(tmp_path)
    resp = c.execution_service.request(
        action("mystery.action"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "denied"
    assert resp.decision.value == "DENY"


def test_catalogued_but_unregistered_rejected(tmp_path):
    # No providers registered -> a SAFE action is authorized but then REJECTED.
    c = make_container(tmp_path, providers=[])
    resp = c.execution_service.request(
        action("stub.noop"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "rejected"
    with transaction(c.session_factory) as session:
        outcomes = [e.outcome for e in c.audit_service.list(session)]
    assert "AUTHORIZED" in outcomes
    assert "REJECTED" in outcomes


class ValidateFailProvider:
    id = "validate-fail"
    action_types = frozenset({"stub.noop"})

    def validate(self, action):
        raise ToolError("invalid params")

    def execute(self, action, ctx):
        raise AssertionError("must not execute")


def test_provider_validate_failure_rejected(tmp_path):
    c = make_container(tmp_path, providers=[ValidateFailProvider()])
    resp = c.execution_service.request(
        action("stub.noop"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "rejected"


class RaiseProvider:
    id = "raise"
    action_types = frozenset({"stub.noop"})

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        raise ToolError("boom")


def test_provider_raise_failed(tmp_path):
    c = make_container(tmp_path, providers=[RaiseProvider()])
    resp = c.execution_service.request(
        action("stub.noop"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "failed"


def test_capability_domain_tagged_in_audit(tmp_path):
    c = make_container(tmp_path)
    # device.screenshot is SENSITIVE -> ALLOW by default; executes via stub.
    resp = c.execution_service.request(
        action("device.screenshot"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "executed"
    with transaction(c.session_factory) as session:
        entries = [e for e in c.audit_service.list(session) if e.action_type == "device.screenshot"]
    assert any(e.capability_domain == "device" for e in entries)
