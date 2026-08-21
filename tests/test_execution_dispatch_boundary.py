"""Phase 1E: execution-service/provider dispatch boundary and error propagation.

These tests lock the invariant that:
* authorization is durably recorded BEFORE dispatch (audit-before-execute);
* a provider result/failure/timeout is recorded AFTER dispatch with a stable
  ProviderErrorCode;
* providers are only ever reached through ExecutionService, never directly by
  routes/agent;
* FORBIDDEN actions never dispatch, regardless of engine/confirmation state.
"""

from __future__ import annotations

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import Decision, Outcome
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.db import transaction
from tests.conftest import make_container


class AuthFailProvider:
    id = "auth-fail"
    action_types = frozenset({"stub.noop"})

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        raise ToolError("bad credential ref", code=ProviderErrorCode.AUTH)


class ValidationFailProvider:
    id = "val-fail"
    action_types = frozenset({"stub.noop"})

    def validate(self, action):
        raise ToolError("missing url", code=ProviderErrorCode.VALIDATION)

    def execute(self, action, ctx):
        raise AssertionError("must not execute")


class UnavailableProvider:
    id = "down"
    action_types = frozenset({"stub.noop"})

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        raise ToolError("503", code=ProviderErrorCode.UNAVAILABLE)


class BuggyProvider:
    id = "buggy"
    action_types = frozenset({"stub.noop"})

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        raise RuntimeError("not a ToolError")


def _outcomes(c):
    with transaction(c.session_factory) as session:
        return [e.outcome for e in c.audit_service.list(session)]


def test_authorization_recorded_before_dispatch(tmp_path):
    order: list[str] = []

    class OrderedProvider:
        id = "ordered"
        action_types = frozenset({"stub.noop"})

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            # At the moment the provider runs, the AUTHORIZED record must
            # already be committed and visible.
            with transaction(c.session_factory) as session:
                outcomes = [e.outcome for e in c.audit_service.list(session)]
            order.extend(outcomes)
            return ActionResult(success=True, summary="ok")

    c = make_container(tmp_path, providers=[OrderedProvider()])
    resp = c.execution_service.request(
        Action(action_type="stub.noop"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "executed"
    assert Outcome.AUTHORIZED.value in order, (
        "AUTHORIZED must be committed before the provider executes"
    )


def test_provider_auth_failure_recorded_with_code(tmp_path):
    c = make_container(tmp_path, providers=[AuthFailProvider()])
    resp = c.execution_service.request(
        Action(action_type="stub.noop"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "failed"
    with transaction(c.session_factory) as session:
        failed = [e for e in c.audit_service.list(session) if e.outcome == "FAILED"]
    assert failed
    assert failed[-1].error_code == ProviderErrorCode.AUTH.value
    assert failed[-1].provider_id == "auth-fail"


def test_validation_rejection_recorded_with_code(tmp_path):
    c = make_container(tmp_path, providers=[ValidationFailProvider()])
    resp = c.execution_service.request(
        Action(action_type="stub.noop"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "rejected"
    with transaction(c.session_factory) as session:
        rejected = [e for e in c.audit_service.list(session) if e.outcome == "REJECTED"]
    assert rejected
    assert rejected[-1].error_code == ProviderErrorCode.VALIDATION.value


def test_unavailable_provider_code_propagates(tmp_path):
    c = make_container(tmp_path, providers=[UnavailableProvider()])
    c.execution_service.request(
        Action(action_type="stub.noop"), ExecutionContext(actor_id="t"),
    )
    with transaction(c.session_factory) as session:
        failed = [e for e in c.audit_service.list(session) if e.outcome == "FAILED"]
    assert failed[-1].error_code == ProviderErrorCode.UNAVAILABLE.value


def test_buggy_provider_mapped_to_internal(tmp_path):
    c = make_container(tmp_path, providers=[BuggyProvider()])
    resp = c.execution_service.request(
        Action(action_type="stub.noop"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "failed"
    with transaction(c.session_factory) as session:
        failed = [e for e in c.audit_service.list(session) if e.outcome == "FAILED"]
    assert failed[-1].error_code == ProviderErrorCode.INTERNAL.value


def test_no_provider_is_not_implemented(tmp_path):
    c = make_container(tmp_path, providers=[])
    resp = c.execution_service.request(
        Action(action_type="stub.noop"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "rejected"
    with transaction(c.session_factory) as session:
        rejected = [e for e in c.audit_service.list(session) if e.outcome == "REJECTED"]
    assert rejected[-1].error_code == ProviderErrorCode.NOT_IMPLEMENTED.value


def test_success_has_no_error_code(tmp_path):
    c = make_container(tmp_path)
    c.execution_service.request(
        Action(action_type="stub.noop"), ExecutionContext(actor_id="t"),
    )
    with transaction(c.session_factory) as session:
        executed = [e for e in c.audit_service.list(session) if e.outcome == "EXECUTED"]
    assert executed
    assert executed[-1].error_code is None


def test_forbidden_never_dispatches_even_with_registered_provider(tmp_path):
    class ForbiddenCapable:
        id = "fc"
        action_types = frozenset({"secret.export"})
        calls = 0

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            ForbiddenCapable.calls += 1
            return ActionResult(success=True)

    c = make_container(tmp_path, providers=[ForbiddenCapable()])
    c.permission_engine.evaluate = lambda action, policy: Decision.ALLOW
    resp = c.execution_service.request(
        Action(action_type="secret.export"), ExecutionContext(actor_id="t"),
    )
    assert resp.status == "denied"
    assert resp.decision == Decision.DENY
    assert ForbiddenCapable.calls == 0


def test_confirmation_approved_then_authorized_before_execute(tmp_path):
    class Probe:
        id = "probe"
        action_types = frozenset({"email.send"})

        def __init__(self):
            self.saw_authorized = False

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            with transaction(c.session_factory) as session:
                outcomes = [e.outcome for e in c.audit_service.list(session)]
            self.saw_authorized = Outcome.AUTHORIZED.value in outcomes
            return ActionResult(success=True, summary="sent")

    provider = Probe()
    c = make_container(tmp_path, providers=[provider])
    a = Action(action_type="email.send", params={"to": "a@x.com"})
    pending = c.execution_service.request(a, ExecutionContext(actor_id="t"))
    assert pending.status == "confirmation_required"

    done = c.execution_service.approve(
        pending.confirmation_id, a, ExecutionContext(actor_id="t"),
    )
    assert done.status == "executed"
    assert provider.saw_authorized is True
