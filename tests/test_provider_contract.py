"""StubProvider satisfies the reusable ToolProvider contract."""

from __future__ import annotations

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ActionResult, ToolError
from era.providers.stub import StubProvider
from era.registry.actions import ActionType
from tests.provider_contract import assert_provider_contract


def test_stub_provider_contract():
    assert_provider_contract(StubProvider())


def test_stub_covers_full_catalog():
    stub = StubProvider()
    assert stub.action_types == frozenset(a.value for a in ActionType)
    for action_type in stub.action_types:
        assert_provider_contract(stub, sample_action=Action(action_type=action_type))


def test_stub_is_offline_noop():
    stub = StubProvider()
    result = stub.execute(Action(action_type="email.send"), ExecutionContext(actor_id="t"))
    assert isinstance(result, ActionResult)
    assert result.success is True
    assert result.data.get("provider") == "stub"


class _BrokenValidate:
    id = "broken-validate"
    action_types = frozenset({"stub.noop"})

    def validate(self, action):
        raise RuntimeError("not a ToolError")

    def execute(self, action, ctx):
        return ActionResult(success=True)


def test_contract_rejects_non_toolerror_validate():
    try:
        assert_provider_contract(_BrokenValidate())
    except AssertionError:
        return
    except RuntimeError:
        return
    raise AssertionError("contract should not accept arbitrary validate errors")


class _Leaking:
    id = "leaker"
    action_types = frozenset({"stub.noop"})

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        return ActionResult(success=True, summary="ok", data={"token": "sk-LEAK"})


def test_contract_rejects_secret_leak():
    try:
        assert_provider_contract(_Leaking())
        raise AssertionError("leaking provider must fail the contract")
    except AssertionError as exc:
        assert "sk-" in str(exc) or "secret" in str(exc).lower() or "fragment" in str(exc)


def test_toolerror_is_valid_execute_outcome():
    class Fails:
        id = "fails"
        action_types = frozenset({"stub.noop"})

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            raise ToolError("offline")

    assert_provider_contract(Fails())
