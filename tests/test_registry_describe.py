"""Phase 1E: ToolRegistry provider lookup, de-duplication and introspection."""

from __future__ import annotations

import pytest

from era.core.result import ActionResult
from era.core.tool_registry import ToolRegistry
from era.providers import StubProvider


class AlphaProvider:
    id = "alpha"
    action_types = frozenset({"web.search"})

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        return ActionResult(success=True)


class BetaProvider:
    id = "beta"
    action_types = frozenset({"web.fetch"})

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        return ActionResult(success=True)


def test_register_and_lookup_by_action_type_and_id():
    reg = ToolRegistry()
    reg.register(AlphaProvider())
    assert reg.get("web.search").id == "alpha"
    assert reg.get_provider("alpha") is not None
    assert reg.get_provider("nope") is None
    assert reg.describe("web.search").id == "alpha"


def test_provider_ids_property():
    reg = ToolRegistry()
    reg.register(AlphaProvider())
    reg.register(BetaProvider())
    assert reg.provider_ids == frozenset({"alpha", "beta"})


def test_describe_all_dedupes_by_provider_id():
    reg = ToolRegistry()
    reg.register(AlphaProvider())
    reg.register(BetaProvider())
    infos = reg.describe_all()
    ids = {i.id for i in infos}
    assert ids == {"alpha", "beta"}
    assert len(infos) == 2


def test_describe_unknown_action_returns_none():
    reg = ToolRegistry()
    assert reg.describe("nope.action") is None


def test_duplicate_provider_id_rejected():
    reg = ToolRegistry()
    reg.register(AlphaProvider())
    with pytest.raises(ValueError):
        reg.register(AlphaProvider())


def test_list_providers_returns_instances():
    reg = ToolRegistry()
    a = AlphaProvider()
    reg.register(a)
    listed = reg.list_providers()
    assert listed == [a]


def test_stub_registers_and_describes():
    reg = ToolRegistry()
    reg.register(StubProvider())
    info = reg.describe("stub.noop")
    assert info.id == "stub"
    assert info.is_stub is True
