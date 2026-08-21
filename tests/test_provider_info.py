"""Phase 1E: ProviderInfo / describe_provider introspection."""

from __future__ import annotations

from era.core.provider_info import ProviderInfo, describe_provider
from era.core.tool_provider import ToolProvider
from era.providers import MockLLMProvider, StubProvider
from era.registry.actions import ActionType


def test_describe_stub_provider():
    info = describe_provider(StubProvider())
    assert isinstance(info, ProviderInfo)
    assert info.id == "stub"
    assert info.is_stub is True
    assert info.action_types == frozenset(a.value for a in ActionType)
    assert info.version == "0.1.0"
    assert "noop" in info.capabilities
    # Metadata must never carry secrets.
    blob = repr(info)
    assert "sk-" not in blob
    assert "token" not in blob.lower()


def test_describe_mock_llm():
    info = describe_provider(MockLLMProvider())
    assert info.id == "mock"
    assert info.is_stub is True
    assert info.action_types == frozenset()


def test_describe_legacy_provider_without_describe_method():
    class Legacy:
        id = "legacy"
        action_types = frozenset({"stub.noop"})

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            return None

    info = describe_provider(Legacy())
    assert info.id == "legacy"
    assert info.action_types == frozenset({"stub.noop"})
    assert info.version == "unknown"
    assert info.is_stub is False


def test_describe_accepts_dict_return():
    class DictDescriber:
        id = "dd"
        action_types = frozenset({"stub.noop"})

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            return None

        def describe(self):
            return {"id": "dd", "version": "9.9", "is_stub": False,
                    "capabilities": ["x"], "display_name": "Dict"}

    info = describe_provider(DictDescriber())
    assert info.version == "9.9"
    assert info.display_name == "Dict"
    assert info.capabilities == ("x",)


def test_describe_survives_buggy_describe():
    class Buggy:
        id = "buggy"
        action_types = frozenset({"stub.noop"})

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            return None

        def describe(self):
            raise RuntimeError("kaboom")

    info = describe_provider(Buggy())
    assert info.id == "buggy"
    assert info.action_types == frozenset({"stub.noop"})


def test_provider_info_to_dict_is_jsonable():
    d = describe_provider(StubProvider()).to_dict()
    assert d["id"] == "stub"
    assert isinstance(d["action_types"], list)
    assert "stub.noop" in d["action_types"]


def test_stub_satisfies_runtime_protocol_without_describe_required():
    # describe() is optional on the Protocol; isinstance must still pass.
    assert isinstance(StubProvider(), ToolProvider)
