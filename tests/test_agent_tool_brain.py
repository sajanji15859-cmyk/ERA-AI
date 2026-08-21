"""ToolCallBrain tests — native function calling, validation, guards (3B)."""

from __future__ import annotations

import pytest

from era.agents.budget import AgentBudget
from era.agents.memory import ShortTermMemory
from era.agents.models import Task
from era.agents.tool_brain import ToolCallBrain
from era.agents.tool_schema import build_tools_json
from era.core.llm import LLMRequest, LLMResponse, ToolCall
from era.core.tool_registry import ToolRegistry
from era.providers.stub import StubProvider
from era.providers.web import WebProvider
from era.providers.workspace import WorkspaceProvider
from era.registry.actions import ACTION_CATALOG


class _FakeLLM:
    model = "gpt-4o-mini"

    def __init__(self, tool_calls=None, text=""):
        self._tool_calls = tool_calls or []
        self._text = text
        self.calls: list[LLMRequest] = []

    def complete(self, req: LLMRequest) -> LLMResponse:
        self.calls.append(req)
        return LLMResponse(text=self._text, tool_calls=list(self._tool_calls),
                           usage={"prompt_tokens": 100, "completion_tokens": 50,
                                  "total_tokens": 150})

    def stream(self, req):
        yield self.complete(req)


@pytest.fixture
def catalog_and_registry(tmp_path):
    registry = ToolRegistry()
    registry.register(WorkspaceProvider(root=tmp_path / "ws"))
    registry.register(WebProvider(workspace_root=tmp_path / "ws", timeout_seconds=2.0))
    claimed = frozenset({a for p in registry.list_providers() for a in p.action_types})
    registry.register(StubProvider(exclude=claimed))
    return ACTION_CATALOG, registry


def _brain(llm, catalog, registry, *, allowed=None):
    return ToolCallBrain(llm, AgentBudget(), catalog=catalog, registry=registry,
                         allowed=allowed)


def _task(**kw):
    return Task(id="t1", title="write a file", action_type="fs.write",
                params={"path": "site/a.html"}, **kw)


def test_valid_proposal_is_used(catalog_and_registry):
    catalog, registry = catalog_and_registry
    llm = _FakeLLM(tool_calls=[ToolCall(id="c1", action_type="fs.read",
                                        params={"path": "site/a.html"})])
    brain = _brain(llm, catalog, registry)
    calls = brain.propose_tool_calls(_task(), ShortTermMemory(goal="g"),
                                     {"path": "site/a.html", "content": "x"})
    assert [c.action_type for c in calls] == ["fs.read"]


def test_unknown_action_rejected_and_fallback(catalog_and_registry):
    catalog, registry = catalog_and_registry
    llm = _FakeLLM(tool_calls=[ToolCall(id="c1", action_type="hack.the.planet",
                                        params={})])
    brain = _brain(llm, catalog, registry)
    calls = brain.propose_tool_calls(_task(), ShortTermMemory(goal="g"),
                                     {"path": "site/a.html", "content": "x"})
    assert calls and calls[0].action_type == "fs.write"  # planned fallback


def test_unregistered_catalogued_action_rejected(catalog_and_registry):
    catalog, _registry = catalog_and_registry
    # email.send is catalogued but has no registered provider in this fixture
    # (the stub withdrew fs/web only; actually stub still claims email.send).
    # Construct a registry where email.send has no provider:
    bare = ToolRegistry()
    bare.register(WorkspaceProvider(root="/tmp/nonexistent-ws"))
    llm = _FakeLLM(tool_calls=[ToolCall(id="c1", action_type="email.send",
                                        params={"to": "a@b.c"})])
    brain = _brain(llm, catalog, bare)
    calls = brain.propose_tool_calls(_task(), ShortTermMemory(goal="g"),
                                     {"path": "x", "content": "y"})
    assert calls and calls[0].action_type == "fs.write"  # fallback, never email.send


def test_forbidden_action_never_proposed_or_offered(catalog_and_registry):
    catalog, registry = catalog_and_registry
    llm = _FakeLLM(tool_calls=[ToolCall(id="c1", action_type="secret.export",
                                        params={})])
    brain = _brain(llm, catalog, registry)
    calls = brain.propose_tool_calls(_task(), ShortTermMemory(goal="g"),
                                     {"path": "x", "content": "y"})
    assert all(c.action_type != "secret.export" for c in calls)
    tools = build_tools_json(catalog, registry)
    names = {t["function"]["name"] for t in tools}
    assert "secret.export" not in names
    assert "account.delete" not in names


def test_domain_guard_filters_offered_tools(catalog_and_registry):
    catalog, registry = catalog_and_registry
    from era.security.rbac import role_domain_allowed
    user_guard = lambda a: role_domain_allowed("user",
                                               catalog.get(a).capability_domain if catalog.get(a) else None)
    tools = build_tools_json(catalog, registry, allowed=user_guard)
    names = {t["function"]["name"] for t in tools}
    assert "device.shell" not in names  # device.* is admin-only
    assert "fs.write" in names


def test_guard_rejects_model_call_to_blocked_domain(catalog_and_registry):
    catalog, registry = catalog_and_registry
    from era.security.rbac import role_domain_allowed

    def user_guard(a):
        spec = catalog.get(a)
        return spec is not None and role_domain_allowed("user", spec.capability_domain)

    llm = _FakeLLM(tool_calls=[ToolCall(id="c1", action_type="device.shell",
                                        params={"cmd": "rm -rf /"})])
    brain = _brain(llm, catalog, registry, allowed=user_guard)
    calls = brain.propose_tool_calls(_task(), ShortTermMemory(goal="g"),
                                     {"path": "x", "content": "y"})
    assert all(c.action_type != "device.shell" for c in calls)


def test_oversized_params_rejected(catalog_and_registry):
    # Content-bearing actions allow up to MAX_CONTENT_LEN; beyond that the
    # proposal is rejected and the planned params are used instead.
    from era.security.validation import MAX_CONTENT_LEN
    catalog, registry = catalog_and_registry
    llm = _FakeLLM(tool_calls=[ToolCall(id="c1", action_type="fs.write",
                                        params={"path": "x",
                                                "content": "z" * (MAX_CONTENT_LEN + 100)})])
    brain = _brain(llm, catalog, registry)
    calls = brain.propose_tool_calls(_task(), ShortTermMemory(goal="g"),
                                     {"path": "x", "content": "planned"})
    assert calls and calls[0].params["content"] == "planned"  # fallback params


def test_content_injected_when_model_omits_it(catalog_and_registry):
    catalog, registry = catalog_and_registry
    llm = _FakeLLM(tool_calls=[ToolCall(id="c1", action_type="fs.write",
                                        params={"path": "site/a.html"})])
    brain = _brain(llm, catalog, registry)
    calls = brain.propose_tool_calls(_task(), ShortTermMemory(goal="g"),
                                     {"path": "site/a.html", "content": "RENDERED"})
    assert calls and calls[0].params["content"] == "RENDERED"


def test_llm_failure_falls_back_and_budget_recorded(catalog_and_registry):
    catalog, registry = catalog_and_registry

    class Broken:
        model = "gpt-4o-mini"

        def complete(self, req):
            raise RuntimeError("down")

        def stream(self, req):
            yield self.complete(req)

    budget = AgentBudget()
    brain = ToolCallBrain(Broken(), budget, catalog=catalog, registry=registry)
    calls = brain.propose_tool_calls(_task(), ShortTermMemory(goal="g"),
                                     {"path": "x", "content": "y"})
    assert calls and calls[0].action_type == "fs.write"
    assert budget.llm_calls == 0  # failed call not charged


def test_tool_schema_shape(tmp_path):
    catalog = ACTION_CATALOG
    registry = ToolRegistry()
    registry.register(WorkspaceProvider(root=tmp_path / "ws"))
    registry.register(WebProvider(workspace_root=tmp_path / "ws", timeout_seconds=2.0))
    tools = build_tools_json(catalog, registry)
    by_name = {t["function"]["name"]: t for t in tools}
    assert by_name["fs.write"]["function"]["parameters"]["required"] == ["path", "content"]
    assert by_name["web.search"]["function"]["parameters"]["required"] == ["q"]
    assert all(t["type"] == "function" for t in tools)
