"""Abstract agent/LLM interface: model-proposed tool calls route through the gate."""

from __future__ import annotations

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.llm import LLMRequest, ToolCall
from era.db import transaction
from era.providers import MockLLMProvider
from tests.conftest import make_container


class MockAgent:
    """A minimal orchestrator: model -> tool calls -> ExecutionService -> done.

    It receives ONLY the ExecutionService handle — never providers, repos or the
    audit service — so every tool call must pass the permission gate.
    """

    def __init__(self, execution_service, llm_provider):
        self.execution_service = execution_service
        self.llm_provider = llm_provider

    def run(self, task: str, ctx: ExecutionContext):
        response = self.llm_provider.complete(LLMRequest(messages=[{"role": "user", "content": task}]))
        results = []
        for call in response.tool_calls:
            results.append(self.execution_service.request(
                Action(action_type=call.action_type, params=call.params), ctx,
            ))
        return results


def test_agent_loop_routes_through_execution_service(tmp_path):
    c = make_container(tmp_path)
    llm = MockLLMProvider(tool_calls=[ToolCall(id="c1", action_type="stub.noop", params={})])
    agent = MockAgent(c.execution_service, llm)

    results = agent.run("do a noop", ExecutionContext(actor_id="agent"))

    assert len(results) == 1
    assert results[0].status == "executed"

    # The loop produced audit entries through the gate (not a direct provider call).
    with transaction(c.session_factory) as session:
        entries = [e for e in c.audit_service.list(session) if e.action_type == "stub.noop"]
    assert any(e.outcome == "EXECUTED" for e in entries)


def test_agent_receives_only_execution_service(tmp_path):
    # Structural boundary: the agent constructor takes the execution service and
    # an LLM provider — nothing that could reach providers or audit internals.
    c = make_container(tmp_path)
    agent = MockAgent(c.execution_service, MockLLMProvider())
    assert hasattr(agent, "execution_service")
    assert not hasattr(agent, "registry")
    assert not hasattr(agent, "audit_service")
