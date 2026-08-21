"""AgentBudget cap-enforcement tests (Phase 3A)."""

from __future__ import annotations

from era.agents.budget import AgentBudget


def test_budget_ok_within_caps():
    b = AgentBudget(max_iterations=5, max_tool_calls=5, max_llm_calls=3,
                    timeout_seconds=60)
    assert b.check() is None
    b.iterations = 4
    b.tool_calls = 3
    b.llm_calls = 2
    b.cost_used_usd = 0.01
    assert b.check() is None


def test_iteration_cap():
    b = AgentBudget(max_iterations=3)
    b.iterations = 4
    assert "max iterations" in b.check()


def test_tool_call_cap_blocks_further_calls():
    b = AgentBudget(max_tool_calls=2)
    b.tool_calls = 2
    assert b.can_tool_call() is not None  # no room for another call
    b.tool_calls = 1
    assert b.can_tool_call() is None


def test_llm_call_cap():
    b = AgentBudget(max_llm_calls=1)
    b.llm_calls = 1
    assert b.can_llm_call() is not None


def test_cost_cap():
    b = AgentBudget(cost_cap_usd=0.05)
    b.record_llm_call(tokens=100, cost_usd=0.06)
    assert "cost cap" in b.check()
    assert b.tokens_used == 100


def test_timeout_cap():
    b = AgentBudget(timeout_seconds=0.0)  # already expired
    assert "timeout" in b.check()


def test_snapshot_restore_roundtrip():
    b = AgentBudget()
    b.iterations = 7
    b.tool_calls = 9
    b.llm_calls = 2
    b.tokens_used = 300
    b.cost_used_usd = 0.002
    snap = b.snapshot()
    fresh = AgentBudget()
    fresh.restore(snap)
    assert fresh.iterations == 7
    assert fresh.tool_calls == 9
    assert fresh.tokens_used == 300
    assert fresh.cost_used_usd == 0.002
