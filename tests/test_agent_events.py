"""Agent event-stream tests (Phase 3B)."""

from __future__ import annotations

import pytest

from era.agent_runtime import build_agent_container
from era.agents.brain import OfflineBrain
from era.agents.budget import AgentBudget
from era.agents.events import AgentEventType, summarize_params
from era.agents.loop import AgentLoop
from era.agents.models import Plan, Task
from era.agents.planner import RulePlanner
from era.agents.verifier import Verifier
from era.config import Settings
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/ev.db",
                        agent_workspace_root=str(tmp_path / "ws"),
                        web_timeout_seconds=2.0)
    container = build_agent_container(settings)
    user = container.auth_service.create_user(username="ev", role="user")
    ctx = ExecutionContext(actor_id=user.id, session_id="ev")

    from era.providers.web import WebProvider

    def _offline(self, url, max_bytes):
        raise ToolError("offline (test)", provider_id="web",
                        code=ProviderErrorCode.UNAVAILABLE)

    monkeypatch.setattr(WebProvider, "_http_get", _offline)

    from era.agent import _demo_approver
    approver = _demo_approver(container.execution_service,
                              container.agent_service.verifier.workspace_root,
                              verbose=False)
    yield container, ctx, approver
    container.engine.dispose()


def _loop(container, ctx, approver, *, emit=None, domain_guard=None):
    budget = AgentBudget(timeout_seconds=120)
    return AgentLoop(
        execution_service=container.execution_service,
        planner=RulePlanner(),
        brain=OfflineBrain(),
        verifier=Verifier(workspace_root=container.agent_service.verifier.workspace_root),
        budget=budget,
        run_id="ev-run",
        approval_handler=approver,
        emit=emit,
        domain_guard=domain_guard,
    )


def test_event_sequence_for_tiny_run(env):
    container, ctx, approver = env
    plan = Plan(goal="g", tasks=[
        Task(id="w1", title="write", action_type="fs.write",
             params={"path": "site/a.html", "content": "<h1>ok</h1>"},
             verify={"kind": "file_exists", "path": "site/a.html", "min_bytes": 5}),
    ])
    loop = _loop(container, ctx, approver)
    record = loop.run("g", ctx, plan=plan)
    assert record.status.value == "completed"
    types = [e.type for e in loop.events]
    assert types[0] is AgentEventType.RUN_STARTED
    assert types[1] is AgentEventType.PLAN_CREATED
    assert AgentEventType.TASK_STARTED in types
    assert AgentEventType.TOOL_CALL in types
    assert AgentEventType.CONFIRMATION_REQUIRED in types  # fs.write is MUTATING
    assert AgentEventType.OBSERVATION in types
    assert AgentEventType.VERDICT in types
    assert AgentEventType.TASK_COMPLETED in types
    assert types[-1] is AgentEventType.RUN_FINISHED
    final = loop.events[-1]
    assert final.data["status"] == "completed"
    assert final.data["tasks_completed"] == 1


def test_emit_callback_receives_all_events(env):
    container, ctx, approver = env
    seen: list = []
    plan = Plan(goal="g", tasks=[
        Task(id="w1", title="write", action_type="fs.write",
             params={"path": "a.txt", "content": "hello"},
             verify={"kind": "file_exists", "path": "a.txt"}),
    ])
    loop = _loop(container, ctx, approver, emit=lambda ev: seen.append(ev))
    loop.run("g", ctx, plan=plan)
    assert seen and seen[-1].type is AgentEventType.RUN_FINISHED
    assert all(ev.run_id == "ev-run" for ev in seen)
    # seq is monotonically increasing
    seqs = [ev.seq for ev in seen]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def test_tool_call_event_never_leaks_content_or_secrets(env):
    container, ctx, approver = env
    big_content = "<h1>x</h1>" * 500  # > 200 chars -> length marker in events
    plan = Plan(goal="g", tasks=[
        Task(id="w1", title="write", action_type="fs.write",
             params={"path": "big.html", "content": big_content,
                     "token": "super-secret-value"},
             verify={"kind": "file_exists", "path": "big.html"}),
    ])
    loop = _loop(container, ctx, approver)
    loop.run("g", ctx, plan=plan)
    tool_events = [e for e in loop.events if e.type is AgentEventType.TOOL_CALL]
    assert tool_events, "expected TOOL_CALL events"
    for ev in tool_events:
        params = ev.data["params"]
        assert params["content"].startswith("<str:")  # length marker, not content
        assert params["token"] == "[REDACTED]"  # secret fields redacted
        blob = ev.model_dump_json()
        assert "super-secret-value" not in blob
        assert "<h1>x</h1>" not in blob


def test_broken_sink_does_not_break_run(env):
    container, ctx, approver = env

    def broken(ev):
        raise RuntimeError("sink down")

    plan = Plan(goal="g", tasks=[
        Task(id="w1", title="write", action_type="fs.write",
             params={"path": "a.txt", "content": "hello"},
             verify={"kind": "file_exists", "path": "a.txt"}),
    ])
    loop = _loop(container, ctx, approver, emit=broken)
    record = loop.run("g", ctx, plan=plan)
    assert record.status.value == "completed"  # the run survives the sink failure


def test_events_include_budget_abort_reason(env):
    container, ctx, approver = env
    plan = Plan(goal="g", tasks=[
        Task(id="w1", title="write", action_type="fs.write",
             params={"path": "a.txt", "content": "hello"}),
    ])
    budget = AgentBudget(max_tool_calls=0, timeout_seconds=120)
    loop = AgentLoop(
        execution_service=container.execution_service, planner=RulePlanner(),
        brain=OfflineBrain(),
        verifier=Verifier(workspace_root=container.agent_service.verifier.workspace_root),
        budget=budget, run_id="ev-budget", approval_handler=approver,
    )
    record = loop.run("g", ctx, plan=plan)
    assert record.status.value == "budget_exceeded"
    assert loop.events[-1].type is AgentEventType.RUN_FINISHED
    assert loop.events[-1].data["status"] == "budget_exceeded"


def test_summarize_params_redacts_and_marks():
    out = summarize_params({"q": "welding", "content": "x" * 500,
                            "api_key": "sk-123"}, frozenset({"api_key"}))
    assert out["q"] == "welding"
    assert out["content"] == "<str:500 chars>"
    assert out["api_key"] == "[REDACTED]"
