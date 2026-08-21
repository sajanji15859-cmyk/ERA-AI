"""AgentLoop tests — plan→execute→observe→verify→retry, approval gates, budgets."""

from __future__ import annotations

import pytest

from era.agent_runtime import build_agent_container
from era.agents.brain import OfflineBrain
from era.agents.budget import AgentBudget
from era.agents.loop import AgentLoop
from era.agents.models import ApprovalResolution, Plan, RunStatus, Task, TaskStatus
from era.agents.planner import RulePlanner
from era.agents.verifier import Verifier
from era.config import Settings
from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError


@pytest.fixture
def agent_env(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/loop.db",
                        agent_workspace_root=str(tmp_path / "ws"),
                        web_timeout_seconds=2.0)
    container = build_agent_container(settings)
    user = container.auth_service.create_user(username="loop-user", role="user")
    ctx = ExecutionContext(actor_id=user.id, session_id="loop")
    yield container, ctx, settings
    container.engine.dispose()


def _write_task(content: str) -> Task:
    return Task(
        id="w1", title="write page", action_type="fs.write",
        params={"path": "site/index.html", "content": content},
        verify={"kind": "html_valid", "path": "site/index.html",
                "required_elements": ["h1", "nav"],
                "keywords": ["welding"]},
        max_attempts=3,
    )


def _loop(container, ctx, *, brain=None, budget=None, approval_handler=None,
          max_replans=1):
    budget = budget or AgentBudget(timeout_seconds=120)
    return AgentLoop(
        execution_service=container.execution_service,
        planner=RulePlanner(),
        brain=brain or OfflineBrain(),
        verifier=Verifier(workspace_root=container.agent_service.verifier.workspace_root),
        budget=budget,
        run_id="test-run",
        approval_handler=approval_handler,
        max_replans=max_replans,
    )


def _auto_approve(container):
    from era.agent import _demo_approver
    root = container.agent_service.verifier.workspace_root
    return _demo_approver(container.execution_service, root, verbose=False)


class _FixOnRetryBrain(OfflineBrain):
    """Deterministic brain that fixes content on retry (verification feedback)."""

    def prepare(self, task, memory):
        params = dict(task.params)
        if task.correction_note and "content" in params:
            params["content"] = f"{params['content']} welding"
        return params


def test_loop_recovers_from_verification_failure_via_retry(agent_env):
    container, ctx, _ = agent_env
    plan = Plan(goal="g", tasks=[_write_task("<h1>hi</h1><nav>x</nav>")])
    loop = _loop(container, ctx, brain=_FixOnRetryBrain(),
                 approval_handler=_auto_approve(container))
    record = loop.run("g", ctx, plan=plan)
    assert record.status is RunStatus.COMPLETED
    task = record.tasks[0]
    assert task.status is TaskStatus.COMPLETED
    assert task.attempt == 1  # one corrective retry
    assert task.correction_note  # verification feedback recorded
    # the gate was used: audit log has AUTHORIZED + EXECUTED pairs
    with container.session_factory() as session:
        entries = container.audit_service.list(session, action_type="fs.write")
    assert any(e.outcome == "EXECUTED" for e in entries)
    assert any(e.outcome == "AUTHORIZED" for e in entries)


def test_loop_pauses_for_user_and_resumes_on_approval(agent_env):
    container, ctx, _ = agent_env
    plan = Plan(goal="g", tasks=[_write_task("<h1>hi</h1><nav>x</nav> welding")])
    loop = _loop(container, ctx)  # no approval handler → pause
    record = loop.run("g", ctx, plan=plan)
    assert record.status is RunStatus.WAITING_FOR_USER
    assert len(record.pending_confirmations) == 1
    task = record.tasks[0]
    assert task.status is TaskStatus.WAITING_FOR_USER

    # Operator approves through the normal gate.
    cid = record.pending_confirmations[0]
    response = container.execution_service.approve(cid, Action(
        action_type="fs.write",
        params={"path": "site/index.html",
                "content": "<h1>hi</h1><nav>x</nav> welding"}), ctx)
    assert response.status == "executed"

    resumed = loop.resume(record, ctx, [ApprovalResolution(
        confirmation_id=cid, outcome="executed")])
    assert resumed.status is RunStatus.COMPLETED
    assert resumed.tasks[0].status is TaskStatus.COMPLETED


def test_loop_denied_confirmation_fails_task(agent_env):
    container, ctx, _ = agent_env
    plan = Plan(goal="g", tasks=[_write_task("<h1>hi</h1><nav>x</nav> welding")])
    loop = _loop(container, ctx, approval_handler=lambda action, resp: "deny")
    record = loop.run("g", ctx, plan=plan)
    assert record.status is RunStatus.FAILED
    task = record.tasks[0]
    assert task.status is TaskStatus.FAILED
    assert "denied" in (task.error or "")


def test_loop_unknown_tool_is_rejected_fail_closed(agent_env):
    container, ctx, _ = agent_env
    plan = Plan(goal="g", tasks=[Task(id="u1", title="unknown tool",
                                      action_type="nope.action", params={})])
    loop = _loop(container, ctx)
    record = loop.run("g", ctx, plan=plan)
    assert record.status is RunStatus.FAILED
    assert record.tasks[0].status is TaskStatus.FAILED


def test_loop_budget_aborts_cleanly(agent_env):
    container, ctx, _ = agent_env
    plan = Plan(goal="g", tasks=[_write_task("<h1>hi</h1><nav>x</nav> welding")])
    budget = AgentBudget(max_tool_calls=0, timeout_seconds=120)
    loop = _loop(container, ctx, budget=budget, approval_handler=_auto_approve(container))
    record = loop.run("g", ctx, plan=plan)
    assert record.status is RunStatus.BUDGET_EXCEEDED
    assert "tool calls" in record.result.notes[0]


def test_loop_iteration_cap_stops_run(agent_env):
    container, ctx, _ = agent_env
    plan = Plan(goal="g", tasks=[_write_task("<h1>hi</h1><nav>x</nav> welding")])
    budget = AgentBudget(max_iterations=0, timeout_seconds=120)
    loop = _loop(container, ctx, budget=budget)
    record = loop.run("g", ctx, plan=plan)
    assert record.status is RunStatus.BUDGET_EXCEEDED


def test_loop_replan_adds_repair_tasks(agent_env):
    container, ctx, _ = agent_env
    # Content can never satisfy the keyword check → verification keeps failing,
    # retries exhaust, then one replan adds repair tasks.
    plan = Plan(goal="g", tasks=[Task(
        id="w1", title="write", action_type="fs.write",
        params={"path": "site/bad.html", "content": "<h1>no keyword</h1>"},
        verify={"kind": "html_valid", "path": "site/bad.html",
                "required_elements": ["h1"], "keywords": ["unobtainable-kw"]},
        max_attempts=2)])
    loop = _loop(container, ctx, approval_handler=_auto_approve(container))
    record = loop.run("g", ctx, plan=plan)
    ids = [t.id for t in record.tasks]
    assert "repair-w1" in ids and "reverify-w1" in ids
    assert record.status is RunStatus.FAILED


def test_loop_offline_research_failure_is_tolerated(agent_env, monkeypatch):
    """Non-required research tasks that fail must not fail the whole run."""
    container, ctx, _ = agent_env

    # Simulate a hard offline environment deterministically (no real sockets).
    from era.providers.web import WebProvider

    def _offline(self, url, max_bytes):
        raise ToolError("offline", provider_id="web",
                        code=ProviderErrorCode.UNAVAILABLE)

    monkeypatch.setattr(WebProvider, "_http_get", _offline)

    plan = Plan(goal="g", tasks=[
        Task(id="research", title="research", action_type="web.search",
             params={"q": "welding"}, required=False),
        Task(id="w1", title="write", action_type="fs.write",
             params={"path": "site/ok.html", "content": "<h1>ok</h1>"},
             verify={"kind": "file_exists", "path": "site/ok.html", "min_bytes": 5}),
    ])
    loop = _loop(container, ctx, approval_handler=_auto_approve(container))
    record = loop.run("g", ctx, plan=plan)
    # In the sandbox, the search fails (network blocked) but is tolerated.
    assert record.status is RunStatus.COMPLETED
    research = next(t for t in record.tasks if t.id == "research")
    assert research.status in (TaskStatus.FAILED, TaskStatus.COMPLETED)
