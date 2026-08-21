"""End-to-end MVEA demo test (Phase 3A).

The user's first real goal: «मेरे लिए एक welding training website बनाओ» —
plan → tasks → tool execution through the permission/confirmation/audit gate
→ verification → retry → final site. Runs fully offline and deterministic
(no network, no LLM key): the FREE limitation path of the architecture.
"""

from __future__ import annotations

import pytest

from era.agent import _demo_approver
from era.agent_runtime import build_agent_container
from era.agents.models import RunStatus, TaskStatus
from era.config import Settings
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError


@pytest.fixture
def agent(tmp_path, monkeypatch):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/demo.db",
                        agent_workspace_root=str(tmp_path / "ws"),
                        web_timeout_seconds=2.0)
    container = build_agent_container(settings)
    user = container.auth_service.create_user(username="demo", role="user")
    ctx = ExecutionContext(actor_id=user.id, session_id="demo")

    # Deterministic offline environment: no real sockets in tests.
    from era.providers.web import WebProvider

    def _offline(self, url, max_bytes):
        raise ToolError("offline (test)", provider_id="web",
                        code=ProviderErrorCode.UNAVAILABLE)

    monkeypatch.setattr(WebProvider, "_http_get", _offline)

    root = container.agent_service.verifier.workspace_root
    approver = _demo_approver(container.execution_service, root, verbose=False)
    yield container, ctx, approver, root
    container.engine.dispose()


def test_welding_training_website_end_to_end(agent):
    container, ctx, approver, root = agent
    record = container.agent_service.start_run(
        "मेरे लिए एक welding training website बनाओ", ctx,
        approval_handler=approver)

    assert record.status is RunStatus.COMPLETED, \
        [f"{t.id}:{t.status.value}:{t.error}" for t in record.tasks]
    assert record.result.tasks_completed >= 10
    assert record.result.estimated_cost_usd == 0.0  # offline mode costs nothing

    # The site exists on disk with the planned structure.
    site = root / "welding_training_site"
    for page in ("index.html", "safety.html", "processes.html", "courses.html",
                 "career.html", "contact.html"):
        assert (site / page).is_file(), f"missing {page}"
    assert (site / "assets" / "style.css").is_file()
    assert (site / "assets" / "app.js").is_file()

    # Every page is valid HTML with nav + footer.
    for page in site.glob("*.html"):
        content = page.read_text(encoding="utf-8")
        assert "<title>" in content and "<nav" in content and "<footer>" in content

    # The research task hit the offline environment and was tolerated.
    research = next(t for t in record.tasks if t.id == "research")
    assert research.required is False
    assert research.status is TaskStatus.FAILED  # observed, adapted, tolerated

    # Every write went through the gate: audit log has AUTHORIZED+EXECUTED.
    with container.session_factory() as session:
        entries = container.audit_service.list(session, action_type="fs.write")
    assert sum(1 for e in entries if e.outcome == "EXECUTED") >= 8
    assert sum(1 for e in entries if e.outcome == "AUTHORIZED") >= 8
    # ...and the confirmation flow was exercised for MUTATING writes.
    with container.session_factory() as session:
        entries = container.audit_service.list(session, action_type="fs.write")
    assert any(e.confirmation_id for e in entries)


def test_generic_subject_site_end_to_end(agent):
    container, ctx, approver, root = agent
    record = container.agent_service.start_run(
        "build a website about photography", ctx, approval_handler=approver)
    assert record.status is RunStatus.COMPLETED
    site = root / "photography_site"
    assert (site / "index.html").is_file()
    assert (site / "about.html").is_file()


def test_run_persisted_and_listed(agent):
    container, ctx, approver, _root = agent
    record = container.agent_service.start_run("make me a welding site", ctx,
                                               approval_handler=approver)
    loaded = container.agent_service.get_run(record.run_id, ctx.actor_id)
    assert loaded is not None
    assert loaded.status is RunStatus.COMPLETED
    assert loaded.result.tasks_completed == record.result.tasks_completed
    runs = container.agent_service.list_runs(ctx.actor_id)
    assert len(runs) == 1
    assert container.agent_service.get_run(record.run_id, "someone-else") is None
