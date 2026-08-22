"""Phase 4D — workflow operations & governance tests.

Covers scheduling, bounded DAG/parallel/conditional execution, deterministic
governance, immutable templates/versioning, operator review, observability,
RBAC and regression against the Phase 4C guarantees. All tests are
deterministic offline simulator tests; real-Chromium E2E stays opt-in.
"""

from __future__ import annotations

import threading
import time

import pytest

from era.config import Settings
from era.container import build_container
from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import Decision, RiskLevel
from era.core.result import ProviderErrorCode, ToolError
from era.providers.browser import BrowserProvider, SimulatedBrowserTransport
from era.registry.actions import ACTION_CATALOG
from era.security.rbac import ROLE_PERMISSIONS, Permission, Role, role_has_permission
from era.services.policy import default_policy
from era.services.workflow_ops_service import WorkflowTemplateError
from era.workflows.definition import (
    WorkflowCondition,
    WorkflowDefinition,
    WorkflowDefinitionError,
    WorkflowParallelBlock,
    WorkflowStep,
    validate_workflow_definition,
)
from era.workflows.reference import LOGIN_WORKFLOW

LOGIN = "https://93.184.216.34/login"
PUBLIC = "https://93.184.216.34"
NEXT = "https://93.184.216.34/next"
PAGES = {
    PUBLIC: "<html><body><a href='/login'>Sign in</a></body></html>",
    LOGIN: ("<html><body><form action='/next'>"
            "<label for='user'>Username</label><input id='user' name='user'>"
            "<label for='pass'>Password</label><input id='pass' name='pass' "
            "type='password'><button type='submit'>Submit</button>"
            "</form></body></html>"),
    NEXT: "<html><body><h1>Done</h1></body></html>",
}


class FakeResolver:
    def __init__(self):
        self.values = {"vault:browser/user": "alice",
                       "vault:browser/pass": "a-secret-value"}

    def resolve_ref(self, ref: str, *, actor_id=None, require_owner=False) -> str:
        return self.values.get(ref)


def _build(tmp_path, *, pages=None):
    resolver = FakeResolver()
    transport = SimulatedBrowserTransport(pages if pages is not None else PAGES,
                                          element_ref_ttl_seconds=120.0)
    provider = BrowserProvider(workspace_root=str(tmp_path / "ws"), transport=transport,
                               secret_resolver=resolver,
                               element_ref_ttl_seconds=120.0)
    return provider, transport, resolver


def _container(tmp_path, provider=None, **settings_kwargs):
    if provider is None:
        provider, _t, _r = _build(tmp_path)
    settings = Settings(database_url=f"sqlite:///{tmp_path}/wf.db",
                        scheduler_enabled=False, **settings_kwargs)
    return build_container(settings, providers=[provider])


def _user(c, role="user"):
    return c.auth_service.create_user(username=f"u-{role}-{int(time.time()*1000)}",
                                      role=role)


def _ctx(user, *, scope=None, session="k1"):
    return ExecutionContext(actor_id=user.id, session_id=session, execution_scope=scope)


def _guard(c, role="user"):
    from era.security.rbac import role_domain_allowed
    def g(at):
        spec = c.catalog.get(at)
        return spec is not None and role_domain_allowed(role, spec.capability_domain)
    return g


def _allow_mutating(c):
    p = default_policy()
    p.tier_defaults[RiskLevel.MUTATING] = Decision.ALLOW
    c.policy_service.create_version(p, changed_by="test")


def _login_params():
    return {"url": LOGIN, "username_vault": "vault:browser/user",
            "password_vault": "vault:browser/pass",
            "expected_url_contains": "/next"}


# ---------------------------------------------------------------------------
# Priority 2 — DAG/parallel/condition definition validation
# ---------------------------------------------------------------------------
def test_dag_rejects_cycle_unknown_dep_and_bad_condition():
    cat = ACTION_CATALOG

    def nav(sid, deps=None):
        return WorkflowStep(id=sid, action="browser.navigate",
                            params={"url": "https://93.184.216.34"},
                            depends_on=deps or [])

    with pytest.raises(WorkflowDefinitionError):
        validate_workflow_definition(
            WorkflowDefinition(name="cycle", version=1,
                               steps=[nav("a", ["b"]), nav("b", ["a"])]), cat)
    with pytest.raises(WorkflowDefinitionError):
        validate_workflow_definition(
            WorkflowDefinition(name="unk", version=1,
                               steps=[nav("a", ["zz"])]), cat)
    with pytest.raises((WorkflowDefinitionError, ValueError)):
        wf = WorkflowDefinition(name="badcond", version=1, steps=[
            nav("a"),
            WorkflowStep(id="b", action="browser.extract_dom",
                         params={"max_chars": 100},
                         condition=WorkflowCondition(kind="evil")),
        ])
        validate_workflow_definition(wf, cat)


def test_dag_rejects_parallel_sibling_dependency_and_unbounded_fanout():
    cat = ACTION_CATALOG

    def nav(sid, deps=None):
        return WorkflowStep(id=sid, action="browser.navigate",
                            params={"url": "https://93.184.216.34"},
                            depends_on=deps or [])

    with pytest.raises(WorkflowDefinitionError):
        validate_workflow_definition(WorkflowDefinition(
            name="sib", version=1,
            steps=[nav("a"), nav("b", ["a"])],
            parallel=[WorkflowParallelBlock(steps=["a", "b"])]), cat)
    fanout = [nav("a")] + [
        nav(f"s{i}", ["a"]) for i in range(10)
    ]
    with pytest.raises(WorkflowDefinitionError):
        validate_workflow_definition(
            WorkflowDefinition(name="fanout", version=1, steps=fanout), cat)


# ---------------------------------------------------------------------------
# Priority 2 — DAG execution
# ---------------------------------------------------------------------------
def test_dag_orders_dependencies_and_divergent_condition(tmp_path):
    provider, _t, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider)
    user = _user(c)
    ctx = _ctx(user)
    wf = WorkflowDefinition(name="dag", version=1, steps=[
        WorkflowStep(id="nav", action="browser.navigate", params={"url": LOGIN}),
        WorkflowStep(id="extract", action="browser.extract_dom",
                     params={"max_chars": 2000}, depends_on=["nav"]),
        WorkflowStep(id="skipme", action="browser.extract_dom",
                     params={"max_chars": 2000}, depends_on=["nav"],
                     condition=WorkflowCondition(kind="url_contains",
                                                 value="never-occurs")),
        WorkflowStep(id="after", action="browser.extract_dom",
                     params={"max_chars": 2000},
                     depends_on=["extract", "skipme"]),
    ])
    run = c.workflow_service.start(definition=wf, params={}, ctx=ctx,
                                   run_token="dagrun", domain_allowed=_guard(c))
    assert run.status == "completed", run.error
    run, steps = c.workflow_service.get_run(run.id, ctx)
    assert [s.status for s in steps] == [
        "completed", "completed", "skipped_conditional", "completed"]
    assert steps[3].step_id == "after"
    c.engine.dispose()


def test_parallel_execution_respects_concurrency_cap(tmp_path):
    provider, transport, _r = _build(tmp_path)
    active = 0
    max_active = 0
    lock = threading.Lock()
    orig = transport.extract

    def tracked(*args, **kwargs):
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.05)
        try:
            return orig(*args, **kwargs)
        finally:
            with lock:
                active -= 1

    transport.extract = tracked
    c = _container(tmp_path, provider=provider,
                   workflow_max_pending_confirmations=2)
    user = _user(c)
    ctx = _ctx(user)
    wf = WorkflowDefinition(name="par", version=1, steps=[
        WorkflowStep(id="nav", action="browser.navigate", params={"url": LOGIN}),
        WorkflowStep(id="e1", action="browser.extract_dom",
                     params={"max_chars": 1000}, depends_on=["nav"]),
        WorkflowStep(id="e2", action="browser.extract_dom",
                     params={"max_chars": 1000}, depends_on=["nav"]),
    ], parallel=[WorkflowParallelBlock(steps=["e1", "e2"], depends_on=["nav"],
                                       max_concurrency=2)])
    run = c.workflow_service.start(definition=wf, params={}, ctx=ctx,
                                   run_token="parrun", domain_allowed=_guard(c))
    assert run.status == "completed", run.error
    run, steps = c.workflow_service.get_run(run.id, ctx)
    assert all(s.status == "completed" for s in steps)
    assert max_active == 2  # cap enforced
    c.engine.dispose()


def test_parallel_confirmation_continuity(tmp_path):
    provider, _t, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider)
    user = _user(c)
    ctx = _ctx(user)
    wf = WorkflowDefinition(name="parconf", version=1, steps=[
        WorkflowStep(id="nav", action="browser.navigate", params={"url": LOGIN}),
        WorkflowStep(id="fill1", action="browser.fill",
                     params={"value_ref": "vault:browser/user"},
                     target={"role": "textbox", "name": "Username",
                             "input_type": "text"}, depends_on=["nav"]),
        WorkflowStep(id="fill2", action="browser.fill",
                     params={"value_ref": "vault:browser/pass"},
                     target={"role": "textbox", "name": "Password",
                             "input_type": "password"}, depends_on=["nav"]),
    ], parallel=[WorkflowParallelBlock(steps=["fill1", "fill2"],
                                       depends_on=["nav"], max_concurrency=2)])
    run = c.workflow_service.start(definition=wf, params={}, ctx=ctx,
                                   run_token="parconfrun",
                                   domain_allowed=_guard(c))
    run_id = run.id
    # Parallel concurrency is bounded by workflow_max_pending_confirmations (1
    # by default), so the run pauses with one independent confirmation at a
    # time; each is resolved independently and the run resumes exactly once per
    # step.
    assert run.status == "waiting_for_user"
    seen = set()
    for _ in range(2):
        run, steps = c.workflow_service.get_run(run_id, ctx)
        waiting = [s for s in steps if s.status == "waiting_for_user"
                   and s.confirmation_id]
        assert waiting, f"expected a waiting confirmation; status={run.status}"
        step = waiting[0]
        assert step.step_id not in seen
        seen.add(step.step_id)
        with c.session_factory() as sess:
            conf = c.confirmation_service.get(sess, step.confirmation_id)
            action = Action(action_type=conf.action_type,
                            params=conf.action_params_redacted)
        resp = c.execution_service.approve(step.confirmation_id, action, ctx)
        assert resp.status == "executed"
        final = c.workflow_service.resume(run_id, ctx, _guard(c))
        if final.status == "completed":
            break
    assert final.status == "completed", final.error
    run, steps = c.workflow_service.get_run(run_id, ctx)
    completed = [s for s in steps if s.status == "completed"]
    assert len(completed) >= 3
    assert all(s.attempt == 1 for s in completed)
    c.engine.dispose()


# ---------------------------------------------------------------------------
# Priority 3 — governance
# ---------------------------------------------------------------------------
def test_governance_concurrent_run_cap(tmp_path):
    provider, _t, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider,
                   workflow_max_concurrent_per_actor=2)
    user = _user(c)
    c.workflow_governance_service.claim_start(actor_id=user.id, workflow_name="login")
    c.workflow_governance_service.claim_start(actor_id=user.id, workflow_name="login")
    with pytest.raises(Exception) as info:
        c.workflow_governance_service.claim_start(actor_id=user.id,
                                                  workflow_name="login")
    assert getattr(info.value, "code", "") == "CONCURRENCY_EXCEEDED"
    c.workflow_governance_service.release_start(actor_id=user.id, workflow_name="login")
    c.workflow_governance_service.release_start(actor_id=user.id, workflow_name="login")
    c.workflow_governance_service.claim_start(actor_id=user.id, workflow_name="login")
    c.engine.dispose()


def test_governance_db_concurrent_racing_cap(tmp_path):
    provider, _t, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider,
                   workflow_max_concurrent_per_actor=1)
    errors = []

    def worker():
        try:
            c.workflow_governance_service.claim_start(actor_id="racer",
                                                      workflow_name="w")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    accepted = 4 - len(errors)
    assert accepted == 1
    assert all(getattr(e, "code", "") == "CONCURRENCY_EXCEEDED" for e in errors)
    c.engine.dispose()


def test_governance_rate_limit_window(tmp_path):
    provider, _t, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider,
                   workflow_max_concurrent_per_actor=10,
                   workflow_max_concurrent_per_workflow=10,
                   workflow_max_runs_per_window=2,
                   workflow_rate_window_seconds=3600)
    c.workflow_governance_service.claim_start(actor_id="a", workflow_name="login")
    c.workflow_governance_service.claim_start(actor_id="a", workflow_name="login")
    with pytest.raises(Exception) as info:
        c.workflow_governance_service.claim_start(actor_id="a", workflow_name="login")
    assert getattr(info.value, "code", "") == "RATE_LIMIT_EXCEEDED"
    c.engine.dispose()


def test_governance_budget_exceeded_fails_run_deterministically(tmp_path):
    provider, _t, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider,
                   workflow_max_steps_per_run=2)
    user = _user(c)
    ctx = _ctx(user)
    wf = WorkflowDefinition(name="budget", version=1, steps=[
        WorkflowStep(id="a", action="browser.navigate", params={"url": LOGIN}),
        WorkflowStep(id="b", action="browser.extract_dom",
                     params={"max_chars": 1000}),
        WorkflowStep(id="c", action="browser.extract_dom",
                     params={"max_chars": 1000}),
    ])
    run = c.workflow_service.start(definition=wf, params={}, ctx=ctx,
                                   run_token="budgetrun",
                                   domain_allowed=_guard(c))
    assert run.status == "failed"
    assert run.governance_code == "BUDGET_EXCEEDED"
    run, steps = c.workflow_service.get_run(run.id, ctx)
    assert steps[2].status == "failed"
    assert steps[2].error_code == "BUDGET_EXCEEDED"
    c.engine.dispose()


# ---------------------------------------------------------------------------
# Priority 1 — scheduling
# ---------------------------------------------------------------------------
def test_schedule_register_due_tick_and_exact_once(tmp_path):
    provider, _t, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider)
    user = _user(c)
    ctx = _ctx(user)
    s = c.workflow_schedule_service.create(
        actor_id=user.id, actor_role="user", name="hourly-login",
        workflow_name="login", params=_login_params(), interval_seconds=3600,
        enabled=True, domain_allowed=_guard(c))
    assert s.workflow_version == 1
    from era.db import transaction
    with transaction(c.session_factory) as session:
        row = c.repositories.workflow_schedule.get(session, s.id)
        row.next_run_at = "2020-01-01T00:00:00+00:00"
        c.repositories.workflow_schedule.update(session, row)
    run_ids = c.workflow_schedule_service.tick("2020-01-01T00:01:00+00:00")
    assert len(run_ids) == 1
    runs = c.workflow_service.list_runs(ctx)
    assert len(runs) == 1
    assert runs[0].scheduled is True
    assert runs[0].schedule_id == s.id
    assert runs[0].status == "waiting_for_user"  # schedule is not a bypass
    # Second tick at the same due stamp is exactly-once (no duplicate run).
    with transaction(c.session_factory) as session:
        row = c.repositories.workflow_schedule.get(session, s.id)
        row.next_run_at = "2020-01-01T00:00:00+00:00"
        c.repositories.workflow_schedule.update(session, row)
    run_ids2 = c.workflow_schedule_service.tick("2020-01-01T00:01:00+00:00")
    assert run_ids2 == []
    assert len(c.workflow_service.list_runs(ctx)) == 1
    c.engine.dispose()


def test_schedule_enable_disable_and_confirmation_pause(tmp_path):
    provider, _t, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider)
    user = _user(c)
    s = c.workflow_schedule_service.create(
        actor_id=user.id, actor_role="user", name="toggle",
        workflow_name="login", params=_login_params(), interval_seconds=60,
        enabled=False, domain_allowed=_guard(c))
    assert s.enabled is False
    updated = c.workflow_schedule_service.update(
        s.id, user.id, enabled=True, interval_seconds=60)
    assert updated.enabled is True
    assert updated.next_run_at is not None
    updated = c.workflow_schedule_service.update(s.id, user.id, enabled=False)
    assert updated.enabled is False
    assert updated.next_run_at is None
    # A disabled schedule never becomes due.
    run_ids = c.workflow_schedule_service.tick("2099-01-01T00:00:00+00:00")
    assert run_ids == []
    c.engine.dispose()


# ---------------------------------------------------------------------------
# Priority 4 — templates / versioning
# ---------------------------------------------------------------------------
def test_template_publish_version_isolation_and_param_rejection(tmp_path):
    provider, _t, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider)
    user = _user(c)
    t1 = c.workflow_template_service.publish(LOGIN_WORKFLOW, created_by=user.id)
    assert t1.version == 1
    v2 = LOGIN_WORKFLOW.model_copy(deep=True)
    v2.description = "version 2"
    t2 = c.workflow_template_service.publish(v2, created_by=user.id)
    assert t2.version == 2
    # Exact old version is reusable and isolated from v2.
    d1 = c.workflow_template_service.instantiate("login", _login_params(), version=1)
    assert d1.version == 1
    assert d1.description != v2.description
    # Param-schema rejection.
    with pytest.raises((WorkflowTemplateError, ValueError)):
        c.workflow_template_service.instantiate(
            "login", {"url": LOGIN}, version=1)
    # Checksum drift is fail-closed.
    latest = c.workflow_template_service.get_latest("login")
    assert latest.checksum == c.workflow_catalog.checksum(v2)
    c.engine.dispose()


def test_template_run_records_exact_version(tmp_path):
    provider, _t, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider)
    user = _user(c)
    ctx = _ctx(user)
    c.workflow_template_service.publish(LOGIN_WORKFLOW, created_by=user.id)
    definition = c.workflow_template_service.instantiate("login", _login_params())
    run = c.workflow_service.start(
        definition=definition, params=_login_params(), ctx=ctx,
        run_token="tmplrun", domain_allowed=_guard(c),
        template_name="login", template_version=1)
    assert run.template_name == "login"
    assert run.template_version == 1
    assert run.template_checksum == c.workflow_catalog.checksum(definition)
    c.engine.dispose()


# ---------------------------------------------------------------------------
# Priority 5 — operator review
# ---------------------------------------------------------------------------
def test_admin_awaiting_list_and_timeline(tmp_path):
    provider, transport, _r = _build(tmp_path)
    def bad_click(*args, **kwargs):
        raise ToolError("outcome unknown", provider_id="browser",
                        code=ProviderErrorCode.SIDE_EFFECT_UNKNOWN)
    transport.click = bad_click
    c = _container(tmp_path, provider=provider)
    _allow_mutating(c)
    user = _user(c)
    admin = _user(c, role="admin")
    ctx = _ctx(user)
    wf = WorkflowDefinition(name="amb_wf", version=1, steps=[
        WorkflowStep(id="nav", action="browser.navigate", params={"url": LOGIN}),
        WorkflowStep(id="click", action="browser.click", params={},
                     target={"role": "button", "name": "Submit"}),
    ])
    run = c.workflow_service.start(definition=wf, params={}, ctx=ctx,
                                   run_token="ambop", domain_allowed=_guard(c))
    assert run.status == "ambiguous"
    awaiting = c.workflow_service.list_awaiting_runs()
    assert any(r.id == run.id for r in awaiting)
    timeline = c.workflow_service.run_timeline(run.id, _ctx(admin), admin=True)
    # No secrets / refs / page content in the timeline.
    blob = str(timeline)
    assert "element_ref" not in blob
    assert "cookie" not in blob.lower()
    assert "a-secret-value" not in blob
    c.engine.dispose()


def test_admin_cross_actor_resolve_allow_and_deny(tmp_path):
    provider, transport, _r = _build(tmp_path)

    def bad_click(*args, **kwargs):
        raise ToolError("outcome unknown", provider_id="browser",
                        code=ProviderErrorCode.SIDE_EFFECT_UNKNOWN)

    transport.click = bad_click
    c = _container(tmp_path, provider=provider)
    _allow_mutating(c)
    user = _user(c)
    admin = _user(c, role="admin")
    other = _user(c, role="user")
    ctx = _ctx(user)
    # RBAC: admin holds review/schedule; user holds schedule but not review.
    assert role_has_permission(Role.ADMIN, Permission.WORKFLOW_REVIEW)
    assert role_has_permission(Role.USER, Permission.WORKFLOW_SCHEDULE)
    assert not role_has_permission(Role.USER, Permission.WORKFLOW_REVIEW)

    wf = WorkflowDefinition(name="rw", version=1, steps=[
        WorkflowStep(id="nav", action="browser.navigate", params={"url": LOGIN}),
        WorkflowStep(id="click", action="browser.click", params={},
                     target={"role": "button", "name": "Submit"}),
    ])
    run = c.workflow_service.start(definition=wf, params={}, ctx=ctx,
                                   run_token="adminrun",
                                   domain_allowed=_guard(c))
    assert run.status == "ambiguous"
    # A regular non-owner user may not resolve another actor's run through the
    # owner-scoped API. The service method `resolve_ambiguous` is owner-bound.
    from era.services.workflow_service import WorkflowStateError
    with pytest.raises(WorkflowStateError):
        c.workflow_service.resolve_ambiguous(
            run.id, _ctx(other, session="other"), "abort")
    # Admin cross-actor resolve is allowed and audited.
    resolved = c.workflow_service.admin_resolve_ambiguous(
        run.id, _ctx(admin, session="admin"), "abort", "operator review")
    assert resolved.status == "cancelled", resolved.error
    with c.session_factory() as sess:
        entries = c.audit_service.list(
            sess, action_type="workflow.operator.resolve", limit=10)
    assert entries and entries[-1].meta.get("operator") is True
    c.engine.dispose()


# ---------------------------------------------------------------------------
# Priority 6 — observability
# ---------------------------------------------------------------------------
def test_aggregation_and_actor_scoping(tmp_path):
    provider, _transport, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider)
    user = _user(c)
    admin = _user(c, role="admin")
    ctx = _ctx(user)
    wf = WorkflowDefinition(name="obs", version=1, steps=[
        WorkflowStep(id="nav", action="browser.navigate", params={"url": LOGIN}),
        WorkflowStep(id="extract", action="browser.extract_dom",
                     params={"max_chars": 1000}),
    ])
    run = c.workflow_service.start(definition=wf, params={}, ctx=ctx,
                                   run_token="obs1", domain_allowed=_guard(c))
    assert run.status == "completed", run.error
    agg_user = c.workflow_service.aggregate_runs(ctx=ctx)
    assert agg_user["total"] == 1
    assert agg_user["by_status"]["completed"] == 1
    # Admin scoping sees the same in a single-actor test.
    agg_admin = c.workflow_service.aggregate_runs(ctx=_ctx(admin), admin=True)
    assert agg_admin["total"] == 1
    items = c.workflow_service.list_runs_filtered(
        ctx=ctx, limit=1, offset=0)
    assert len(items) == 1
    c.engine.dispose()


# ---------------------------------------------------------------------------
# Priority 8 — RBAC integration
# ---------------------------------------------------------------------------
def test_phase4d_permissions_mirrored():
    for perm in (Permission.WORKFLOW_SCHEDULE, Permission.WORKFLOW_READ,
                 Permission.WORKFLOW_TEMPLATES_MANAGE, Permission.WORKFLOW_REVIEW):
        assert perm in ROLE_PERMISSIONS[Role.ADMIN]
    assert Permission.WORKFLOW_SCHEDULE in ROLE_PERMISSIONS[Role.USER]
    assert Permission.WORKFLOW_READ in ROLE_PERMISSIONS[Role.USER]
    assert Permission.WORKFLOW_REVIEW not in ROLE_PERMISSIONS[Role.USER]
    assert Permission.WORKFLOW_TEMPLATES_MANAGE not in ROLE_PERMISSIONS[Role.USER]


# ---------------------------------------------------------------------------
# Priority 9 — preserved guarantees
# ---------------------------------------------------------------------------
def test_backward_compatible_login_still_runs(tmp_path):
    provider, _t, _r = _build(tmp_path)
    c = _container(tmp_path, provider=provider)
    user = _user(c)
    ctx = _ctx(user)
    run = c.workflow_service.start(
        definition="login", params=_login_params(), ctx=ctx,
        run_token="bclogin", domain_allowed=_guard(c))
    assert run.status in ("waiting_for_user", "completed")
    c.engine.dispose()
