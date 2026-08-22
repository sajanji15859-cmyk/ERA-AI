"""Phase 4A.1 browser lifecycle, side-effect, vault and result hardening tests."""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from era.agent_runtime import build_agent_container
from era.agents.brain import OfflineBrain
from era.agents.budget import AgentBudget
from era.agents.loop import AgentLoop
from era.agents.models import Plan, RunStatus, Task, TaskStatus
from era.agents.planner import RulePlanner
from era.agents.verifier import Verifier
from era.config import Settings
from era.container import build_container
from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.providers.browser import (
    BrowserProvider,
    PlaywrightBrowserTransport,
    SimulatedBrowserTransport,
    _PlaywrightSession,
)
from era.security.redaction import REDACTED
from era.security.result_safety import UnsafeResultError, sanitize_action_result
from era.services.vault_service import VaultRefResolver

PUBLIC_URL = "https://93.184.216.34"
PAGE = (
    "<html><head><title>Secure</title></head><body><button id='go'>Go</button>"
    "<form id='login'><input id='password'></form></body></html>"
)
MASTER_KEY = "42" * 32


def _ctx(*, scope: str | None = None, session: str = "api-key") -> ExecutionContext:
    return ExecutionContext(
        actor_id="alice", session_id=session, execution_scope=scope,
    )


def _browser_container(tmp_path, transport=None, *, settings=None, resolver=None):
    settings = settings or Settings(database_url=f"sqlite:///{tmp_path}/hardening.db")
    transport = transport or SimulatedBrowserTransport({PUBLIC_URL: PAGE})
    provider = BrowserProvider(
        workspace_root=tmp_path / "workspace",
        transport=transport,
        secret_resolver=resolver,
    )
    container = build_container(settings, providers=[provider])
    return container, provider, transport


def _open(container, ctx):
    response = container.execution_service.request(
        Action(action_type="browser.navigate", params={"url": PUBLIC_URL}), ctx,
    )
    assert response.status == "executed"


def _approve(container, action, ctx):
    pending = container.execution_service.request(action, ctx)
    assert pending.status == "confirmation_required"
    return container.execution_service.approve(pending.confirmation_id, action, ctx)


# -- run-scoped context lifecycle -------------------------------------------------

def test_confirmation_restores_original_browser_execution_scope(tmp_path):
    container, _, transport = _browser_container(tmp_path)
    run_ctx = _ctx(scope="agent:run-one")
    _open(container, run_ctx)
    action = Action(action_type="browser.click", params={"selector": "#go"})
    pending = container.execution_service.request(action, run_ctx)

    with container.session_factory() as session:
        confirmation = container.confirmation_service.get(session, pending.confirmation_id)
        assert confirmation.execution_scope == "agent:run-one"

    # Approval arrives through an ordinary API-key context with no run scope.
    approved = container.execution_service.approve(
        pending.confirmation_id, action, _ctx(session="different-api-request"),
    )
    assert approved.status == "executed"
    assert len(transport.sessions) == 1
    assert next(iter(transport.sessions.values())).clicks[0]["selector"] == "#go"


def test_browser_context_key_prefers_run_scope_over_shared_api_session(tmp_path):
    _, provider, transport = _browser_container(tmp_path)
    for scope in ("agent:run-a", "agent:run-b"):
        provider.execute(
            Action(action_type="browser.navigate", params={"url": PUBLIC_URL}),
            _ctx(scope=scope),
        )
    assert len(transport.sessions) == 2


def test_completed_agent_run_discards_browser_context(tmp_path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path}/agent-cleanup.db",
        agent_workspace_root=str(tmp_path / "workspace"),
    )
    container = build_agent_container(settings)
    browser = container.registry.get_provider("browser")
    transport = SimulatedBrowserTransport({PUBLIC_URL: PAGE})
    browser.transport = transport
    user = container.auth_service.create_user(username="cleanup", role="user")

    record = container.agent_service.start_run(
        f"{PUBLIC_URL} ka screenshot lo",
        ExecutionContext(actor_id=user.id, session_id="shared-api-key"),
    )
    assert record.status is RunStatus.COMPLETED
    assert not transport.sessions
    container.engine.dispose()


def test_waiting_run_keeps_context_then_terminal_continue_discards_it(tmp_path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path}/agent-resume.db",
        agent_workspace_root=str(tmp_path / "workspace"),
    )
    container = build_agent_container(settings)
    browser = container.registry.get_provider("browser")
    transport = SimulatedBrowserTransport({PUBLIC_URL: PAGE})
    browser.transport = transport
    user = container.auth_service.create_user(username="resume", role="user")
    ctx = ExecutionContext(actor_id=user.id, session_id="shared-api-key")
    plan = Plan(goal="click", tasks=[
        Task(id="nav", title="navigate", action_type="browser.navigate",
             params={"url": PUBLIC_URL}),
        Task(id="click", title="click", action_type="browser.click",
             params={"selector": "#go"}, depends_on=["nav"]),
    ])
    container.agent_service.make_planner = lambda budget, role: _FixedPlanner(plan)

    record = container.agent_service.start_run("click safely", ctx)
    assert record.status is RunStatus.WAITING_FOR_USER
    assert len(transport.sessions) == 1
    click = next(task for task in record.tasks if task.id == "click")
    action = Action(action_type=click.action_type, params=click.params)
    approved = container.execution_service.approve(
        record.pending_confirmations[0], action, ctx,
    )
    assert approved.status == "executed"
    assert len(transport.sessions) == 1

    resumed = container.agent_service.continue_run(record.run_id, ctx)
    assert resumed.status is RunStatus.COMPLETED
    assert not transport.sessions
    container.engine.dispose()


class _FixedPlanner:
    id = "fixed"

    def __init__(self, plan):
        self._plan = plan

    def plan(self, goal):
        return self._plan.model_copy(deep=True, update={"goal": goal})

    def repair(self, failed, reason):
        del failed, reason
        return []


# -- non-retryable side effects ---------------------------------------------------

class _FailingInteractionTransport(SimulatedBrowserTransport):
    def __init__(self, operation: str, error: BaseException):
        super().__init__({PUBLIC_URL: PAGE})
        self.operation = operation
        self.error = error
        self.calls = 0

    def _fail(self):
        self.calls += 1
        raise self.error

    def click(self, *args, **kwargs):
        if self.operation == "click":
            return self._fail()
        return super().click(*args, **kwargs)

    def fill(self, *args, **kwargs):
        if self.operation == "fill":
            return self._fail()
        return super().fill(*args, **kwargs)

    def submit(self, *args, **kwargs):
        if self.operation == "submit":
            return self._fail()
        return super().submit(*args, **kwargs)


@pytest.mark.parametrize("operation,params", [
    ("click", {"selector": "#go"}),
    ("fill", {"selector": "#password", "text": "value"}),
    ("submit", {"selector": "#login"}),
])
def test_mutating_browser_transport_failures_are_never_retried(tmp_path, operation, params):
    transport = _FailingInteractionTransport(
        operation,
        ToolError("transient", provider_id="browser", code=ProviderErrorCode.UNAVAILABLE),
    )
    container, _, _ = _browser_container(tmp_path, transport)
    ctx = _ctx(scope="agent:no-retry")
    _open(container, ctx)
    result = _approve(
        container, Action(action_type=f"browser.{operation}", params=params), ctx,
    )
    assert result.status == "failed"
    assert transport.calls == 1


@pytest.mark.parametrize("operation,params", [
    ("click", {"selector": "#go"}),
    ("fill", {"selector": "#password", "text": "value"}),
    ("submit", {"selector": "#login"}),
])
def test_mutating_timeout_is_side_effect_unknown_and_quarantines_context(
    tmp_path, operation, params,
):
    transport = _FailingInteractionTransport(operation, TimeoutError("late"))
    container, _, _ = _browser_container(tmp_path, transport)
    ctx = _ctx(scope="agent:ambiguous")
    _open(container, ctx)
    result = _approve(
        container, Action(action_type=f"browser.{operation}", params=params), ctx,
    )
    assert result.status == "failed"
    with container.session_factory() as session:
        rows = container.audit_service.list(
            session, action_type=f"browser.{operation}", outcome="FAILED",
        )
    assert rows[-1].error_code == ProviderErrorCode.SIDE_EFFECT_UNKNOWN.value
    assert not transport.sessions
    assert transport.calls == 1


def test_agent_does_not_repeat_interaction_after_failed_postcondition(tmp_path):
    container, provider, transport = _browser_container(tmp_path)
    ctx = _ctx(scope="agent:postcondition")
    _open(container, ctx)
    task = Task(
        id="click", title="click once", action_type="browser.click",
        params={"selector": "#go"},
        verify={"kind": "dom_extracted", "min_chars": 1},
        max_attempts=3,
    )
    loop = AgentLoop(
        execution_service=container.execution_service,
        planner=RulePlanner(),
        brain=OfflineBrain(),
        verifier=Verifier(workspace_root=tmp_path / "workspace"),
        budget=AgentBudget(timeout_seconds=30),
        run_id="postcondition",
        approval_handler=lambda action, response: "approve",
    )
    record = loop.run("click once", ctx, plan=Plan(goal="click", tasks=[task]))
    assert record.status is RunStatus.FAILED
    assert record.tasks[0].status is TaskStatus.FAILED
    assert record.tasks[0].attempt == 0
    assert len(next(iter(transport.sessions.values())).clicks) == 1
    provider.close()


# -- cancellable/bounded Playwright command queue ---------------------------------

class _ControlledPlaywrightTransport(PlaywrightBrowserTransport):
    def __init__(self, *, queue_size=8):
        super().__init__(command_queue_size=queue_size, context_idle_seconds=60)
        self.entered = threading.Event()
        self.release = threading.Event()
        self.operations: list[str] = []

    def _ensure_runtime(self):
        return None

    def _dispatch(self, command):
        self.operations.append(command.operation)
        if len(self.operations) == 1:
            self.entered.set()
            self.release.wait(timeout=2)
        return {"url": PUBLIC_URL, "title": "controlled", "status": 200}


def test_expired_queued_command_is_cancelled_before_dispatch():
    transport = _ControlledPlaywrightTransport()
    first_error = []

    def first():
        try:
            transport.navigate(
                "one", PUBLIC_URL, wait_until="load", timeout_ms=1_000,
            )
        except ToolError as exc:
            first_error.append(exc)

    thread = threading.Thread(target=first)
    thread.start()
    assert transport.entered.wait(timeout=1)
    with pytest.raises(ToolError) as error:
        transport.navigate("two", PUBLIC_URL, wait_until="load", timeout_ms=20)
    assert error.value.code == ProviderErrorCode.TIMEOUT
    transport.release.set()
    thread.join(timeout=2)
    time.sleep(0.05)
    assert transport.operations == ["navigate"]
    assert not first_error
    transport.close()


def test_bounded_command_queue_fails_closed_when_full():
    transport = _ControlledPlaywrightTransport(queue_size=1)
    threads = [threading.Thread(
        target=lambda key=key: _ignore_tool_error(
            lambda: transport.navigate(
                key, PUBLIC_URL, wait_until="load", timeout_ms=1_000,
            )
        ),
    ) for key in ("one", "two")]
    threads[0].start()
    assert transport.entered.wait(timeout=1)
    threads[1].start()
    time.sleep(0.02)
    with pytest.raises(ToolError) as error:
        transport.navigate("three", PUBLIC_URL, wait_until="load", timeout_ms=20)
    assert error.value.code == ProviderErrorCode.UNAVAILABLE
    transport.release.set()
    for thread in threads:
        thread.join(timeout=2)
    transport.close()


def test_playwright_worker_classifies_mutating_timeout_as_ambiguous():
    class TimeoutTransport(_ControlledPlaywrightTransport):
        def _dispatch(self, command):
            raise TimeoutError("playwright timeout")

    transport = TimeoutTransport()
    with pytest.raises(ToolError) as error:
        transport.click(
            "scope", selector="#go", text=None, exact=False, timeout_ms=500,
        )
    assert error.value.code == ProviderErrorCode.SIDE_EFFECT_UNKNOWN
    transport.close()


def _ignore_tool_error(call):
    try:
        call()
    except ToolError:
        pass


class _FakeContext:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_provider_internal_timeout_stays_inside_outer_dispatch_deadline(tmp_path):
    class RecordingTransport(SimulatedBrowserTransport):
        timeout_ms = None

        def navigate(self, session_key, url, *, wait_until, timeout_ms):
            self.timeout_ms = timeout_ms
            return super().navigate(
                session_key, url, wait_until=wait_until, timeout_ms=timeout_ms,
            )

    transport = RecordingTransport({PUBLIC_URL: PAGE})
    provider = BrowserProvider(
        workspace_root=tmp_path, transport=transport, timeout_seconds=30,
    )
    ctx = _ctx(scope="agent:deadline").model_copy(update={
        "deadline": time.monotonic() + 1.0,
    })
    provider.execute(
        Action(action_type="browser.navigate", params={"url": PUBLIC_URL}), ctx,
    )
    assert 1 <= transport.timeout_ms <= 750


@pytest.mark.parametrize("proxy", [
    "ftp://proxy.example:21",
    "http://user:password@proxy.example:8080",
    "not-a-url",
])
def test_browser_proxy_configuration_rejects_unsafe_values(proxy):
    with pytest.raises(ValueError):
        PlaywrightBrowserTransport(proxy_server=proxy)


def test_idle_context_reaper_and_context_cap_are_fail_closed():
    transport = PlaywrightBrowserTransport(max_contexts=1, context_idle_seconds=1)
    old = _FakeContext()
    transport._contexts["old"] = _PlaywrightSession(
        context=old, page=object(), last_used=time.monotonic() - 2,
    )
    transport._reap_idle_contexts()
    assert old.closed and not transport._contexts

    active = _FakeContext()
    transport._contexts["active"] = _PlaywrightSession(
        context=active, page=object(), last_used=time.monotonic(),
    )
    transport._browser = SimpleNamespace(new_context=lambda **kwargs: None)
    with pytest.raises(ToolError) as error:
        transport._context_page("second")
    assert error.value.code == ProviderErrorCode.UNAVAILABLE
    transport._shutdown_runtime()


# -- vault-backed fill + persistence redaction ------------------------------------

def test_browser_fill_resolves_vault_reference_without_leaking_secret(tmp_path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path}/vault-fill.db",
        vault_master_key=MASTER_KEY,
    )
    resolver = VaultRefResolver()
    transport = SimulatedBrowserTransport({PUBLIC_URL: PAGE})
    container, _, _ = _browser_container(
        tmp_path, transport, settings=settings, resolver=resolver,
    )
    resolver.attach(container.vault_service)
    secret = "correct-horse-battery-staple"
    container.vault_service.store_or_rotate_secret(
        domain="browser", name="login_password", value=secret, actor_id="alice",
    )
    ctx = _ctx(scope="agent:vault")
    _open(container, ctx)
    action = Action(action_type="browser.fill", params={
        "selector": "#password",
        "value_ref": "vault:browser/login_password",
    })
    completed = _approve(container, action, ctx)
    assert completed.status == "executed"
    assert next(iter(transport.sessions.values())).fields["#password"] == secret
    assert secret not in completed.model_dump_json()

    with container.session_factory() as session:
        rows = container.audit_service.list(session, action_type="browser.fill")
    assert rows
    for row in rows:
        # Opaque references remain visible so approval can resubmit the exact
        # hash-bound action; only plaintext input values are secret fields.
        assert row.action_params["value_ref"] == "vault:browser/login_password"
        assert secret not in str(row.action_params)

    bob = ExecutionContext(actor_id="bob", execution_scope="agent:bob")
    provider = container.registry.get_provider("browser")
    provider.execute(
        Action(action_type="browser.navigate", params={"url": PUBLIC_URL}), bob,
    )
    with pytest.raises(ToolError) as ownership_error:
        provider.execute(action, bob)
    assert ownership_error.value.code == ProviderErrorCode.AUTH


def test_browser_fill_rejects_non_browser_or_malformed_vault_reference(tmp_path):
    _, provider, _ = _browser_container(tmp_path)
    for value_ref in ("not-a-ref", "vault:email/password", "vault:browser/"):
        with pytest.raises(ToolError) as error:
            provider.validate(Action(action_type="browser.fill", params={
                "selector": "#password", "value_ref": value_ref,
            }))
        assert error.value.code == ProviderErrorCode.VALIDATION


def test_plain_fill_text_is_redacted_from_confirmation_and_audit(tmp_path):
    container, _, _ = _browser_container(tmp_path)
    ctx = _ctx(scope="direct:fill")
    _open(container, ctx)
    secret = "one-time-private-input"
    action = Action(action_type="browser.fill", params={
        "selector": "#password", "text": secret,
    })
    pending = container.execution_service.request(action, ctx)
    with container.session_factory() as session:
        confirmation = container.confirmation_service.get(session, pending.confirmation_id)
        rows = container.audit_service.list(session, action_type="browser.fill")
    assert confirmation.action_params_redacted["text"] == REDACTED
    assert rows[-1].action_params["text"] == REDACTED
    assert secret not in str(confirmation.action_params_redacted)


def test_agent_rejects_and_erases_raw_browser_fill_value(tmp_path):
    container, _, transport = _browser_container(tmp_path)
    ctx = _ctx(scope="agent:raw-fill")
    _open(container, ctx)
    secret = "must-never-persist"
    plan = Plan(goal="fill", tasks=[Task(
        id="fill", title="fill", action_type="browser.fill",
        params={"selector": "#password", "text": secret},
    )])
    loop = AgentLoop(
        execution_service=container.execution_service,
        planner=RulePlanner(), brain=OfflineBrain(),
        verifier=Verifier(workspace_root=tmp_path / "workspace"),
        budget=AgentBudget(timeout_seconds=30), run_id="raw-fill",
    )
    record = loop.run("fill", ctx, plan=plan)
    assert record.status is RunStatus.FAILED
    assert record.tasks[0].params["text"] == REDACTED
    assert secret not in record.model_dump_json()
    assert next(iter(transport.sessions.values())).fields == {}


# -- centralized provider result boundary ----------------------------------------

def test_result_safety_redacts_nested_keys_and_token_patterns():
    result = sanitize_action_result(ActionResult(
        summary="received Bearer abcdefghijklmnop",
        data={
            "token": "plain-secret",
            "nested": {
                "value": "sk-abcdefghijklmno",
                "assignment": "password=hunter2",
                "url": "https://user:pass@example.com/private",
            },
            "safe": ["ok", 1, True, None],
        },
    ))
    assert result.summary == f"received {REDACTED}"
    assert result.data["token"] == REDACTED
    assert result.data["nested"]["value"] == REDACTED
    assert result.data["nested"]["assignment"] == REDACTED
    assert result.data["nested"]["url"] == f"{REDACTED}example.com/private"
    assert result.data["safe"] == ["ok", 1, True, None]


def test_result_safety_rejects_non_json_non_finite_and_oversized_data():
    with pytest.raises(UnsafeResultError):
        sanitize_action_result(ActionResult(data={"bad": object()}))
    with pytest.raises(UnsafeResultError):
        sanitize_action_result(ActionResult(data={"bad": float("nan")}))
    with pytest.raises(UnsafeResultError):
        sanitize_action_result(ActionResult(data={"large": "x" * 100}), max_bytes=32)


def test_execution_boundary_redacts_buggy_provider_result(tmp_path):
    class LeakyProvider:
        id = "leaky-runtime"
        action_types = frozenset({"stub.noop"})

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            return ActionResult(
                summary="Bearer abcdefghijklmnop",
                data={"password": "hunter2", "value": "ghp_abcdefghijklmno"},
            )

    container = build_container(
        Settings(database_url=f"sqlite:///{tmp_path}/leaky.db"),
        providers=[LeakyProvider()],
    )
    response = container.execution_service.request(
        Action(action_type="stub.noop"), _ctx(),
    )
    assert response.status == "executed"
    assert response.result.summary == REDACTED
    assert response.result.data == {"password": REDACTED, "value": REDACTED}
    assert "hunter2" not in response.model_dump_json()
    with container.session_factory() as session:
        rows = container.audit_service.list(session, action_type="stub.noop")
    assert rows[-1].result == REDACTED
    assert "abcdefghijklmnop" not in (rows[-1].result or "")


def test_unsafe_result_fails_once_without_retry_or_persistence_leak(tmp_path):
    class UnsafeProvider:
        id = "unsafe-runtime"
        action_types = frozenset({"stub.noop"})

        def __init__(self):
            self.calls = 0

        def validate(self, action):
            return None

        def execute(self, action, ctx):
            self.calls += 1
            return ActionResult(data={"custom": object()})

    provider = UnsafeProvider()
    container = build_container(
        Settings(database_url=f"sqlite:///{tmp_path}/unsafe.db"),
        providers=[provider],
    )
    response = container.execution_service.request(
        Action(action_type="stub.noop"), _ctx(),
    )
    assert response.status == "failed"
    assert response.message == "provider returned an unsafe result"
    assert provider.calls == 1
    with container.session_factory() as session:
        rows = container.audit_service.list(session, action_type="stub.noop")
    assert rows[-1].error_code == ProviderErrorCode.INTERNAL.value
