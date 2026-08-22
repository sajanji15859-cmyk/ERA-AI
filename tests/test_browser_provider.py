"""Phase 4A browser provider, sandbox, SSRF and transport contract tests."""

from __future__ import annotations

import socket

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import Outcome
from era.core.result import ProviderErrorCode, ToolError
from era.providers.browser import (
    BrowserProvider,
    PlaywrightBrowserTransport,
    SimulatedBrowserTransport,
    guard_browser_request,
)
from era.registry.actions import ACTION_CATALOG
from era.security.rbac import ACTION_DOMAIN_ALLOWLIST, Role, role_domain_allowed
from era.security.validation import ValidationError_, validate_param_schema
from tests.conftest import make_container
from tests.provider_contract import assert_provider_contract

PUBLIC_URL = "https://93.184.216.34"
PAGE = """<!doctype html><html><head><title>Live Dashboard</title>
<style>.hidden {display:none}</style><script>window.secret = 'ignore me'</script></head>
<body><main><h1>Live score</h1><p>ERA leads by 42 points.</p>
<a href='/details'>Read details</a><form id='search'><input id='q'></form></main></body></html>"""


@pytest.fixture
def browser(tmp_path):
    transport = SimulatedBrowserTransport({PUBLIC_URL: PAGE})
    provider = BrowserProvider(workspace_root=tmp_path, transport=transport)
    return provider, transport


def _ctx(actor: str = "actor-a", session: str = "run-1") -> ExecutionContext:
    return ExecutionContext(actor_id=actor, session_id=session)


def _navigate(provider: BrowserProvider, ctx: ExecutionContext | None = None):
    return provider.execute(
        Action(action_type="browser.navigate", params={"url": PUBLIC_URL}),
        ctx or _ctx(),
    )


def test_browser_provider_contract_offline(browser):
    provider, _ = browser
    assert_provider_contract(
        provider,
        sample_action=Action(action_type="browser.navigate", params={"url": PUBLIC_URL}),
    )


def test_navigate_returns_public_page_metadata(browser):
    provider, _ = browser
    result = _navigate(provider)
    assert result.success
    assert result.data == {"url": PUBLIC_URL, "title": "Live Dashboard", "status": 200}
    assert PUBLIC_URL in result.summary


@pytest.mark.parametrize("url", [
    "http://127.0.0.1",
    "http://10.1.2.3",
    "http://192.168.1.4",
    "http://172.16.0.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
])
def test_navigate_blocks_private_loopback_link_local_and_metadata(browser, url):
    provider, transport = browser
    with pytest.raises(ToolError) as error:
        provider.execute(Action(action_type="browser.navigate", params={"url": url}), _ctx())
    assert error.value.code == ProviderErrorCode.FORBIDDEN
    assert not transport.sessions


def test_navigate_rechecks_url_at_execute_time(browser, monkeypatch):
    provider, _ = browser
    calls = []

    def guard(url):
        calls.append(url)
        return "https", "93.184.216.34", 443

    monkeypatch.setattr("era.providers.browser.validate_public_url", guard)
    _navigate(provider)
    # BrowserProvider.execute calls validate(), then repeats immediately before
    # transport dispatch. This is intentionally more than a one-time API check.
    assert calls == [PUBLIC_URL, PUBLIC_URL]


def test_browser_network_guard_blocks_non_network_and_private_schemes():
    guard_browser_request("data:text/plain,hello")
    guard_browser_request("blob:https://example.com/id")
    guard_browser_request("about:blank")
    guard_browser_request(PUBLIC_URL)
    with pytest.raises(ToolError) as ftp:
        guard_browser_request("ftp://example.com/file")
    assert ftp.value.code == ProviderErrorCode.FORBIDDEN
    with pytest.raises(ToolError):
        guard_browser_request("http://127.0.0.1/admin")


def test_dns_resolution_to_private_address_is_blocked(browser, monkeypatch):
    provider, _ = browser

    def private_dns(*args, **kwargs):
        del args, kwargs
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.40", 443))]

    monkeypatch.setattr("era.security.url_safety.socket.getaddrinfo", private_dns)
    with pytest.raises(ToolError) as error:
        provider.validate(Action(
            action_type="browser.navigate", params={"url": "https://internal.example"},
        ))
    assert error.value.code == ProviderErrorCode.FORBIDDEN


def test_screenshot_is_workspace_confined_and_valid_png(browser, tmp_path):
    provider, _ = browser
    _navigate(provider)
    result = provider.execute(Action(
        action_type="browser.screenshot", params={"path": "shots/dashboard.png"},
    ), _ctx())
    saved = tmp_path / "shots" / "dashboard.png"
    assert result.data["path"] == "shots/dashboard.png"
    assert result.data["bytes"] == saved.stat().st_size
    assert saved.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")


@pytest.mark.parametrize("path", ["../escape.png", "/tmp/escape.png", "shots/no-extension"])
def test_screenshot_rejects_escape_absolute_and_bad_extension(browser, path):
    provider, _ = browser
    with pytest.raises(ToolError) as error:
        provider.validate(Action(action_type="browser.screenshot", params={"path": path}))
    assert error.value.code in {ProviderErrorCode.FORBIDDEN, ProviderErrorCode.VALIDATION}


def test_screenshot_rejects_symlink_escape(browser, tmp_path):
    provider, _ = browser
    outside = tmp_path.parent / "outside-browser"
    outside.mkdir(exist_ok=True)
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ToolError) as error:
        provider.validate(Action(
            action_type="browser.screenshot", params={"path": "linked/escape.png"},
        ))
    assert error.value.code == ProviderErrorCode.FORBIDDEN


def test_element_screenshot_cannot_also_be_full_page(browser):
    provider, _ = browser
    with pytest.raises(ToolError, match="cannot use full_page"):
        provider.validate(Action(
            action_type="browser.screenshot",
            params={"path": "x.png", "selector": "main", "full_page": True},
        ))


def test_extract_dom_returns_clean_text_markdown_links_and_html_dump(browser, tmp_path):
    provider, _ = browser
    _navigate(provider)
    result = provider.execute(Action(
        action_type="browser.extract_dom",
        params={"max_chars": 5000, "save_html_path": "dom/dashboard.html"},
    ), _ctx())
    assert "ERA leads by 42 points" in result.data["text"]
    assert "window.secret" not in result.data["text"]
    assert "# Live score" in result.data["markdown"]
    assert result.data["links"] == [{
        "text": "Read details", "url": f"{PUBLIC_URL}/details",
    }]
    assert result.data["html_path"] == "dom/dashboard.html"
    assert (tmp_path / "dom" / "dashboard.html").read_text(encoding="utf-8") == PAGE


def test_extract_dom_honours_output_character_bound(browser):
    provider, _ = browser
    _navigate(provider)
    result = provider.execute(Action(
        action_type="browser.extract_dom", params={"max_chars": 12},
    ), _ctx())
    assert len(result.data["text"]) <= 12
    assert len(result.data["markdown"]) <= 12


@pytest.mark.parametrize("params", [
    {"max_chars": 0},
    {"max_chars": 100_001},
    {"save_html_path": "../dump.html"},
    {"save_html_path": "dump.txt"},
])
def test_extract_dom_rejects_invalid_bounds_and_dump_paths(browser, params):
    provider, _ = browser
    with pytest.raises(ToolError):
        provider.validate(Action(action_type="browser.extract_dom", params=params))


def test_click_supports_selector_or_visible_text(browser):
    provider, transport = browser
    _navigate(provider)
    provider.execute(Action(
        action_type="browser.click", params={"selector": "#open"},
    ), _ctx())
    provider.execute(Action(
        action_type="browser.click", params={"text": "Read details", "exact": True},
    ), _ctx())
    state = next(iter(transport.sessions.values()))
    assert state.clicks == [
        {"selector": "#open", "text": None, "exact": False},
        {"selector": None, "text": "Read details", "exact": True},
    ]


@pytest.mark.parametrize("params", [{}, {"selector": "#x", "text": "X"}])
def test_click_requires_exactly_one_target(browser, params):
    provider, _ = browser
    with pytest.raises(ToolError, match="exactly one"):
        provider.validate(Action(action_type="browser.click", params=params))


def test_fill_and_submit_change_only_the_current_simulated_context(browser):
    provider, transport = browser
    _navigate(provider)
    fill = provider.execute(Action(
        action_type="browser.fill", params={"selector": "#q", "text": "private query"},
    ), _ctx())
    submit = provider.execute(Action(
        action_type="browser.submit", params={"selector": "#search"},
    ), _ctx())
    state = next(iter(transport.sessions.values()))
    assert fill.summary == "filled browser input"
    assert submit.summary == "submitted browser form"
    assert state.fields == {"#q": "private query"}
    assert state.submitted is True
    # Filled text is deliberately absent from provider results.
    assert "private query" not in fill.model_dump_json()


def test_actions_require_an_open_page(browser):
    provider, _ = browser
    with pytest.raises(ToolError) as error:
        provider.execute(Action(
            action_type="browser.screenshot", params={"path": "x.png"},
        ), _ctx())
    assert error.value.code == ProviderErrorCode.NOT_FOUND


def test_contexts_are_isolated_by_actor_and_session(browser):
    provider, transport = browser
    contexts = [_ctx("alice", "run-1"), _ctx("bob", "run-1"), _ctx("alice", "run-2")]
    for ctx in contexts:
        _navigate(provider, ctx)
    for index, ctx in enumerate(contexts):
        provider.execute(Action(
            action_type="browser.fill",
            params={"selector": "#q", "text": f"value-{index}"},
        ), ctx)
    assert len(transport.sessions) == 3
    assert {s.fields["#q"] for s in transport.sessions.values()} == {
        "value-0", "value-1", "value-2",
    }


def test_close_context_discards_ephemeral_state(browser):
    provider, transport = browser
    _navigate(provider)
    assert len(transport.sessions) == 1
    provider.close_context(_ctx())
    assert not transport.sessions
    provider.close()
    assert transport.closed is True


def test_playwright_transport_is_lazy_and_close_does_not_import_browser():
    transport = PlaywrightBrowserTransport()
    assert transport._thread is None
    transport.close()
    assert transport._thread is None


def test_transport_timeout_is_normalized(tmp_path):
    class TimesOut(SimulatedBrowserTransport):
        def navigate(self, session_key, url, *, wait_until, timeout_ms):
            del session_key, url, wait_until, timeout_ms
            raise TimeoutError("vendor text should not leak")

    provider = BrowserProvider(workspace_root=tmp_path, transport=TimesOut())
    with pytest.raises(ToolError) as error:
        _navigate(provider)
    assert error.value.code == ProviderErrorCode.TIMEOUT
    assert "vendor text" not in str(error.value)


def test_browser_catalog_schemas_are_strict():
    actions = [
        "browser.navigate", "browser.screenshot", "browser.extract_dom",
        "browser.click", "browser.fill", "browser.submit",
        # Phase 4B
        "browser.inspect", "browser.tabs", "browser.activate_tab",
        "browser.download", "browser.upload",
    ]
    for action_type in actions:
        spec = ACTION_CATALOG.get(action_type)
        assert spec is not None
        assert spec.capability_domain == "browser"
        assert spec.param_schema["type"] == "object"
        assert spec.param_schema["additionalProperties"] is False

    click_schema = ACTION_CATALOG.get("browser.click").param_schema
    assert validate_param_schema({"selector": "#ok"}, click_schema)
    with pytest.raises(ValidationError_, match="exactly one"):
        validate_param_schema({}, click_schema)
    with pytest.raises(ValidationError_, match="exactly one"):
        validate_param_schema({"selector": "#x", "text": "X"}, click_schema)


def test_user_and_admin_roles_allow_browser_domain():
    assert "browser" in ACTION_DOMAIN_ALLOWLIST[Role.USER]
    assert "browser" in ACTION_DOMAIN_ALLOWLIST[Role.ADMIN]
    assert role_domain_allowed("user", "browser")
    assert role_domain_allowed("admin", "browser")
    assert not role_domain_allowed("admin", "unknown-future-domain")


@pytest.mark.parametrize("action_type,params", [
    ("browser.click", {"selector": "#button"}),
    ("browser.fill", {"selector": "#q", "text": "hello"}),
    ("browser.submit", {"selector": "#search"}),
])
def test_mutating_browser_actions_use_confirmation_and_audit_gate(
    tmp_path, action_type, params,
):
    transport = SimulatedBrowserTransport({PUBLIC_URL: PAGE})
    provider = BrowserProvider(workspace_root=tmp_path / "ws", transport=transport)
    container = make_container(tmp_path, providers=[provider])
    ctx = _ctx()

    opened = container.execution_service.request(
        Action(action_type="browser.navigate", params={"url": PUBLIC_URL}), ctx,
    )
    assert opened.status == "executed"
    assert opened.result.data["title"] == "Live Dashboard"

    action = Action(action_type=action_type, params=params)
    pending = container.execution_service.request(action, ctx)
    assert pending.status == "confirmation_required"
    # No mutation happens before explicit approval.
    state = next(iter(transport.sessions.values()))
    assert not state.clicks and not state.fields and not state.submitted

    done = container.execution_service.approve(pending.confirmation_id, action, ctx)
    assert done.status == "executed"
    with container.session_factory() as session:
        entries = container.audit_service.list(session, action_type=action_type)
    assert [entry.outcome for entry in entries] == [
        Outcome.PENDING.value, Outcome.AUTHORIZED.value, Outcome.EXECUTED.value,
    ]


def test_schema_rejects_unknown_browser_parameter_before_transport(tmp_path):
    transport = SimulatedBrowserTransport({PUBLIC_URL: PAGE})
    provider = BrowserProvider(workspace_root=tmp_path / "ws", transport=transport)
    container = make_container(tmp_path, providers=[provider])
    response = container.execution_service.request(Action(
        action_type="browser.extract_dom", params={"unexpected": True},
    ), _ctx())
    assert response.status == "rejected"
    assert "unknown parameter" in response.message
    assert not transport.sessions
