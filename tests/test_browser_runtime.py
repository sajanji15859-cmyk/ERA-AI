"""Phase 4A settings, runtime wiring and result-boundary integration tests."""

from __future__ import annotations

from era import __version__
from era.agent_runtime import build_agent_container, build_browser_provider
from era.config import Settings
from era.core.action import Action
from era.core.context import ExecutionContext
from era.providers.browser import PlaywrightBrowserTransport, SimulatedBrowserTransport

PUBLIC_URL = "https://93.184.216.34"
PAGE = "<html><head><title>Runtime</title></head><body><h1>Ready</h1></body></html>"


def test_browser_settings_defaults_and_version():
    settings = Settings()
    assert settings.browser_headless is True
    assert settings.browser_timeout_seconds == 30.0
    assert settings.browser_viewport_width == 1280
    assert settings.browser_viewport_height == 800
    assert settings.browser_user_agent == (
        "ERA-Agent/0.9.0 (+https://github.com/sajanji15859-cmyk/ERA-AI)"
    )
    assert settings.browser_max_contexts == 32
    assert settings.browser_context_idle_seconds == 300.0
    assert settings.browser_command_queue_size == 128
    assert settings.browser_proxy_server == ""
    assert settings.browser_element_ref_ttl_seconds == 120.0
    assert settings.browser_max_inspect_elements == 200
    assert settings.browser_max_download_bytes == 209715200
    assert settings.browser_max_upload_bytes == 104857600
    assert settings.provider_result_max_bytes == 524288
    assert settings.app_version == "0.9.0"
    assert __version__ == "0.9.0"


def test_browser_settings_load_exact_era_environment_names(monkeypatch):
    monkeypatch.setenv("ERA_BROWSER_HEADLESS", "false")
    monkeypatch.setenv("ERA_BROWSER_TIMEOUT_SECONDS", "12.5")
    monkeypatch.setenv("ERA_BROWSER_VIEWPORT_WIDTH", "1440")
    monkeypatch.setenv("ERA_BROWSER_VIEWPORT_HEIGHT", "900")
    monkeypatch.setenv("ERA_BROWSER_USER_AGENT", "ERA-Test-Browser")
    monkeypatch.setenv("ERA_BROWSER_MAX_CONTEXTS", "7")
    monkeypatch.setenv("ERA_BROWSER_CONTEXT_IDLE_SECONDS", "45")
    monkeypatch.setenv("ERA_BROWSER_COMMAND_QUEUE_SIZE", "9")
    monkeypatch.setenv("ERA_BROWSER_PROXY_SERVER", "http://egress-proxy:8080")
    monkeypatch.setenv("ERA_BROWSER_ELEMENT_REF_TTL_SECONDS", "45")
    monkeypatch.setenv("ERA_BROWSER_MAX_INSPECT_ELEMENTS", "77")
    monkeypatch.setenv("ERA_BROWSER_MAX_DOWNLOAD_BYTES", "1048576")
    monkeypatch.setenv("ERA_BROWSER_MAX_UPLOAD_BYTES", "524288")
    monkeypatch.setenv("ERA_PROVIDER_RESULT_MAX_BYTES", "262144")
    settings = Settings()
    assert settings.browser_headless is False
    assert settings.browser_timeout_seconds == 12.5
    assert (settings.browser_viewport_width, settings.browser_viewport_height) == (1440, 900)
    assert settings.browser_user_agent == "ERA-Test-Browser"
    assert settings.browser_max_contexts == 7
    assert settings.browser_context_idle_seconds == 45
    assert settings.browser_command_queue_size == 9
    assert settings.browser_proxy_server == "http://egress-proxy:8080"
    assert settings.browser_element_ref_ttl_seconds == 45
    assert settings.browser_max_inspect_elements == 77
    assert settings.browser_max_download_bytes == 1048576
    assert settings.browser_max_upload_bytes == 524288
    assert settings.provider_result_max_bytes == 262144


def test_build_browser_provider_applies_settings_without_starting_chromium(tmp_path):
    settings = Settings(
        browser_headless=False,
        browser_timeout_seconds=9.5,
        browser_viewport_width=1024,
        browser_viewport_height=768,
        browser_user_agent="ERA-Custom",
        browser_max_contexts=5,
        browser_context_idle_seconds=20,
        browser_command_queue_size=11,
        browser_proxy_server="http://proxy:3128",
    )
    provider = build_browser_provider(settings, tmp_path)
    assert provider.timeout_seconds == 9.5
    assert provider.viewport_width == 1024
    assert provider.viewport_height == 768
    assert provider.user_agent == "ERA-Custom"
    assert isinstance(provider.transport, PlaywrightBrowserTransport)
    assert provider.transport.max_contexts == 5
    assert provider.transport.context_idle_seconds == 20
    assert provider.transport._commands.maxsize == 11
    assert provider.transport.proxy_server == "http://proxy:3128"
    assert provider.transport._thread is None
    provider.close()


def test_build_browser_provider_supports_offline_transport_injection(tmp_path):
    transport = SimulatedBrowserTransport({PUBLIC_URL: PAGE})
    provider = build_browser_provider(Settings(), tmp_path, transport=transport)
    result = provider.execute(
        Action(action_type="browser.navigate", params={"url": PUBLIC_URL}),
        ExecutionContext(actor_id="a", session_id="run"),
    )
    assert result.data["title"] == "Runtime"
    assert provider.transport is transport


def test_agent_runtime_registers_real_browser_and_stub_does_not_claim_it(tmp_path):
    container = build_agent_container(Settings(
        database_url=f"sqlite:///{tmp_path}/browser-runtime.db",
        agent_workspace_root=str(tmp_path / "workspace"),
    ))
    browser = container.registry.get_provider("browser")
    stub = container.registry.get_provider("stub")
    assert browser is not None
    assert browser.action_types == {
        "browser.navigate", "browser.screenshot", "browser.extract_dom",
        "browser.click", "browser.fill", "browser.submit",
        # Phase 4B
        "browser.inspect", "browser.tabs", "browser.activate_tab",
        "browser.download", "browser.upload",
    }
    assert not (browser.action_types & stub.action_types)
    assert container.registry.get("browser.navigate") is browser
    browser.close()
    container.engine.dispose()


def test_execution_service_preserves_safe_provider_result_data(tmp_path):
    transport = SimulatedBrowserTransport({PUBLIC_URL: PAGE})
    settings = Settings(
        database_url=f"sqlite:///{tmp_path}/result-data.db",
        agent_workspace_root=str(tmp_path / "workspace"),
    )
    provider = build_browser_provider(settings, tmp_path / "workspace", transport=transport)
    from era.container import build_container
    container = build_container(settings, providers=[provider])
    ctx = ExecutionContext(actor_id="actor", session_id="run")

    opened = container.execution_service.request(
        Action(action_type="browser.navigate", params={"url": PUBLIC_URL}), ctx,
    )
    extracted = container.execution_service.request(
        Action(action_type="browser.extract_dom", params={}), ctx,
    )
    assert opened.result.data["title"] == "Runtime"
    assert extracted.result.data["text"] == "Runtime Ready"
    assert extracted.result.data["markdown"]
    assert extracted.result.data["links"] == []
    container.engine.dispose()


def test_provider_uses_configured_internal_wall_clock_timeout(tmp_path):
    class RecordingTransport(SimulatedBrowserTransport):
        seen_timeout_ms = None

        def navigate(self, session_key, url, *, wait_until, timeout_ms):
            self.seen_timeout_ms = timeout_ms
            return super().navigate(
                session_key, url, wait_until=wait_until, timeout_ms=timeout_ms,
            )

    transport = RecordingTransport({PUBLIC_URL: PAGE})
    provider = build_browser_provider(
        Settings(browser_timeout_seconds=2.75), tmp_path, transport=transport,
    )
    provider.execute(
        Action(action_type="browser.navigate", params={"url": PUBLIC_URL}),
        ExecutionContext(actor_id="a"),
    )
    assert transport.seen_timeout_ms == 2750
