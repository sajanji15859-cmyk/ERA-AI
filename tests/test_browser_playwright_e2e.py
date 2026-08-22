"""Opt-in real Chromium smoke test for Phase 4A.1.

Run with a locally installed Playwright Chromium binary and public network:

    ERA_TEST_BROWSER=1 pytest -m browser tests/test_browser_playwright_e2e.py
"""

from __future__ import annotations

import os

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.providers.browser import BrowserProvider

pytestmark = pytest.mark.browser


@pytest.mark.skipif(os.getenv("ERA_TEST_BROWSER") != "1",
                    reason="set ERA_TEST_BROWSER=1 for real Chromium E2E")
def test_real_chromium_navigation_dom_and_screenshot(tmp_path):
    url = os.getenv("ERA_TEST_BROWSER_URL", "https://example.com")
    provider = BrowserProvider(workspace_root=tmp_path, timeout_seconds=20)
    ctx = ExecutionContext(
        actor_id="browser-e2e", session_id="e2e", execution_scope="e2e:one",
    )
    try:
        navigation = provider.execute(Action(
            action_type="browser.navigate", params={"url": url, "wait_until": "load"},
        ), ctx)
        dom = provider.execute(Action(
            action_type="browser.extract_dom", params={"max_chars": 10_000},
        ), ctx)
        screenshot = provider.execute(Action(
            action_type="browser.screenshot", params={"path": "e2e/page.png"},
        ), ctx)
    finally:
        provider.close()

    assert navigation.success and navigation.data["url"].startswith("http")
    assert dom.data["text"].strip()
    assert isinstance(dom.data["links"], list)
    assert screenshot.data["bytes"] > 100
    assert (tmp_path / "e2e" / "page.png").is_file()
