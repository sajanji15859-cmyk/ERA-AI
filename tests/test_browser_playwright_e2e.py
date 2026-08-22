"""Opt-in real Chromium E2E tests for Phase 4A.1 and Phase 4B.

Run with a locally installed Playwright Chromium binary and public network:

    ERA_TEST_BROWSER=1 pytest -m browser tests/test_browser_playwright_e2e.py

The tests are strictly opt-in (``ERA_TEST_BROWSER=1``): when skipped, the
skip reason is explicit and the offline/simulator suite remains the
authoritative green check.  A skipped test is never reported as a pass.
"""

from __future__ import annotations

import os

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.providers.browser import BrowserProvider

pytestmark = pytest.mark.browser

_SKIP_REASON = "set ERA_TEST_BROWSER=1 for real Chromium E2E"


@pytest.mark.skipif(os.getenv("ERA_TEST_BROWSER") != "1", reason=_SKIP_REASON)
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


@pytest.mark.skipif(os.getenv("ERA_TEST_BROWSER") != "1", reason=_SKIP_REASON)
def test_real_chromium_inspect_and_element_ref_workflow(tmp_path):
    """Phase 4B: inspect -> element_ref -> confirm -> revalidate -> click once.

    Exercises the primary reliable-workflow path on a real dynamic page: a
    bounded accessibility snapshot with provider-issued refs, a confirmed
    ref-based click, deterministic post-condition data and a sanitized
    receipt.  No selectors are invented anywhere.
    """
    url = os.getenv("ERA_TEST_BROWSER_URL", "https://example.com")
    provider = BrowserProvider(workspace_root=tmp_path, timeout_seconds=20)
    ctx = ExecutionContext(
        actor_id="browser-e2e", session_id="e2e", execution_scope="e2e:ref",
    )
    try:
        navigation = provider.execute(Action(
            action_type="browser.navigate", params={"url": url, "wait_until": "load"},
        ), ctx)
        snapshot = provider.execute(Action(
            action_type="browser.inspect", params={"max_elements": 100},
        ), ctx)
        data = snapshot.data
        assert navigation.success
        assert data["elements_shown"] > 0
        assert data["generation"] >= 1
        assert data["content_untrusted"] is True
        for element in data["elements"]:
            assert element["element_ref"].startswith("er_")
            assert element["tab_id"]
            assert element["frame_id"]
            assert element["origin"]
            # Sensitive metadata is never exposed by inspection.
            assert "value" not in element

        # Ref-based click: either succeeds with a receipt or fails closed
        # deterministically (e.g. the element disappeared on a dynamic page).
        target = data["elements"][0]
        clicked = provider.execute(Action(action_type="browser.click", params={
            "element_ref": target["element_ref"],
        }), ctx)
        assert clicked.success
        receipt = clicked.data
        assert receipt["tab_id"] == target["tab_id"]
        assert receipt["frame_id"] == target["frame_id"]
        assert "post_condition" in receipt

        # A fresh snapshot invalidates the old generation; reusing the old ref
        # must fail closed (never guess, never fall back to a selector).
        refreshed = provider.execute(Action(
            action_type="browser.inspect", params={"max_elements": 10},
        ), ctx)
        assert refreshed.data["generation"] > data["generation"]
        try:
            provider.execute(Action(action_type="browser.click", params={
                "element_ref": target["element_ref"],
            }), ctx)
        except Exception as error:  # noqa: BLE001 - deterministic fail-closed
            from era.core.result import ProviderErrorCode
            assert error.code in (ProviderErrorCode.CONFLICT,
                                  ProviderErrorCode.NOT_FOUND)
        else:
            raise AssertionError("stale element_ref resolved instead of failing closed")
    finally:
        provider.close()
