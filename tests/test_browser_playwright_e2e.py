"""Opt-in real Chromium E2E tests for Phase 4A.1, Phase 4B and Phase 4C.

Run with a locally installed Playwright Chromium binary and public network:

    ERA_TEST_BROWSER=1 pytest -m browser tests/test_browser_playwright_e2e.py

The tests are strictly opt-in (``ERA_TEST_BROWSER=1``): when skipped, the
skip reason is explicit and the offline/simulator suite remains the
authoritative green check.  A skipped test is never reported as a pass.
"""

from __future__ import annotations

import os

import pytest

from era.config import Settings
from era.container import build_container
from era.core.action import Action
from era.core.context import ExecutionContext
from era.providers.browser import BrowserProvider
from era.security.rbac import role_domain_allowed
from era.workflows.definition import WorkflowDefinition, WorkflowStep

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


@pytest.mark.skipif(os.getenv("ERA_TEST_BROWSER") != "1", reason=_SKIP_REASON)
def test_real_chromium_workflow_engine(tmp_path):
    """Phase 4C: run a declarative workflow through the engine on real Chromium.

    Exercises the full engine path (workflow engine -> ExecutionService -> real
    Playwright Chromium provider -> durable run) against a public page. The
    workflow uses only SAFE/SENSITIVE steps so it completes without a
    confirmation pause, and needs no vault (no secret fills).
    """
    url = os.getenv("ERA_TEST_BROWSER_URL", "https://example.com")
    container = build_container(
        Settings(database_url=f"sqlite:///{tmp_path}/wf-e2e.db"),
        providers=[BrowserProvider(workspace_root=tmp_path, timeout_seconds=20)],
    )
    try:
        user = container.auth_service.create_user(username="wfe2e", role="user")
        ctx = ExecutionContext(actor_id=user.id, session_id="e2e")

        def guard(action_type: str) -> bool:
            spec = container.catalog.get(action_type)
            return spec is not None and role_domain_allowed("user",
                                                            spec.capability_domain)

        wf = WorkflowDefinition(name="e2e_browse", version=1, steps=[
            WorkflowStep(id="nav", action="browser.navigate",
                         params={"url": url, "wait_until": "load"}),
            WorkflowStep(id="extract", action="browser.extract_dom",
                         params={"max_chars": 5_000}),
        ])
        run = container.workflow_service.start(
            definition=wf, params={}, ctx=ctx, run_token="e2e-run",
            domain_allowed=guard)
        assert run.status == "completed"
        run, steps = container.workflow_service.get_run(run.id, ctx)
        assert [s.step_id for s in steps] == ["nav", "extract"]
        assert all(s.status == "completed" for s in steps)
        # The extract receipt is bounded and contains no secrets/refs.
        assert "element_ref" not in str(steps[1].result_receipt)
    finally:
        container.engine.dispose()
        for provider in container.registry.list_providers():
            close = getattr(provider, "close", None)
            if callable(close):
                close()
