"""Tests for Phase 3H: Website Builder first-class capability."""

from __future__ import annotations

import zipfile

import pytest

from era.agent import _demo_approver
from era.agent_runtime import build_agent_container
from era.agents.models import RunStatus
from era.agents.planner import _extract_subject
from era.agents.website_builder import (
    export_site_to_zip,
    generate_favicon_svg,
    render_html_page,
    slugify,
)
from era.config import Settings
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError
from era.providers.web import WebProvider


def test_subject_extraction():
    assert _extract_subject("meri bakery ki website banao") == "bakery"
    assert _extract_subject("mere liye ek welding training website banao") == "welding training"
    assert _extract_subject("build a website about photography") == "photography"
    assert _extract_subject("create a website for yoga studio") == "yoga studio"
    assert _extract_subject("make me a welding site") == "welding"


def test_slugify():
    assert slugify("Welding Training") == "welding_training"
    assert slugify("Yoga & Wellness Studio!") == "yoga_wellness_studio"


def test_favicon_generation():
    svg = generate_favicon_svg("Bakery")
    assert "<svg" in svg
    assert "</svg>" in svg
    assert ">B<" in svg


def test_render_html_page():
    html_doc = render_html_page(
        site_name="Artisan Bakery",
        tagline="Fresh bread every morning",
        subject="Bakery",
        page_title="Artisan Bakery — Home",
        current_page="index.html",
        nav_links=[("index.html", "Home"), ("about.html", "About"), ("contact.html", "Contact")],
        sections=[("Our Specials", ["Sourdough", "Croissants"])],
        is_contact=True,
    )
    assert "<!DOCTYPE html>" in html_doc
    assert "<nav id=\"mainNav\">" in html_doc
    assert "href=\"index.html\"" in html_doc
    assert "href=\"about.html\"" in html_doc
    assert "href=\"contact.html\"" in html_doc
    assert "contactForm" in html_doc
    assert "assets/favicon.svg" in html_doc
    assert "assets/style.css" in html_doc
    assert "assets/app.js" in html_doc


@pytest.fixture
def agent_env(tmp_path, monkeypatch):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path}/site_demo.db",
        agent_workspace_root=str(tmp_path / "workspace"),
        web_timeout_seconds=2.0,
    )
    container = build_agent_container(settings)
    user = container.auth_service.create_user(username="web-builder-user", role="user")
    ctx = ExecutionContext(actor_id=user.id, session_id="web-build")

    def _offline(self, url, max_bytes):
        raise ToolError("offline", provider_id="web", code=ProviderErrorCode.UNAVAILABLE)

    monkeypatch.setattr(WebProvider, "_http_get", _offline)

    root = container.agent_service.verifier.workspace_root
    approver = _demo_approver(container.execution_service, root, verbose=False)
    yield container, ctx, approver, root
    container.engine.dispose()


def test_website_builder_end_to_end_hinglish_goal(agent_env):
    container, ctx, approver, root = agent_env
    record = container.agent_service.start_run(
        "meri bakery ki website banao",
        ctx,
        approval_handler=approver,
    )

    assert record.status is RunStatus.COMPLETED
    assert record.result.tasks_completed >= 8

    site_dir = root / "bakery_site"
    assert site_dir.is_dir()
    assert (site_dir / "index.html").is_file()
    assert (site_dir / "about.html").is_file()
    assert (site_dir / "contact.html").is_file()
    assert (site_dir / "assets" / "style.css").is_file()
    assert (site_dir / "assets" / "app.js").is_file()
    assert (site_dir / "assets" / "favicon.svg").is_file()

    # Verify no broken internal links using verifier
    from era.agents.models import Observation, Task
    dummy_obs = Observation(task_id="check-links", action_type="fs.read", status="executed", success=True, summary="ok")
    link_task = Task(
        id="check-links",
        title="Check links",
        action_type="fs.read",
        params={"path": "bakery_site/index.html"},
        verify={"kind": "links_resolve", "pages": ["bakery_site/index.html", "bakery_site/about.html", "bakery_site/contact.html"]},
    )
    link_verdict = container.agent_service.verifier.verify(link_task, dummy_obs)
    assert link_verdict.ok is True, f"broken links: {link_verdict.reason}"

    # Export to zip archive
    zip_bytes = export_site_to_zip(site_dir)
    assert len(zip_bytes) > 200

    zip_file = root / "bakery_site.zip"
    zip_file.write_bytes(zip_bytes)
    with zipfile.ZipFile(zip_file, "r") as zf:
        names = zf.namelist()
        assert "index.html" in names
        assert "about.html" in names
        assert "contact.html" in names
        assert "assets/style.css" in names
        assert "assets/favicon.svg" in names
