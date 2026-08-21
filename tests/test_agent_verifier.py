"""Verifier tests (Phase 3A) — the agent must not blindly trust tool success."""

from __future__ import annotations

import pytest

from era.agents.models import Observation, Task
from era.agents.verifier import Verifier


@pytest.fixture
def ws(tmp_path):
    (tmp_path / "site").mkdir()
    (tmp_path / "site" / "index.html").write_text(
        "<!DOCTYPE html><html><head><title>Home</title></head><body>"
        "<h1>Welding Academy</h1><nav><a href='safety.html'>Safety</a></nav>"
        "<section><p>Learn welding training today.</p></section>"
        "<footer>bye</footer></body></html>", encoding="utf-8")
    (tmp_path / "site" / "safety.html").write_text(
        "<!DOCTYPE html><html><head><title>Safety</title></head><body>"
        "<h1>Safety</h1><nav><a href='index.html'>Home</a></nav>"
        "<section><p>PPE rules.</p></section></body></html>", encoding="utf-8")
    return Verifier(workspace_root=tmp_path)


def _task(**verify):
    return Task(id="t", title="t", action_type="fs.read",
                params={"path": "site/index.html"}, verify=verify or None)


def _obs(status="executed"):
    return Observation(task_id="t", action_type="fs.read", status=status)


def test_action_success_verification(ws):
    ok = ws.verify(_task(), _obs("executed"))
    assert ok.ok
    bad = ws.verify(_task(), _obs("failed"))
    assert not bad.ok and "did not execute" in bad.reason


def test_file_exists(ws):
    task = _task(kind="file_exists", path="site/index.html", min_bytes=10)
    assert ws.verify(task, _obs()).ok
    missing = _task(kind="file_exists", path="site/nope.html")
    assert not ws.verify(missing, _obs()).ok
    too_small = _task(kind="file_exists", path="site/index.html", min_bytes=10 ** 9)
    assert not ws.verify(too_small, _obs()).ok


def test_html_valid_required_elements_and_keywords(ws):
    task = _task(kind="html_valid", path="site/index.html",
                 required_elements=["title", "h1", "nav", "section", "footer"],
                 keywords=["welding", "safety"])
    verdict = ws.verify(task, _obs())
    assert verdict.ok, verdict.reason
    broken = _task(kind="html_valid", path="site/index.html",
                   required_elements=["title", "h1", "nav", "table", "form"])
    assert not ws.verify(broken, _obs()).ok
    no_keyword = _task(kind="html_valid", path="site/index.html",
                       required_elements=["title"], keywords=["underwater-basket-weaving"])
    assert not ws.verify(no_keyword, _obs()).ok


def test_text_contains(ws):
    task = _task(kind="text_contains", path="site/index.html",
                 required=["welding training", "academy"])
    assert ws.verify(task, _obs()).ok
    missing = _task(kind="text_contains", path="site/index.html", required=["nope"])
    assert not ws.verify(missing, _obs()).ok


def test_links_resolve_detects_broken_links(ws):
    task = _task(kind="links_resolve",
                 pages=["site/index.html", "site/safety.html"])
    assert ws.verify(task, _obs()).ok
    broken = _task(kind="links_resolve", pages=["site/index.html", "site/ghost.html"])
    assert not ws.verify(broken, _obs()).ok


def test_links_resolve_ignores_external_links(ws):
    (ws.workspace_root / "site" / "index.html").write_text(
        "<a href='https://example.com'>ext</a><a href='mailto:a@b.c'>m</a>"
        "<a href='safety.html'>ok</a>", encoding="utf-8")
    task = _task(kind="links_resolve", pages=["site/index.html"])
    assert ws.verify(task, _obs()).ok


def test_path_escape_fails_closed(ws):
    evil = _task(kind="file_exists", path="../../etc/passwd")
    assert not ws.verify(evil, _obs()).ok
