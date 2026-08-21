"""Web UI / chat dashboard tests (Phase 3E).

Covers the static dashboard serving, the ``/v1/me`` identity introspection
endpoint, and the response-hardening headers (CSP, clickjacking, MIME
sniffing). The UI itself is a static client over the authenticated API, so the
auth/authorization/confirmation behavior is already locked by the Phase 2A–3B
suites — here we assert the dashboard is served correctly and cannot weaken
those guarantees.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from era.config import Settings
from tests.conftest import create_principal


@pytest.fixture
def ui_app(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/ui.db")
    from era.main import create_app
    app = create_app(settings)
    container = app.state.container
    user = create_principal(container, username="tuser", role="user")
    with TestClient(app) as client:
        yield client, {"user": user, "container": container}
    container.engine.dispose()


@pytest.fixture
def agent_app(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/agent-ui.db",
                        agent_enabled=True,
                        agent_workspace_root=str(tmp_path / "ws"))
    from era.main import create_app
    app = create_app(settings)
    container = app.state.container
    user = create_principal(container, username="tuser", role="user")
    with TestClient(app) as client:
        yield client, {"user": user, "container": container}
    container.engine.dispose()


def _h(principal):
    return {"Authorization": f"Bearer {principal['raw_key']}"}


# -- static serving -------------------------------------------------------------

def test_index_serves_dashboard(ui_app):
    client, _ = ui_app
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "chat dashboard" in resp.text.lower() or "ERA" in resp.text


def test_index_is_not_cached(ui_app):
    client, _ = ui_app
    resp = client.get("/")
    assert resp.headers.get("cache-control") == "no-store"


def test_index_references_external_assets(ui_app):
    client, _ = ui_app
    html = client.get("/").text
    assert "/static/app.js" in html
    assert "/static/styles.css" in html


def test_static_assets_served(ui_app):
    client, _ = ui_app
    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert "application/javascript" in js.headers["content-type"] \
        or "text/javascript" in js.headers["content-type"]
    css = client.get("/static/styles.css")
    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")


def test_dashboard_served_even_without_agent_runtime(ui_app):
    client, _ = ui_app
    assert client.get("/").status_code == 200
    assert client.get("/static/app.js").status_code == 200


# -- /v1/me identity introspection ---------------------------------------------

def test_me_requires_auth(ui_app):
    client, _ = ui_app
    assert client.get("/v1/me").status_code == 401


def test_me_rejects_revoked_key(ui_app):
    client, p = ui_app
    container = p["container"]
    key_id = p["user"]["api_key"].id
    container.auth_service.revoke_key(key_id)
    resp = client.get("/v1/me", headers=_h(p["user"]))
    assert resp.status_code == 401


def test_me_returns_identity(ui_app):
    client, p = ui_app
    resp = client.get("/v1/me", headers=_h(p["user"]))
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "tuser"
    assert data["role"] == "user"
    assert data["agent_enabled"] is False
    assert data["app_version"]


def test_me_reports_agent_enabled(agent_app):
    client, p = agent_app
    resp = client.get("/v1/me", headers=_h(p["user"]))
    assert resp.status_code == 200
    assert resp.json()["agent_enabled"] is True


def test_me_never_echoes_secret(ui_app):
    client, p = ui_app
    raw = p["user"]["raw_key"]
    body = client.get("/v1/me", headers=_h(p["user"])).text
    assert raw not in body


# -- security headers -----------------------------------------------------------

def test_security_headers_on_index(ui_app):
    client, _ = ui_app
    resp = client.get("/")
    assert "frame-ancestors" in resp.headers["content-security-policy"]
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "no-referrer"


def test_security_headers_on_static_assets(ui_app):
    client, _ = ui_app
    resp = client.get("/static/app.js")
    assert "content-security-policy" in resp.headers
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_security_headers_on_api_responses(ui_app):
    client, p = ui_app
    resp = client.get("/v1/me", headers=_h(p["user"]))
    assert "content-security-policy" in resp.headers
    assert resp.headers["x-frame-options"] == "DENY"


def test_security_headers_on_error_responses(ui_app):
    client, _ = ui_app
    resp = client.get("/v1/me")  # 401
    assert resp.status_code == 401
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_security_headers_on_sse_stream(agent_app):
    client, p = agent_app
    with client.stream("POST", "/v1/agent/chat", headers=_h(p["user"]),
                       json={"message": "say hello"}) as resp:
        assert resp.status_code == 200
        assert "content-security-policy" in resp.headers
        assert resp.headers["x-frame-options"] == "DENY"
