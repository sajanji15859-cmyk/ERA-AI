"""Agent API tests — authenticated, permission-gated run endpoints (Phase 3A)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from era.config import Settings
from tests.conftest import create_principal


@pytest.fixture
def api(tmp_path, monkeypatch):
    from era.core.result import ProviderErrorCode, ToolError
    from era.providers.web import WebProvider

    def _offline(self, url, max_bytes):
        raise ToolError("offline (test)", provider_id="web",
                        code=ProviderErrorCode.UNAVAILABLE)

    monkeypatch.setattr(WebProvider, "_http_get", _offline)

    settings = Settings(database_url=f"sqlite:///{tmp_path}/agent.db",
                        agent_enabled=True,
                        agent_workspace_root=str(tmp_path / "ws"),
                        web_timeout_seconds=2.0)
    from era.main import create_app
    app = create_app(settings)
    container = app.state.container
    user = create_principal(container, username="tuser", role="user")
    admin = create_principal(container, username="tadmin", role="admin")
    with TestClient(app) as client:
        yield client, {"user": user, "admin": admin, "container": container}
    container.engine.dispose()


def _h(principals, which="user"):
    return {"Authorization": f"Bearer {principals[which]['raw_key']}"}


def test_agent_routes_absent_when_disabled(tmp_path):
    from era.main import create_app
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path}/plain.db"))
    with TestClient(app) as client:
        assert client.post("/v1/agent/runs", json={"goal": "x"}).status_code == 404
    app.state.container.engine.dispose()


def test_start_run_pauses_for_user_approval(api):
    client, p = api
    r = client.post("/v1/agent/runs", headers=_h(p),
                    json={"goal": "make me a welding training website"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "waiting_for_user"
    assert body["pending_confirmations"]
    run_id = body["run_id"]

    got = client.get(f"/v1/agent/runs/{run_id}", headers=_h(p))
    assert got.status_code == 200
    assert got.json()["status"] == "waiting_for_user"

    listed = client.get("/v1/agent/runs", headers=_h(p))
    assert listed.status_code == 200
    assert any(run["run_id"] == run_id for run in listed.json()["runs"])


def test_run_not_visible_to_other_actor(api):
    client, p = api
    r = client.post("/v1/agent/runs", headers=_h(p), json={"goal": "make a site"})
    run_id = r.json()["run_id"]
    got = client.get(f"/v1/agent/runs/{run_id}", headers=_h(p, "admin"))
    assert got.status_code == 404  # other actor: not found (no enumeration)


def test_deny_confirmation_then_continue(api):
    client, p = api
    run_id = client.post("/v1/agent/runs", headers=_h(p),
                         json={"goal": "make me a welding training website"}).json()["run_id"]
    record = p["container"].agent_service.get_run(run_id, p["user"]["user"].id)
    cid = record.pending_confirmations[0]

    denied = client.post(f"/v1/confirmations/{cid}/deny", headers=_h(p), json={})
    assert denied.status_code == 200

    continued = client.post(f"/v1/agent/runs/{run_id}/continue", headers=_h(p))
    assert continued.status_code == 200
    body = continued.json()
    denied_task = next(t for t in body["tasks"]
                       if t["status"] == "failed" and "denied" in (t["error"] or ""))
    assert denied_task


def test_approve_confirmation_then_continue_reaches_next_gate(api):
    client, p = api
    run_id = client.post("/v1/agent/runs", headers=_h(p),
                         json={"goal": "make me a welding training website"}).json()["run_id"]
    container = p["container"]
    record = container.agent_service.get_run(run_id, p["user"]["user"].id)
    cid = record.pending_confirmations[0]

    # Fetch the confirmation to learn the exact authorized params.
    conf = client.get(f"/v1/confirmations/{cid}", headers=_h(p)).json()
    approved = client.post(f"/v1/confirmations/{cid}/approve", headers=_h(p), json={
        "action_type": conf["action_type"],
        "params": conf["action_params"],
    })
    assert approved.status_code == 200
    assert approved.json()["status"] == "executed"

    # Continue: the approved task completes; the run reaches the next gate
    # (another MUTATING write) and pauses again — proof the loop advanced.
    continued = client.post(f"/v1/agent/runs/{run_id}/continue", headers=_h(p)).json()
    assert continued["status"] == "waiting_for_user"
    assert any(t["status"] == "completed" for t in continued["tasks"])
    assert continued["pending_confirmations"]


def test_agent_runs_require_authentication(api):
    client, _ = api
    assert client.post("/v1/agent/runs", json={"goal": "x"}).status_code == 401
    assert client.get("/v1/agent/runs").status_code == 401


def test_goal_validation(api):
    client, p = api
    r = client.post("/v1/agent/runs", headers=_h(p), json={"goal": "   "})
    assert r.status_code == 422
    r = client.post("/v1/agent/runs", headers=_h(p),
                    json={"goal": "x", "extra": "nope"})
    assert r.status_code == 422  # extra='forbid' hardening
