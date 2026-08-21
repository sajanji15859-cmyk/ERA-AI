"""Agent chat (SSE) API tests — Phase 3B streaming endpoints."""

from __future__ import annotations

import json

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

    settings = Settings(database_url=f"sqlite:///{tmp_path}/chat.db",
                        agent_enabled=True,
                        agent_workspace_root=str(tmp_path / "ws"),
                        web_timeout_seconds=2.0)
    from era.main import create_app
    app = create_app(settings)
    container = app.state.container
    user = create_principal(container, username="tuser", role="user")
    with TestClient(app) as client:
        yield client, {"user": user, "container": container}
    container.engine.dispose()


def _h(principals):
    return {"Authorization": f"Bearer {principals['user']['raw_key']}"}


def _parse_sse(lines):
    events = []
    for line in lines:
        if isinstance(line, bytes):
            line = line.decode("utf-8")
        if line.startswith("data: "):
            events.append(json.loads(line[len("data: "):]))
    return events


def test_chat_streams_events_and_pauses_for_approval(api):
    client, p = api
    with client.stream("POST", "/v1/agent/chat", headers=_h(p),
                       json={"message": "make me a welding training website"}) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        events = _parse_sse(resp.iter_lines())

    types = [e["type"] for e in events]
    assert types[0] == "run_started"
    assert "plan_created" in types
    assert "tool_call" in types
    assert "confirmation_required" in types
    assert "observation" in types
    assert types[-1] == "run_finished"
    final = events[-1]
    assert final["data"]["status"] == "waiting_for_user"
    assert final["data"]["pending_confirmations"]
    run_id = final["run_id"]

    # Event history endpoint replays the same stream.
    got = client.get(f"/v1/agent/runs/{run_id}/events", headers=_h(p))
    assert got.status_code == 200
    history = got.json()["events"]
    assert [e["type"] for e in history][-1] == "run_finished"
    assert len(history) >= len(events)


def _approve_all(api, run_id):
    """Approve every pending confirmation of the run (user-side helper)."""
    client, p = api
    record = p["container"].agent_service.get_run(run_id, p["user"]["user"].id)
    if record is None:
        return
    for cid in list(record.pending_confirmations):
        conf = client.get(f"/v1/confirmations/{cid}", headers=_h(p)).json()
        approved = client.post(f"/v1/confirmations/{cid}/approve", headers=_h(p), json={
            "action_type": conf["action_type"],
            "params": conf["action_params"],
        })
        assert approved.status_code == 200, approved.text


def test_chat_continue_drives_run_to_completion(api):
    client, p = api
    with client.stream("POST", "/v1/agent/chat", headers=_h(p),
                       json={"message": "make me a welding training website"}) as resp:
        events = _parse_sse(resp.iter_lines())
    run_id = events[-1]["run_id"]

    rounds = 0
    while events[-1]["data"]["status"] == "waiting_for_user" and rounds < 12:
        _approve_all(api, run_id)
        with client.stream("POST", "/v1/agent/chat", headers=_h(p),
                           json={"message": "continue", "run_id": run_id}) as resp:
            events = _parse_sse(resp.iter_lines())
        rounds += 1

    assert events[-1]["data"]["status"] == "completed", \
        [e["data"].get("status") for e in events[-3:]]
    assert events[-1]["data"]["tasks_completed"] >= 10
    # site artifacts reported in the final event
    assert any("index.html" in a for a in events[-1]["data"]["artifacts"])


def test_chat_continue_idempotent_when_not_waiting(api):
    client, p = api
    with client.stream("POST", "/v1/agent/chat", headers=_h(p),
                       json={"message": "make me a welding training website"}) as resp:
        events = _parse_sse(resp.iter_lines())
    run_id = events[-1]["run_id"]

    # Continue without approving anything: nothing new happens, but the
    # stream still terminates with the current (waiting) state.
    with client.stream("POST", "/v1/agent/chat", headers=_h(p),
                       json={"message": "continue", "run_id": run_id}) as resp:
        events2 = _parse_sse(resp.iter_lines())
    assert events2[-1]["type"] == "run_finished"
    assert events2[-1]["data"]["status"] == "waiting_for_user"


def test_chat_requires_authentication(api):
    client, _ = api
    with client.stream("POST", "/v1/agent/chat", json={"message": "hi"}) as resp:
        assert resp.status_code == 401


def test_chat_unknown_run_is_404(api):
    client, p = api
    with client.stream("POST", "/v1/agent/chat", headers=_h(p),
                       json={"message": "hi", "run_id": "does-not-exist"}) as resp:
        assert resp.status_code == 404


def test_chat_other_actors_run_is_404(api):
    client, p = api
    with client.stream("POST", "/v1/agent/chat", headers=_h(p),
                       json={"message": "make me a site"}) as resp:
        events = _parse_sse(resp.iter_lines())
    run_id = events[-1]["run_id"]

    other = create_principal(p["container"], username="other", role="user")
    other_headers = {"Authorization": f"Bearer {other['raw_key']}"}
    with client.stream("POST", "/v1/agent/chat", headers=other_headers,
                       json={"message": "continue", "run_id": run_id}) as resp:
        assert resp.status_code == 404  # no cross-actor access




def test_redundant_approval_does_not_poison_resolution(api):
    """Phase 3B regression: a duplicate approve of an already-resolved
    confirmation must NOT flip the outcome — the first terminal audit outcome
    (EXECUTED) wins, and the redundant attempt is rejected idempotently."""
    client, p = api
    with client.stream("POST", "/v1/agent/chat", headers=_h(p),
                       json={"message": "make me a welding training website"}) as resp:
        events = _parse_sse(resp.iter_lines())
    run_id = events[-1]["run_id"]

    container = p["container"]
    record = container.agent_service.get_run(run_id, p["user"]["user"].id)
    cid = record.pending_confirmations[0]
    conf = client.get(f"/v1/confirmations/{cid}", headers=_h(p)).json()

    approved = client.post(f"/v1/confirmations/{cid}/approve", headers=_h(p), json={
        "action_type": conf["action_type"], "params": conf["action_params"]})
    assert approved.json()["status"] == "executed"

    # Redundant approval: rejected, but the original outcome must survive.
    redundant = client.post(f"/v1/confirmations/{cid}/approve", headers=_h(p), json={
        "action_type": conf["action_type"], "params": conf["action_params"]})
    assert redundant.status_code == 200
    assert redundant.json()["status"] == "denied"

    # The confirmation stays USED (never overwritten to DENIED).
    from era.models.confirmation import STATUS_USED
    with container.session_factory() as session:
        row = container.confirmation_service.get(session, cid)
        assert row.status == STATUS_USED

    with client.stream("POST", "/v1/agent/chat", headers=_h(p),
                       json={"message": "continue", "run_id": run_id}) as resp:
        events = _parse_sse(resp.iter_lines())
    # The approved task completed; the run advanced and paused at the NEXT gate.
    assert events[-1]["data"]["status"] == "waiting_for_user"
    rec = container.agent_service.get_run(run_id, p["user"]["user"].id)
    assert any(t.status.value == "completed" for t in rec.tasks)
    assert not any(t.status.value == "failed" and "already" in (t.error or "")
                   for t in rec.tasks)


def test_chat_goal_validation(api):
    client, p = api
    with client.stream("POST", "/v1/agent/chat", headers=_h(p),
                       json={"message": "   "}) as resp:
        assert resp.status_code == 422
