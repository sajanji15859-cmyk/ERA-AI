"""End-to-end API tests via FastAPI TestClient (Phase 2A authenticated)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import make_authed_app


@pytest.fixture
def api(tmp_path):
    app, principals = make_authed_app(tmp_path)
    with TestClient(app) as c:
        yield c, principals


def _h(principals, which="admin"):
    return {"Authorization": f"Bearer {principals[which]['raw_key']}"}


def test_evaluate_safe(api):
    client, p = api
    r = client.post("/v1/actions/evaluate", headers=_h(p),
                    json={"action_type": "web.search", "params": {"q": "x"}})
    assert r.status_code == 200
    assert r.json()["decision"] == "ALLOW"


def test_evaluate_unknown_denied(api):
    client, p = api
    r = client.post("/v1/actions/evaluate", headers=_h(p),
                    json={"action_type": "nope.action"})
    assert r.status_code == 200
    assert r.json()["decision"] == "DENY"


def test_execute_safe_end_to_end(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "stub.noop"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "executed"


def test_execute_confirm_then_approve(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "email.send", "params": {"to": "x@example.com"}})
    body = r.json()
    assert body["status"] == "confirmation_required"
    cid = body["confirmation_id"]

    a = client.post(f"/v1/confirmations/{cid}/approve", headers=_h(p),
                    json={"action_type": "email.send", "params": {"to": "x@example.com"}})
    assert a.json()["status"] == "executed"


def test_execute_confirm_then_deny(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "email.send", "params": {"to": "x@example.com"}})
    cid = r.json()["confirmation_id"]
    d = client.post(f"/v1/confirmations/{cid}/deny", headers=_h(p), json={})
    assert d.json()["status"] == "denied"


def test_audit_list_and_verify(api):
    client, p = api
    client.post("/v1/actions/execute", headers=_h(p), json={"action_type": "stub.noop"})
    r = client.get("/v1/audit", headers=_h(p))
    assert r.status_code == 200
    assert len(r.json()) >= 2  # AUTHORIZED + EXECUTED
    v = client.get("/v1/audit/verify", headers=_h(p))
    assert v.status_code == 200
    assert v.json()["valid"] is True


def test_providers_listing(api):
    client, p = api
    r = client.get("/v1/providers", headers=_h(p))
    assert r.status_code == 200
    providers = r.json()["providers"]
    stub = next(pr for pr in providers if pr["id"] == "stub")
    assert stub["is_stub"] is True
    assert "stub.noop" in stub["action_types"]
    # No secret material is ever surfaced.
    assert "sk-" not in r.text
    assert "token" not in r.text.lower()


def test_provider_detail_and_404(api):
    client, p = api
    r = client.get("/v1/providers/stub", headers=_h(p))
    assert r.status_code == 200
    assert r.json()["id"] == "stub"
    missing = client.get("/v1/providers/nope", headers=_h(p))
    assert missing.status_code == 404


def test_policy_get_and_put(api):
    client, p = api
    r = client.get("/v1/policy", headers=_h(p))
    assert r.status_code == 200
    assert r.json()["version"] == 1

    doc = r.json()["document"]
    doc["overrides"] = {"fs.write": {"decision": "ALLOW"}}
    resp = client.put("/v1/policy", headers=_h(p), json=doc)
    assert resp.status_code == 200
    assert resp.json()["version"] == 2

    # The override now applies.
    e = client.post("/v1/actions/evaluate", headers=_h(p),
                    json={"action_type": "fs.write", "params": {}})
    assert e.json()["decision"] == "ALLOW"
