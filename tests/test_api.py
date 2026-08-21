"""End-to-end API tests via FastAPI TestClient."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from era.config import Settings
from era.main import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path}/api_test.db"))
    with TestClient(app) as c:
        yield c


def test_evaluate_safe(client):
    r = client.post("/v1/actions/evaluate", json={"action_type": "web.search", "params": {"q": "x"}})
    assert r.status_code == 200
    assert r.json()["decision"] == "ALLOW"


def test_evaluate_unknown_denied(client):
    r = client.post("/v1/actions/evaluate", json={"action_type": "nope.action"})
    assert r.status_code == 200
    assert r.json()["decision"] == "DENY"


def test_execute_safe_end_to_end(client):
    r = client.post("/v1/actions/execute", json={"action_type": "stub.noop"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "executed"


def test_execute_confirm_then_approve(client):
    r = client.post("/v1/actions/execute",
                    json={"action_type": "email.send", "params": {"to": "x@example.com"}})
    body = r.json()
    assert body["status"] == "confirmation_required"
    cid = body["confirmation_id"]

    a = client.post(f"/v1/confirmations/{cid}/approve",
                    json={"action_type": "email.send", "params": {"to": "x@example.com"}})
    assert a.json()["status"] == "executed"


def test_execute_confirm_then_deny(client):
    r = client.post("/v1/actions/execute",
                    json={"action_type": "email.send", "params": {"to": "x@example.com"}})
    cid = r.json()["confirmation_id"]
    d = client.post(f"/v1/confirmations/{cid}/deny", json={})
    assert d.json()["status"] == "denied"


def test_audit_list_and_verify(client):
    client.post("/v1/actions/execute", json={"action_type": "stub.noop"})
    r = client.get("/v1/audit")
    assert r.status_code == 200
    assert len(r.json()) >= 2  # AUTHORIZED + EXECUTED
    v = client.get("/v1/audit/verify")
    assert v.status_code == 200
    assert v.json()["valid"] is True


def test_providers_listing(client):
    r = client.get("/v1/providers")
    assert r.status_code == 200
    providers = r.json()["providers"]
    stub = next(p for p in providers if p["id"] == "stub")
    assert stub["is_stub"] is True
    assert "stub.noop" in stub["action_types"]
    # No secret material is ever surfaced.
    assert "sk-" not in r.text
    assert "token" not in r.text.lower()


def test_provider_detail_and_404(client):
    r = client.get("/v1/providers/stub")
    assert r.status_code == 200
    assert r.json()["id"] == "stub"
    missing = client.get("/v1/providers/nope")
    assert missing.status_code == 404


def test_policy_get_and_put(client):
    r = client.get("/v1/policy")
    assert r.status_code == 200
    assert r.json()["version"] == 1

    doc = r.json()["document"]
    doc["overrides"] = {"fs.write": {"decision": "ALLOW"}}
    p = client.put("/v1/policy", json=doc)
    assert p.status_code == 200
    assert p.json()["version"] == 2

    # The override now applies.
    e = client.post("/v1/actions/evaluate", json={"action_type": "fs.write", "params": {}})
    assert e.json()["decision"] == "ALLOW"
