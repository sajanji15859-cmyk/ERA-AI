"""Phase 2A authentication tests: missing/invalid/valid keys, protected endpoints,
actor_id spoofing rejection, and server-side identity in the audit log."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from era.db import transaction
from tests.conftest import make_authed_app


@pytest.fixture
def api(tmp_path):
    app, principals = make_authed_app(tmp_path)
    with TestClient(app) as c:
        yield c, principals


def _h(principals, which="admin"):
    return {"Authorization": f"Bearer {principals[which]['raw_key']}"}


def test_missing_authentication(api):
    client, _ = api
    # No Authorization header -> 401 on every protected endpoint.
    assert client.get("/v1/policy").status_code == 401
    assert client.get("/v1/audit").status_code == 401
    assert client.get("/v1/providers").status_code == 401
    assert client.post("/v1/actions/execute", json={"action_type": "stub.noop"}).status_code == 401
    assert client.post("/v1/actions/evaluate", json={"action_type": "stub.noop"}).status_code == 401


def test_invalid_authentication(api):
    client, _ = api
    bad = {"Authorization": "Bearer not-a-real-key-zzzz"}
    assert client.get("/v1/policy", headers=bad).status_code == 401
    assert client.post("/v1/actions/execute", headers=bad,
                       json={"action_type": "stub.noop"}).status_code == 401


def test_invalid_scheme_and_empty(api):
    client, _ = api
    assert client.get("/v1/policy",
                      headers={"Authorization": "Basic dXNlcjpwYXNz"}).status_code == 401
    assert client.get("/v1/policy", headers={"Authorization": "Bearer"}).status_code == 401
    assert client.get("/v1/policy", headers={"Authorization": "Bearer   "}).status_code == 401


def test_authenticated_request(api):
    client, p = api
    r = client.get("/v1/policy", headers=_h(p))
    assert r.status_code == 200
    assert r.json()["version"] >= 1


def test_revoked_key_rejected(api):
    client, p = api
    # Revoke the user's key, then that key must be rejected.
    user = p["user"]["user"]
    keys = p["container"].auth_service.list_keys(user.id)
    for k in keys:
        p["container"].auth_service.revoke_key(k.id)
    assert client.get("/v1/policy", headers=_h(p, "user")).status_code == 401
    # Admin key still works.
    assert client.get("/v1/policy", headers=_h(p, "admin")).status_code == 200


def test_disabled_user_rejected(api):
    client, p = api
    user = p["user"]["user"]
    p["container"].auth_service.set_user_disabled(user.id, disabled=True)
    assert client.get("/v1/policy", headers=_h(p, "user")).status_code == 401


def test_actor_id_spoofing_rejected(api):
    client, p = api
    # Client tries to claim a different actor_id -> unknown field -> 422.
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "stub.noop", "actor_id": "attacker"})
    assert r.status_code == 422

    # Client tries to supply session_id / credential_refs -> also rejected.
    r2 = client.post("/v1/actions/execute", headers=_h(p),
                     json={"action_type": "stub.noop", "session_id": "x",
                           "credential_refs": {"email": "ref-1"}})
    assert r2.status_code == 422


def test_server_side_identity_in_audit(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "stub.noop"})
    assert r.status_code == 200

    # The audit actor must be the authenticated user id, NOT any client value.
    with transaction(p["container"].session_factory) as session:
        entries = p["container"].audit_service.list(session)
    actor_ids = {e.actor_id for e in entries}
    assert p["admin"]["user"].id in actor_ids
    assert "attacker" not in actor_ids


def test_protected_endpoints_require_privilege(api):
    client, p = api
    # A normal user cannot read the audit log (admin-only).
    assert client.get("/v1/audit", headers=_h(p, "user")).status_code == 403
    # A normal user cannot manage users or write policy.
    assert client.put("/v1/policy", headers=_h(p, "user"), json={}).status_code in (403, 422)
