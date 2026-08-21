"""Phase 2A authorization tests: RBAC permissions + capability-domain allowlist."""

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


def test_user_can_read_policy(api):
    client, p = api
    assert client.get("/v1/policy", headers=_h(p, "user")).status_code == 200


def test_user_cannot_write_policy(api):
    client, p = api
    doc = client.get("/v1/policy", headers=_h(p, "user")).json()["document"]
    r = client.put("/v1/policy", headers=_h(p, "user"), json=doc)
    assert r.status_code == 403


def test_user_cannot_manage_users(api):
    client, p = api
    assert client.get("/v1/users", headers=_h(p, "user")).status_code == 403
    assert client.post("/v1/users", headers=_h(p, "user"),
                       json={"username": "hax", "role": "admin"}).status_code == 403


def test_user_cannot_create_api_keys(api):
    client, p = api
    uid = p["user"]["user"].id
    assert client.post(f"/v1/users/{uid}/api-keys", headers=_h(p, "user"),
                       json={"name": "x"}).status_code == 403


def test_user_cannot_read_audit(api):
    client, p = api
    assert client.get("/v1/audit", headers=_h(p, "user")).status_code == 403


def test_admin_can_do_everything(api):
    client, p = api
    assert client.get("/v1/audit", headers=_h(p, "admin")).status_code == 200
    assert client.get("/v1/users", headers=_h(p, "admin")).status_code == 200


def test_user_cannot_execute_device_actions(api):
    # device.* is admin-only in Phase 2A (high-risk boundary).
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p, "user"),
                    json={"action_type": "device.shell", "params": {"cmd": "whoami"}})
    assert r.status_code == 403


def test_user_can_execute_web_actions(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p, "user"),
                    json={"action_type": "web.search", "params": {"q": "era"}})
    # web.search is SAFE/ALLOW -> executed via the stub.
    assert r.status_code == 200
    assert r.json()["status"] == "executed"


def test_admin_can_execute_device_actions(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p, "admin"),
                    json={"action_type": "device.shell", "params": {"cmd": "ls"}})
    # device.shell is DESTRUCTIVE -> the permission gate requires a strong
    # confirmation; reaching confirmation_required proves admin cleared RBAC.
    assert r.status_code == 200
    assert r.json()["status"] == "confirmation_required"


def test_unknown_action_role_denied_even_for_admin_execute(api):
    # RBAC domain allowlist fails closed for an unknown action (no domain).
    client, p = api
    # Admin executes -> permission engine DENYs unknown action, but execute path
    # still returns a decision (denied), not a 403, because the action is
    # unknown to the catalog (authorize_action denies -> 403 fail closed).
    r = client.post("/v1/actions/execute", headers=_h(p, "admin"),
                    json={"action_type": "totally.unknown", "params": {}})
    # authorize_action rejects unknown-domain actions at the RBAC gate.
    assert r.status_code == 403


def test_cross_user_confirmation_rejected(api):
    client, p = api
    # User initiates an email.send (CONFIRM).
    r = client.post("/v1/actions/execute", headers=_h(p, "user"),
                    json={"action_type": "email.send", "params": {"to": "a@x.com"}})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "confirmation_required"
    cid = body["confirmation_id"]

    # Admin (different actor) tries to approve it -> denied by actor binding.
    a = client.post(f"/v1/confirmations/{cid}/approve", headers=_h(p, "admin"),
                    json={"action_type": "email.send", "params": {"to": "a@x.com"}})
    assert a.status_code == 200
    assert a.json()["status"] == "denied"

    # And the initiating user cannot view it as admin-only... actually the
    # initiator CAN view their own confirmation.
    g = client.get(f"/v1/confirmations/{cid}", headers=_h(p, "user"))
    assert g.status_code == 200
