"""Vault management API tests (Phase 3C): RBAC, no value leakage, fail-closed."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from era.config import Settings
from era.main import create_app
from tests.conftest import create_principal

HEX_KEY = "cd" * 32


@pytest.fixture
def api(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/vault_api.db",
                        vault_master_key=HEX_KEY)
    app = create_app(settings)
    container = app.state.container
    admin = create_principal(container, username="vadmin", role="admin")
    user = create_principal(container, username="vuser", role="user")
    with TestClient(app) as client:
        yield client, {"admin": admin, "user": user, "container": container}


def _h(p, which):
    return {"Authorization": f"Bearer {p[which]['raw_key']}"}


# -- authentication / authorization -------------------------------------------
def test_unauthenticated_rejected(api):
    client, _ = api
    r = client.post("/v1/vault/secrets",
                    json={"domain": "email", "name": "p", "value": "x"})
    assert r.status_code == 401
    r = client.get("/v1/vault/secrets")
    assert r.status_code == 401


def test_user_role_forbidden(api):
    client, p = api
    r = client.post("/v1/vault/secrets", headers=_h(p, "user"),
                    json={"domain": "email", "name": "p", "value": "x"})
    assert r.status_code == 403
    r = client.get("/v1/vault/secrets", headers=_h(p, "user"))
    assert r.status_code == 403
    r = client.post("/v1/vault/secrets/email/p/revoke", headers=_h(p, "user"))
    assert r.status_code == 403


# -- happy path -----------------------------------------------------------------
def test_store_list_revoke_flow(api):
    client, p = api
    r = client.post("/v1/vault/secrets", headers=_h(p, "admin"),
                    json={"domain": "email", "name": "smtp_password",
                          "value": "S3cret!"})
    assert r.status_code == 200, r.text
    body = r.json()
    # metadata only — never the value:
    assert body["domain"] == "email" and body["name"] == "smtp_password"
    assert body["value_length"] == 7 and body["revision"] == 1
    assert "value" not in body
    assert "S3cret!" not in r.text

    r = client.get("/v1/vault/secrets", headers=_h(p, "admin"))
    assert r.status_code == 200
    assert [s["name"] for s in r.json()] == ["smtp_password"]
    assert "S3cret!" not in r.text

    # filter by domain
    r = client.get("/v1/vault/secrets", headers=_h(p, "admin"),
                   params={"domain": "github"})
    assert r.json() == []

    # rotate:
    r = client.post("/v1/vault/secrets", headers=_h(p, "admin"),
                    json={"domain": "email", "name": "smtp_password",
                          "value": "NewPass"})
    assert r.status_code == 200 and r.json()["revision"] == 2

    # revoke:
    r = client.post("/v1/vault/secrets/email/smtp_password/revoke",
                    headers=_h(p, "admin"))
    assert r.status_code == 200 and r.json()["revoked_at"] is not None

    # revoking again is idempotent; missing is 404:
    r = client.post("/v1/vault/secrets/email/smtp_password/revoke",
                    headers=_h(p, "admin"))
    assert r.status_code == 200
    r = client.post("/v1/vault/secrets/email/ghost/revoke", headers=_h(p, "admin"))
    assert r.status_code == 404

    # and the (now revoked) secret no longer resolves — fail closed:
    from era.security.vault import VaultError
    with pytest.raises(VaultError) as ei:
        p["container"].vault_service.resolve_ref("vault:email/smtp_password")
    assert ei.value.code == "revoked"


def test_admin_can_assign_browser_secret_to_intended_user(api):
    client, p = api
    owner_id = p["user"]["user"].id
    response = client.post(
        "/v1/vault/secrets",
        headers=_h(p, "admin"),
        json={
            "domain": "browser",
            "name": "login_password",
            "value": "not-returned",
            "owner_user_id": owner_id,
        },
    )
    assert response.status_code == 200
    assert response.json()["owner_user_id"] == owner_id
    assert "not-returned" not in response.text

    missing = client.post(
        "/v1/vault/secrets",
        headers=_h(p, "admin"),
        json={
            "domain": "browser",
            "name": "ghost",
            "value": "x",
            "owner_user_id": "missing-user",
        },
    )
    assert missing.status_code == 404


def test_store_rejects_bad_input(api):
    client, p = api
    cases = (
        {"domain": "bad domain", "name": "p", "value": "x"},
        {"domain": "email", "name": "", "value": "x"},
        {"domain": "email", "name": "p", "value": ""},
        {"domain": "email", "name": "p", "value": "x" * 16385},
        {"domain": "email", "name": "p", "value": "x", "extra": 1},
    )
    for body in cases:
        r = client.post("/v1/vault/secrets", headers=_h(p, "admin"), json=body)
        assert r.status_code == 422, (body, r.status_code, r.text)


# -- disabled vault fails closed -------------------------------------------------
def test_disabled_vault_api(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/vault_off.db")
    app = create_app(settings)
    container = app.state.container
    admin = create_principal(container, username="vadmin", role="admin")
    with TestClient(app) as client:
        h = {"Authorization": f"Bearer {admin['raw_key']}"}
        r = client.post("/v1/vault/secrets", headers=h,
                        json={"domain": "email", "name": "p", "value": "x"})
        assert r.status_code == 503
        assert "disabled" in r.json()["detail"]
        # reads still work (metadata-only, empty):
        r = client.get("/v1/vault/secrets", headers=h)
        assert r.status_code == 200 and r.json() == []
        r = client.post("/v1/vault/secrets/email/p/revoke", headers=h)
        assert r.status_code == 503
