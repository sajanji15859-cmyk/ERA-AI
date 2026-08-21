"""Phase 2A input-hardening tests: malformed, unexpected, oversized, unknown input."""

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


def test_unknown_field_rejected(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "stub.noop", "bogus": "x"})
    assert r.status_code == 422


def test_unknown_field_on_approve_rejected(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "email.send", "params": {"to": "a@x.com"}})
    cid = r.json()["confirmation_id"]
    a = client.post(f"/v1/confirmations/{cid}/approve", headers=_h(p),
                    json={"action_type": "email.send", "params": {"to": "a@x.com"},
                          "actor_id": "spoof"})
    assert a.status_code == 422


def test_non_object_params_rejected(api):
    client, p = api
    for bad in (["list"], "string", 42, None):
        r = client.post("/v1/actions/execute", headers=_h(p),
                        json={"action_type": "stub.noop", "params": bad})
        assert r.status_code == 422, bad


def test_too_many_params_rejected(api):
    client, p = api
    params = {f"k{i}": i for i in range(100)}
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "stub.noop", "params": params})
    assert r.status_code == 422


def test_oversized_string_param_rejected(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "stub.noop", "params": {"q": "x" * 100000}})
    assert r.status_code == 422


def test_malformed_action_type_rejected(api):
    client, p = api
    for bad in ("", "no spaces", "bad space", "a" * 200, "ok/action"):
        r = client.post("/v1/actions/execute", headers=_h(p),
                        json={"action_type": bad, "params": {}})
        assert r.status_code == 422, bad


def test_missing_required_field_rejected(api):
    client, p = api
    assert client.post("/v1/actions/execute", headers=_h(p),
                       json={}).status_code == 422


def test_oversized_body_rejected(api):
    client, p = api
    # A body far larger than the 256 KiB middleware cap.
    big = {"action_type": "stub.noop", "params": {"payload": "z" * (1024 * 1024)}}
    r = client.post("/v1/actions/execute", headers=_h(p), json=big)
    assert r.status_code in (413, 422)


def test_deeply_nested_params_rejected(api):
    client, p = api
    deep = {}
    node = deep
    for _ in range(10):
        node["child"] = {}
        node = node["child"]
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "stub.noop", "params": deep})
    assert r.status_code == 422


def test_valid_nested_params_accepted(api):
    client, p = api
    params = {"filters": {"tags": ["a", "b"], "limit": 5}, "q": "era"}
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "web.search", "params": params})
    assert r.status_code == 200
    assert r.json()["status"] == "executed"
