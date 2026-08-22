"""Tests for Scheduled recurring job API routes (Phase 3H)."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from era.config import Settings
from era.main import create_app


@pytest.fixture
def api(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/test.db")
    app = create_app(settings)
    client = TestClient(app)
    c = app.state.container

    # Create admin and regular user
    admin = c.auth_service.create_user(username="admin-user", role="admin")
    _admin_key, admin_raw = c.auth_service.create_api_key(admin.id, name="admin-key")

    user = c.auth_service.create_user(username="test-user", role="user")
    _user_key, user_raw = c.auth_service.create_api_key(user.id, name="user-key")

    auth = {
        "admin": {"user": admin, "key": admin_raw},
        "user": {"user": user, "key": user_raw},
    }
    return client, auth, c


def _h(auth, role="user"):
    return {"Authorization": f"Bearer {auth[role]['key']}"}


def test_schedule_api_lifecycle(api):
    client, auth, _ = api

    # 1. Create schedule
    payload = {
        "name": "Daily clean up",
        "action_type": "stub.noop",
        "action_params": {"mode": "quick"},
        "cron_expr": "0 8 * * *",
        "enabled": True,
    }
    r = client.post("/v1/schedules", headers=_h(auth, "user"), json=payload)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["name"] == "Daily clean up"
    assert data["action_type"] == "stub.noop"
    assert data["next_run_at"] is not None
    sched_id = data["schedule_id"]

    # 2. Get schedule
    r = client.get(f"/v1/schedules/{sched_id}", headers=_h(auth, "user"))
    assert r.status_code == 200
    assert r.json()["schedule_id"] == sched_id

    # 3. List schedules
    r = client.get("/v1/schedules", headers=_h(auth, "user"))
    assert r.status_code == 200
    assert len(r.json()["schedules"]) == 1

    # 4. Patch schedule
    r = client.patch(f"/v1/schedules/{sched_id}", headers=_h(auth, "user"),
                     json={"name": "Updated clean up", "interval_seconds": 3600, "cron_expr": None})
    assert r.status_code == 200
    assert r.json()["name"] == "Updated clean up"
    assert r.json()["interval_seconds"] == 3600

    # 5. Disable / Enable
    r = client.post(f"/v1/schedules/{sched_id}/disable", headers=_h(auth, "user"))
    assert r.status_code == 200
    assert r.json()["enabled"] is False

    r = client.post(f"/v1/schedules/{sched_id}/enable", headers=_h(auth, "user"))
    assert r.status_code == 200
    assert r.json()["enabled"] is True

    # 6. Delete schedule
    r = client.delete(f"/v1/schedules/{sched_id}", headers=_h(auth, "user"))
    assert r.status_code == 200
    assert r.json()["deleted"] is True

    # 7. 404 on deleted
    r = client.get(f"/v1/schedules/{sched_id}", headers=_h(auth, "user"))
    assert r.status_code == 404


def test_schedule_api_actor_isolation(api):
    client, auth, _ = api

    # User creates schedule
    payload = {
        "name": "User schedule",
        "action_type": "stub.noop",
        "interval_seconds": 600,
    }
    r = client.post("/v1/schedules", headers=_h(auth, "user"), json=payload)
    assert r.status_code == 201
    sched_id = r.json()["schedule_id"]

    # Admin list does not see user's schedule (actor isolation)
    r = client.get("/v1/schedules", headers=_h(auth, "admin"))
    assert r.status_code == 200
    assert len(r.json()["schedules"]) == 0

    # Admin cannot get user's schedule directly
    r = client.get(f"/v1/schedules/{sched_id}", headers=_h(auth, "admin"))
    assert r.status_code == 404
