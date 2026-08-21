"""Phase 3F API-key and source-IP rate-limit tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from era.config import Settings
from era.main import create_app


def _settings(tmp_path, **overrides) -> Settings:
    values = {
        "database_url": f"sqlite:///{tmp_path}/rate-limit.db",
        "rate_limit_enabled": True,
        "rate_limit_requests": 2,
        "rate_limit_ip_requests": 100,
        "rate_limit_window_seconds": 60.0,
    }
    values.update(overrides)
    return Settings(**values)


def test_authenticated_requests_are_limited_per_api_key(tmp_path):
    app = create_app(_settings(tmp_path))
    auth = app.state.container.auth_service
    user = auth.create_user(username="limited-user", role="user")
    _key, raw_key = auth.create_api_key(user.id, "first-client")
    headers = {"Authorization": f"Bearer {raw_key}"}

    with TestClient(app) as client:
        first = client.get("/v1/policy", headers=headers)
        second = client.get("/v1/policy", headers=headers)
        limited = client.get("/v1/policy", headers=headers)

        assert first.status_code == second.status_code == 200
        assert first.headers["x-ratelimit-limit"] == "2"
        assert second.headers["x-ratelimit-remaining"] == "0"
        assert limited.status_code == 429
        assert limited.json() == {"detail": "rate limit exceeded"}
        assert int(limited.headers["retry-after"]) >= 1
        # The outer security middleware still hardens early 429 responses.
        assert limited.headers["x-content-type-options"] == "nosniff"

        # A different key gets an independent key bucket (IP cap is higher).
        _other, other_raw = auth.create_api_key(user.id, "second-client")
        other_headers = {"Authorization": f"Bearer {other_raw}"}
        assert client.get("/v1/policy", headers=other_headers).status_code == 200


def test_unauthenticated_requests_are_limited_by_source_ip(tmp_path):
    app = create_app(_settings(
        tmp_path,
        rate_limit_requests=100,
        rate_limit_ip_requests=2,
    ))
    with TestClient(app) as client:
        assert client.get("/v1/policy").status_code == 401
        assert client.get("/v1/policy").status_code == 401
        blocked = client.get("/v1/policy")
        assert blocked.status_code == 429
        assert blocked.headers["x-ratelimit-remaining"] == "0"

        # Dashboard/static traffic does not consume versioned API buckets.
        assert client.get("/").status_code == 200
