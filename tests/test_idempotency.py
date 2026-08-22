"""Phase 3G idempotency: replay-safe synchronous execution.

A replayed execute (same idempotency key + same request) must return the
originally recorded result WITHOUT dispatching the provider, creating a second
confirmation, or appending more audit rows. The same key with a different
request must be a conflict, and an in-flight attempt must be rejected so a
concurrent duplicate cannot race the first dispatch.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from era.config import Settings
from era.container import build_container
from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult
from era.core.util import utcnow_iso
from era.db import transaction
from era.models import IdempotencyRecord
from era.services.idempotency import (
    IdempotencyConflict,
    IdempotencyInProgress,
    _add_seconds,
    key_fingerprint,
    request_fingerprint,
)
from tests.conftest import make_authed_app


class CountingProvider:
    """Records how many times execute() actually ran (SAFE web.search owner)."""

    id = "counting"
    action_types = frozenset({"web.search"})

    def __init__(self):
        self.calls = 0

    def validate(self, action: Action) -> None:
        return None

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        self.calls += 1
        return ActionResult(success=True, summary=f"search {self.calls}")

    def describe(self) -> ProviderInfo:
        return ProviderInfo(id=self.id, action_types=self.action_types)


def _make_service(tmp_path, *, processing_ttl: int = 300):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/idem.db",
                        idempotency_processing_ttl_seconds=processing_ttl)
    provider = CountingProvider()
    container = build_container(settings, providers=[provider])
    return container, provider


def test_replay_returns_recorded_response_without_redispatch(tmp_path):
    container, provider = _make_service(tmp_path)
    service = container.idempotency_service
    action = Action(action_type="web.search", params={"q": "era"})
    ctx = ExecutionContext(actor_id="a1")
    fp = request_fingerprint(action.action_type, action.params)

    def dispatch():
        return container.execution_service.request(action, ctx)

    first = service.run("a1", "key-1", fp, dispatch)
    second = service.run("a1", "key-1", fp, dispatch)

    assert first.status == "executed"
    assert second.status == "executed"
    assert provider.calls == 1  # dispatched exactly once


def test_same_key_different_request_conflicts(tmp_path):
    container, _ = _make_service(tmp_path)
    service = container.idempotency_service
    ctx = ExecutionContext(actor_id="a1")

    fp1 = request_fingerprint("web.search", {"q": "era"})
    fp2 = request_fingerprint("web.search", {"q": "other"})

    service.run("a1", "key-1", fp1,
                lambda: container.execution_service.request(
                    Action(action_type="web.search", params={"q": "era"}), ctx))

    with pytest.raises(IdempotencyConflict):
        service.run("a1", "key-1", fp2,
                    lambda: container.execution_service.request(
                        Action(action_type="web.search", params={"q": "other"}), ctx))


def test_keys_are_scoped_per_actor(tmp_path):
    container, provider = _make_service(tmp_path)
    service = container.idempotency_service
    fp = request_fingerprint("web.search", {"q": "era"})

    for actor in ("a1", "a2"):
        service.run(actor, "shared-key", fp,
                    lambda a=actor: container.execution_service.request(
                        Action(action_type="web.search", params={"q": "era"}),
                        ExecutionContext(actor_id=a)))
    # The same key used by two different actors dispatched twice (no collision).
    assert provider.calls == 2


def test_concurrent_inflight_rejected(tmp_path):
    container, _ = _make_service(tmp_path)
    service = container.idempotency_service
    fp = request_fingerprint("web.search", {"q": "era"})

    # Simulate a first caller whose dispatch is still running: seed a processing
    # record, then verify a second caller is rejected instead of double-running.
    kh = key_fingerprint("a1", "in-flight")
    with transaction(container.session_factory) as session:
        container.repositories.idempotency.create(session, IdempotencyRecord(
            id="rec-1", actor_id="a1", key_hash=kh, request_hash=fp,
            status="processing",
            expires_at=_add_seconds(utcnow_iso(), 3600),
        ))

    with pytest.raises(IdempotencyInProgress):
        service.run("a1", "in-flight", fp, lambda: container.execution_service.request(
            Action(action_type="web.search", params={"q": "era"}),
            ExecutionContext(actor_id="a1")))


def test_stale_processing_record_is_reattempted(tmp_path):
    container, provider = _make_service(tmp_path, processing_ttl=1)
    service = container.idempotency_service
    fp = request_fingerprint("web.search", {"q": "era"})

    kh = key_fingerprint("a1", "stale-key")
    stale_created = (datetime.fromisoformat(utcnow_iso()) - timedelta(seconds=10)).isoformat()
    with transaction(container.session_factory) as session:
        container.repositories.idempotency.create(session, IdempotencyRecord(
            id="rec-stale", actor_id="a1", key_hash=kh, request_hash=fp,
            status="processing", created_at=stale_created,
            expires_at=_add_seconds(utcnow_iso(), 3600),
        ))

    result = service.run("a1", "stale-key", fp,
                         lambda: container.execution_service.request(
                             Action(action_type="web.search", params={"q": "era"}),
                             ExecutionContext(actor_id="a1")))
    assert result.status == "executed"
    assert provider.calls == 1  # abandoned record was discarded and re-run once


def test_confirmation_required_replay_reuses_confirmation(api):
    client, p = api
    h = {"Authorization": f"Bearer {p['user']['raw_key']}"}
    body = {"action_type": "email.send", "params": {"to": "a@x.com"},
            "idempotency_key": "confirm-1"}

    r1 = client.post("/v1/actions/execute", headers=h, json=body)
    r2 = client.post("/v1/actions/execute", headers=h, json=body)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["status"] == "confirmation_required"
    assert r2.json()["status"] == "confirmation_required"
    assert r1.json()["confirmation_id"] == r2.json()["confirmation_id"]


def test_execute_replay_does_not_duplicate_audit_rows(api):
    client, p = api
    h = {"Authorization": f"Bearer {p['user']['raw_key']}"}
    body = {"action_type": "web.search", "params": {"q": "era"},
            "idempotency_key": "audit-1"}

    assert client.post("/v1/actions/execute", headers=h, json=body).status_code == 200
    assert client.post("/v1/actions/execute", headers=h, json=body).status_code == 200

    # admin reads the audit log; the replay must not have added rows.
    admin = {"Authorization": f"Bearer {p['admin']['raw_key']}"}
    rows = client.get("/v1/audit", headers=admin).json()
    web_rows = [r for r in rows if r["action_type"] == "web.search"]
    assert len(web_rows) == 2  # one AUTHORIZED + one EXECUTED, not duplicated


def test_execute_same_key_different_params_is_409(api):
    client, p = api
    h = {"Authorization": f"Bearer {p['user']['raw_key']}"}
    client.post("/v1/actions/execute", headers=h,
                json={"action_type": "web.search", "params": {"q": "era"},
                      "idempotency_key": "k"})
    r = client.post("/v1/actions/execute", headers=h,
                    json={"action_type": "web.search", "params": {"q": "other"},
                          "idempotency_key": "k"})
    assert r.status_code == 409


@pytest.fixture
def api(tmp_path):
    app, principals = make_authed_app(tmp_path)
    with TestClient(app) as c:
        yield c, principals
