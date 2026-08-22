"""Phase 3G background jobs: durable async execution + idempotent submission.

``POST /v1/actions/execute`` with ``async=true`` returns a job id immediately,
the action runs through the same execution gate on a worker thread, and the
result is polled from ``GET /v1/jobs/{id}``. A retried submission with the same
idempotency key returns the *same* job; jobs interrupted by a restart are
failed (never guessed at).
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from era.config import Settings
from era.container import build_container
from era.core.action import Action
from era.core.context import ExecutionContext
from era.db import transaction
from era.models import Job
from tests.conftest import make_authed_app


def _wait_terminal(client, headers, job_id, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/v1/jobs/{job_id}", headers=headers).json()
        if body["status"] in ("completed", "failed"):
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not reach a terminal state in time")


def _h(principals, which="user"):
    return {"Authorization": f"Bearer {principals[which]['raw_key']}"}


@pytest.fixture
def api(tmp_path):
    app, principals = make_authed_app(tmp_path)
    with TestClient(app) as c:
        yield c, principals


def test_async_execute_runs_to_completion(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "web.search", "params": {"q": "era"},
                          "async": True})
    assert r.status_code == 202
    job_id = r.json()["job_id"]
    assert r.json()["status"] == "queued"

    final = _wait_terminal(client, _h(p), job_id)
    assert final["status"] == "completed"
    assert final["result"]["status"] == "executed"


def test_async_submit_is_idempotent(api):
    client, p = api
    body = {"action_type": "web.search", "params": {"q": "era"},
            "async": True, "idempotency_key": "job-key-1"}
    r1 = client.post("/v1/actions/execute", headers=_h(p), json=body)
    r2 = client.post("/v1/actions/execute", headers=_h(p), json=body)
    assert r1.status_code == 202
    assert r2.status_code == 202
    assert r1.json()["job_id"] == r2.json()["job_id"]


def test_async_same_key_different_params_conflicts(api):
    client, p = api
    client.post("/v1/actions/execute", headers=_h(p),
                json={"action_type": "web.search", "params": {"q": "era"},
                      "async": True, "idempotency_key": "job-key-2"})
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "web.search", "params": {"q": "other"},
                          "async": True, "idempotency_key": "job-key-2"})
    assert r.status_code == 409


def test_jobs_are_actor_scoped(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p, "user"),
                    json={"action_type": "web.search", "params": {"q": "era"},
                          "async": True})
    job_id = r.json()["job_id"]

    # Another actor cannot read it.
    assert client.get(f"/v1/jobs/{job_id}", headers=_h(p, "admin")).status_code == 404
    # The owner can.
    assert client.get(f"/v1/jobs/{job_id}", headers=_h(p, "user")).status_code == 200
    # It does not appear in another actor's list.
    listing = client.get("/v1/jobs", headers=_h(p, "admin")).json()["jobs"]
    assert all(j["job_id"] != job_id for j in listing)


def test_jobs_read_requires_permission(api):
    client, _ = api
    assert client.get("/v1/jobs", headers={"Authorization": "Bearer bad"}).status_code == 401


def test_async_confirmation_gate_completes_with_confirmation(api):
    client, p = api
    r = client.post("/v1/actions/execute", headers=_h(p),
                    json={"action_type": "email.send", "params": {"to": "a@x.com"},
                          "async": True})
    job_id = r.json()["job_id"]
    final = _wait_terminal(client, _h(p), job_id)
    assert final["status"] == "completed"
    # The job reached the approval gate (confirmation_required) rather than
    # executing; approval proceeds through the existing confirmation endpoints.
    assert final["result"]["status"] == "confirmation_required"
    assert final["result"]["confirmation_id"]


def test_recover_fails_interrupted_jobs(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/jobs.db")
    container = build_container(settings)

    with transaction(container.session_factory) as session:
        container.repositories.job.create(session, Job(
            id="job-queued", actor_id="a1", kind="action.execute", status="queued",
            action_type="web.search", action_params={},
        ))
        container.repositories.job.create(session, Job(
            id="job-running", actor_id="a1", kind="action.execute", status="running",
            action_type="web.search", action_params={},
        ))

    recovered = container.job_service.recover()
    assert recovered == 2

    queued = container.job_service.get("job-queued", "a1")
    running = container.job_service.get("job-running", "a1")
    assert queued.status == "failed"
    assert queued.error == "interrupted by restart"
    assert running.status == "failed"


def test_job_row_stores_redacted_params_only(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/redact.db")
    container = build_container(settings)
    action = Action(action_type="web.search", params={"q": "era", "api_key": "SUPER-SECRET"})
    ctx = ExecutionContext(actor_id="a1")

    job = container.job_service.submit(action, ctx, idempotency_key="redact-1")
    assert job.action_params["api_key"] == "[REDACTED]"
    assert job.action_params["q"] == "era"

    # Wait for the worker to finish so the process can exit cleanly.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        row = container.job_service.get(job.id, "a1")
        if row.status in ("completed", "failed"):
            break
        time.sleep(0.02)
    container.job_service.shutdown()
