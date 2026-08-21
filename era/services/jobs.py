"""JobService — durable background execution (Phase 3G).

``POST /v1/actions/execute`` with ``async=true`` submits the action to this
service instead of executing inline. The request is persisted as a ``Job``
row (with *redacted* params only), the response returns immediately with the
job id, and a bounded in-process worker pool executes the action through the
same :class:`~era.services.execution_service.ExecutionService` gate — so async
execution loses none of the authorization / confirmation / audit invariants.

Replay safety composes with idempotency: an optional client ``idempotency_key``
deduplicates submissions, so a retried submit returns the *same* job instead of
queuing a duplicate. Jobs interrupted by a crash (still ``queued``/``running``
at startup) are failed by :meth:`recover` rather than silently resumed, because
a half-executed side effect must never be guessed at — the client re-submits
under a fresh idempotency key.
"""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy.exc import IntegrityError

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.util import utcnow_iso
from era.db import transaction
from era.models import Job
from era.repositories.base import JobRepo
from era.schemas.actions import ExecutionResponse
from era.security.hashing import canonical_json, sha256_hex
from era.security.redaction import redact
from era.services.idempotency import IdempotencyConflict, request_fingerprint

_QUEUED = "queued"
_RUNNING = "running"
_COMPLETED = "completed"
_FAILED = "failed"

#: Jobs that may still be mid-flight when the process died and are failed on
#: the next startup by JobService.recover().
_INTERRUPTIBLE_STATUSES = (_QUEUED, _RUNNING)


def _add_seconds(iso: str, seconds: int) -> str:
    from datetime import datetime
    return (datetime.fromisoformat(iso) + timedelta(seconds=seconds)).isoformat()


def _job_key_fingerprint(actor_id: str, idempotency_key: str) -> str:
    return sha256_hex(canonical_json({"actor_id": actor_id, "key": idempotency_key}))


def _response_payload(response: ExecutionResponse) -> dict:
    payload = response.model_dump(mode="json")
    payload["challenge"] = None
    return payload


class JobService:
    def __init__(self, *, session_factory, job_repo: JobRepo, execution_service,
                 settings, executor: ThreadPoolExecutor | None = None):
        self.session_factory = session_factory
        self.repo = job_repo
        self.execution_service = execution_service
        self.settings = settings
        self._owns_executor = executor is None
        self.executor = executor or ThreadPoolExecutor(
            max_workers=max(1, int(getattr(settings, "job_worker_threads", 2))),
            thread_name_prefix="era-job",
        )

    # -- lifecycle ------------------------------------------------------------
    def recover(self) -> int:
        """Fail any job left queued/running by a previous process.

        Returns the number of jobs recovered. Called once at startup; a job
        interrupted mid-execution is failed (never silently resumed) so its
        half-known state cannot be mistaken for a completed side effect.
        """
        recovered = 0
        with transaction(self.session_factory) as session:
            for job in self.repo.list_by_statuses(session, list(_INTERRUPTIBLE_STATUSES)):
                job.status = _FAILED
                job.error = "interrupted by restart"
                job.updated_at = utcnow_iso()
                self.repo.update(session, job)
                recovered += 1
        return recovered

    def shutdown(self) -> None:
        if self._owns_executor:
            self.executor.shutdown(wait=False, cancel_futures=True)

    # -- submission -----------------------------------------------------------
    def submit(self, action: Action, ctx: ExecutionContext,
               idempotency_key: str | None = None) -> Job:
        request_hash = request_fingerprint(action.action_type, action.params)
        key_hash = None
        if idempotency_key:
            key_hash = _job_key_fingerprint(ctx.actor_id, idempotency_key)
            existing = self._get_by_key(ctx.actor_id, key_hash)
            if existing is not None:
                return self._resolve_existing(existing, request_hash)

        spec = self.execution_service.catalog.get(action.action_type)
        secret_fields = spec.secret_fields if spec else frozenset()
        job = Job(
            id=uuid.uuid4().hex,
            actor_id=ctx.actor_id,
            kind="action.execute",
            idempotency_key_hash=key_hash,
            request_hash=request_hash,
            status=_QUEUED,
            action_type=action.action_type,
            action_params=redact(action.params, secret_fields),
            session_id=ctx.session_id,
            credential_refs=dict(ctx.credentials.refs),
            expires_at=_add_seconds(utcnow_iso(),
                                    int(getattr(self.settings, "job_ttl_seconds", 86400))),
        )
        try:
            with transaction(self.session_factory) as session:
                self.repo.create(session, job)
        except IntegrityError:
            # Lost a race against an idempotent re-submission: return the winner.
            existing = self._get_by_key(ctx.actor_id, key_hash)
            if existing is not None:
                return self._resolve_existing(existing, request_hash)
            raise

        # The raw action is passed to the worker in memory only; the DB row
        # keeps the redacted copy, so a crash never persists secret material.
        self.executor.submit(self._run, job.id, action, ctx)
        return job

    def get(self, job_id: str, actor_id: str) -> Job | None:
        with transaction(self.session_factory) as session:
            job = self.repo.get(session, job_id)
            if job is None or job.actor_id != actor_id:
                return None
            return job

    def list(self, actor_id: str, *, limit: int = 50) -> list[Job]:
        with transaction(self.session_factory) as session:
            return self.repo.list_by_actor(session, actor_id, limit=limit)

    # -- worker ---------------------------------------------------------------
    def _run(self, job_id: str, action: Action, ctx: ExecutionContext) -> None:
        self._mark_status(job_id, _RUNNING)
        try:
            response = self.execution_service.request(action, ctx)
        except Exception as exc:  # noqa: BLE001 — record and fail the job
            self._mark_status(job_id, _FAILED,
                              error=f"{type(exc).__name__}: {exc}")
            return
        with transaction(self.session_factory) as session:
            job = self.repo.get(session, job_id)
            if job is None:
                return
            job.status = _COMPLETED
            job.response_json = _response_payload(response)
            job.updated_at = utcnow_iso()
            self.repo.update(session, job)

    def _mark_status(self, job_id: str, status: str, *, error: str | None = None) -> None:
        with transaction(self.session_factory) as session:
            job = self.repo.get(session, job_id)
            if job is None:
                return
            job.status = status
            if error is not None:
                job.error = error
            job.updated_at = utcnow_iso()
            self.repo.update(session, job)

    def _get_by_key(self, actor_id: str, key_hash: str) -> Job | None:
        with transaction(self.session_factory) as session:
            return self.repo.get_by_idempotency_key(session, actor_id, key_hash)

    def _resolve_existing(self, existing: Job, request_hash: str) -> Job:
        # Same key + same request → idempotent replay (same job, no duplicate).
        # Same key + different request → conflict, exactly like the sync path.
        if existing.request_hash and existing.request_hash != request_hash:
            raise IdempotencyConflict(
                "idempotency key was already used with a different request")
        return existing
