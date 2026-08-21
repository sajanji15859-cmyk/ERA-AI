"""IdempotencyService — replay-safe execute (Phase 3G).

Wraps a single execute dispatch so that a client retry (network timeout,
retry middleware, double-click) carrying the same ``idempotency_key`` never
dispatches a side-effecting action twice:

* **Same key + same request** → the originally recorded
  :class:`~era.schemas.actions.ExecutionResponse` is returned without touching
  the permission engine, providers, confirmations or the audit log.
* **Same key + different request** → :class:`IdempotencyConflict` (HTTP 409).
* **Same key while the first attempt is still in flight** →
  :class:`IdempotencyInProgress` (HTTP 409), so a concurrent duplicate cannot
  race the first dispatch.
* **Expired / abandoned records** are discarded lazily and the request is
  re-executed as a fresh attempt.

Only the response the caller already received is persisted (the CONFIRM_STRONG
challenge phrase is stripped — a replay returns the confirmation id without
re-issuing the one-time phrase, which stays known only to the original
recipient). Keys are stored as SHA-256 hashes and scoped to the actor, so
actors can never collide on (or probe) each other's idempotency keys.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import timedelta

from sqlalchemy.exc import IntegrityError

from era.core.util import utcnow_iso
from era.db import transaction
from era.models import IdempotencyRecord
from era.repositories.base import IdempotencyRepo
from era.schemas.actions import ExecutionResponse
from era.security.hashing import canonical_json, sha256_hex


class IdempotencyError(Exception):
    """Base class for idempotency rejections (all surface as HTTP 409)."""


class IdempotencyConflict(IdempotencyError):
    """The same key was reused with a different request."""


class IdempotencyInProgress(IdempotencyError):
    """The same key has an attempt currently in flight."""


def request_fingerprint(action_type: str, params: dict) -> str:
    """Canonical hash binding an idempotent request to (type, params)."""
    return sha256_hex(canonical_json({"action_type": action_type, "params": params}))


def key_fingerprint(actor_id: str, idempotency_key: str) -> str:
    """Hash of (actor, key); the stored form never reveals the raw key."""
    return sha256_hex(canonical_json({"actor_id": actor_id, "key": idempotency_key}))


def _add_seconds(iso: str, seconds: int) -> str:
    from datetime import datetime
    return (datetime.fromisoformat(iso) + timedelta(seconds=seconds)).isoformat()


def _response_payload(response: ExecutionResponse) -> dict:
    """The caller-visible response, with the one-time challenge stripped."""
    payload = response.model_dump(mode="json")
    payload["challenge"] = None
    return payload


class IdempotencyService:
    def __init__(self, *, session_factory, idempotency_repo: IdempotencyRepo, settings):
        self.session_factory = session_factory
        self.repo = idempotency_repo
        self.settings = settings

    @property
    def ttl_seconds(self) -> int:
        return int(getattr(self.settings, "idempotency_ttl_seconds", 86400))

    @property
    def processing_ttl_seconds(self) -> int:
        return int(getattr(self.settings, "idempotency_processing_ttl_seconds", 300))

    def run(self, actor_id: str, idempotency_key: str, request_hash: str,
            dispatch: Callable[[], ExecutionResponse]) -> ExecutionResponse:
        """Dispatch, returning the recorded response on a replayed key."""
        key_hash = key_fingerprint(actor_id, idempotency_key)

        existing = self._get(actor_id, key_hash)
        if existing is not None:
            if self._is_expired(existing):
                self._delete(existing)
            elif existing.status == "completed":
                return self._resolve_completed(existing, request_hash)
            elif self._is_stale_processing(existing):
                self._delete(existing)
            else:
                raise IdempotencyInProgress("an execution with this key is in progress")

        record, created = self._begin(actor_id, key_hash, request_hash)
        if not created:
            # Lost a race with a concurrent caller using the same key.
            if record.status == "completed":
                return self._resolve_completed(record, request_hash)
            if not self._is_stale_processing(record):
                raise IdempotencyInProgress("an execution with this key is in progress")
            # Stale processing record: re-execute as a fresh attempt.
            self._delete(record)
            record, created = self._begin(actor_id, key_hash, request_hash)
            if not created:
                raise IdempotencyInProgress("an execution with this key is in progress")

        try:
            response = dispatch()
        except BaseException:
            # Never leave a dangling "processing" record on a hard failure: the
            # caller must be able to retry. (request() itself does not raise
            # for deny/confirm/failed outcomes — only unexpected errors reach
            # here.)
            self._discard(record.id)
            raise
        self._complete(record.id, response)
        return response

    # -- internals ------------------------------------------------------------
    def _get(self, actor_id: str, key_hash: str) -> IdempotencyRecord | None:
        with transaction(self.session_factory) as session:
            return self.repo.get(session, actor_id, key_hash)

    def _begin(self, actor_id: str, key_hash: str,
               request_hash: str) -> tuple[IdempotencyRecord, bool]:
        record = IdempotencyRecord(
            id=uuid.uuid4().hex,
            actor_id=actor_id,
            key_hash=key_hash,
            request_hash=request_hash,
            status="processing",
            expires_at=_add_seconds(utcnow_iso(), self.ttl_seconds),
        )
        try:
            with transaction(self.session_factory) as session:
                self.repo.create(session, record)
            return record, True
        except IntegrityError:
            # Another caller created the record first (unique actor_id+key_hash).
            with transaction(self.session_factory) as session:
                existing = self.repo.get(session, actor_id, key_hash)
            return existing, False  # type: ignore[return-value]

    def _complete(self, record_id: str, response: ExecutionResponse) -> None:
        with transaction(self.session_factory) as session:
            record = session.get(IdempotencyRecord, record_id)
            if record is None:
                return  # already discarded — nothing to record
            record.status = "completed"
            record.response_json = _response_payload(response)
            record.updated_at = utcnow_iso()
            self.repo.update(session, record)

    def _discard(self, record_id: str) -> None:
        with transaction(self.session_factory) as session:
            record = session.get(IdempotencyRecord, record_id)
            if record is not None:
                self.repo.delete(session, record)

    def _delete(self, record: IdempotencyRecord) -> None:
        with transaction(self.session_factory) as session:
            self.repo.delete(session, record)

    def _resolve_completed(self, record: IdempotencyRecord,
                           request_hash: str) -> ExecutionResponse:
        if record.request_hash != request_hash:
            raise IdempotencyConflict(
                "idempotency key was already used with a different request")
        return ExecutionResponse.model_validate(record.response_json or {})

    def _is_expired(self, record: IdempotencyRecord) -> bool:
        return record.expires_at is not None and utcnow_iso() > record.expires_at

    def _is_stale_processing(self, record: IdempotencyRecord) -> bool:
        if record.status != "processing":
            return False
        # A processing record older than the processing TTL is abandoned (e.g.
        # the dispatching process crashed). ISO-8601 UTC strings compare
        # correctly lexicographically, matching the confirmation expiry logic.
        stale_after = _add_seconds(record.created_at, self.processing_ttl_seconds)
        return utcnow_iso() > stale_after
