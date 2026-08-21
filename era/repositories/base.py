"""Repository protocols + shared value objects.

The service layer depends only on these protocols, so PostgreSQL (or another
DB) can replace SQLite later without touching business logic. Note that only
the *audit* repository is append-only; confirmations and policy legitimately
support create/update transitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from era.models import (
    AgentRun,
    ApiKey,
    AuditLogEntry,
    CircuitBreakerStateRow,
    IdempotencyRecord,
    Job,
    MemoryEntry,
    PendingConfirmation,
    PolicyVersion,
    User,
    VaultSecret,
)


@dataclass
class NewAuditEntry:
    """All fields of an audit entry except the chain fields (seq, hashes)."""

    actor_id: str
    action_type: str
    action_params: dict
    risk_level: str
    decision: str
    outcome: str
    policy_version: int
    app_version: str
    confirmation_id: str | None = None
    result: str | None = None
    error_code: str | None = None
    provider_id: str | None = None
    capability_domain: str | None = None
    credential_ref: str | None = None
    meta: dict = field(default_factory=dict)


@dataclass
class VerifyResult:
    valid: bool
    entry_count: int
    first_mismatch_seq: int | None = None
    message: str = ""


class AuditRepo(Protocol):
    """Append-only audit storage: append / list / get / verify. No update/delete."""

    def append(self, session, entry: NewAuditEntry) -> AuditLogEntry: ...

    def list(self, session, *, limit: int = 100, offset: int = 0,
             action_type: str | None = None, outcome: str | None = None,
             confirmation_id: str | None = None) -> list[AuditLogEntry]: ...

    def get(self, session, entry_id: int) -> AuditLogEntry | None: ...

    def get_last(self, session) -> AuditLogEntry | None: ...

    def verify(self, session) -> VerifyResult: ...


class ConfirmationRepo(Protocol):
    def create(self, session, confirmation: PendingConfirmation) -> PendingConfirmation: ...

    def get(self, session, confirmation_id: str) -> PendingConfirmation | None: ...

    def update(self, session, confirmation: PendingConfirmation) -> PendingConfirmation: ...


class PolicyRepo(Protocol):
    def get_current(self, session) -> PolicyVersion | None: ...

    def create(self, session, version: int, document: dict, changed_by: str) -> PolicyVersion: ...


class UserRepo(Protocol):
    """Identity storage (Phase 2A)."""

    def get(self, session, user_id: str) -> User | None: ...

    def get_by_username(self, session, username: str) -> User | None: ...

    def create(self, session, user: User) -> User: ...

    def update(self, session, user: User) -> User: ...

    def list(self, session) -> list[User]: ...


class ApiKeyRepo(Protocol):
    """API-key storage (Phase 2A). Keys are stored as hashes only."""

    def get(self, session, key_id: str) -> ApiKey | None: ...

    def get_by_hash(self, session, key_hash: str) -> ApiKey | None: ...

    def create(self, session, key: ApiKey) -> ApiKey: ...

    def update(self, session, key: ApiKey) -> ApiKey: ...

    def list_by_user(self, session, user_id: str) -> list[ApiKey]: ...

    def list(self, session) -> list[ApiKey]: ...


class VaultSecretRepo(Protocol):
    """Credential vault storage (Phase 3C). Stores ciphertext only — the
    plaintext value never exists as a column."""

    def create(self, session, secret: VaultSecret) -> VaultSecret: ...

    def get(self, session, domain: str, name: str) -> VaultSecret | None: ...

    def get_by_id(self, session, secret_id: str) -> VaultSecret | None: ...

    def list(self, session, domain: str | None = None) -> list[VaultSecret]: ...

    def update(self, session, secret: VaultSecret) -> VaultSecret: ...


class AgentRunRepo(Protocol):
    """Agent run persistence (Phase 3A)."""

    def create(self, session, run: AgentRun) -> AgentRun: ...

    def get(self, session, run_id: str) -> AgentRun | None: ...

    def update(self, session, run: AgentRun) -> AgentRun: ...

    def list_by_actor(self, session, actor_id: str, *, limit: int = 50) -> list[AgentRun]: ...


class CircuitBreakerStateRepo(Protocol):
    """Durable state snapshots for per-provider circuit breakers."""

    def get(self, session, provider_id: str) -> CircuitBreakerStateRow | None: ...

    def upsert(
        self,
        session,
        *,
        provider_id: str,
        state: str,
        consecutive_failures: int,
        opened_at: float | None,
    ) -> CircuitBreakerStateRow: ...


class MemoryRepo(Protocol):
    """Long-term agent memory storage (Phase 3A)."""

    def create(self, session, entry: MemoryEntry) -> MemoryEntry: ...

    def get(self, session, actor_id: str, namespace: str, key: str) -> MemoryEntry | None: ...

    def update(self, session, entry: MemoryEntry) -> MemoryEntry: ...

    def list_namespace(self, session, actor_id: str, namespace: str) -> list[MemoryEntry]: ...

    def delete(self, session, actor_id: str, namespace: str, key: str) -> bool: ...


class IdempotencyRepo(Protocol):
    """Replay-dedup storage (Phase 3G)."""

    def create(self, session, record: IdempotencyRecord) -> IdempotencyRecord: ...

    def get(self, session, actor_id: str, key_hash: str) -> IdempotencyRecord | None: ...

    def update(self, session, record: IdempotencyRecord) -> IdempotencyRecord: ...

    def delete(self, session, record: IdempotencyRecord) -> None: ...


class JobRepo(Protocol):
    """Background job storage (Phase 3G)."""

    def create(self, session, job: Job) -> Job: ...

    def get(self, session, job_id: str) -> Job | None: ...

    def get_by_idempotency_key(self, session, actor_id: str,
                               key_hash: str) -> Job | None: ...

    def update(self, session, job: Job) -> Job: ...

    def list_by_actor(self, session, actor_id: str, *, limit: int = 50) -> list[Job]: ...

    def list_by_statuses(self, session, statuses: list[str]) -> list[Job]: ...
