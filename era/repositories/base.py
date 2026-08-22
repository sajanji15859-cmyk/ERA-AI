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
    Schedule,
    User,
    VaultSecret,
    WorkflowGovernanceCounter,
    WorkflowRun,
    WorkflowSchedule,
    WorkflowStepRun,
    WorkflowTemplate,
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


class ScheduleRepo(Protocol):
    """Scheduled/recurring job storage (Phase 3H)."""

    def create(self, session, schedule: Schedule) -> Schedule: ...

    def get(self, session, schedule_id: str) -> Schedule | None: ...

    def update(self, session, schedule: Schedule) -> Schedule: ...

    def delete(self, session, schedule: Schedule) -> bool: ...

    def list_by_actor(self, session, actor_id: str, *, limit: int = 50) -> list[Schedule]: ...

    def list_due(self, session, now_iso: str, *, limit: int = 100) -> list[Schedule]: ...


class WorkflowRunRepo(Protocol):
    """Durable workflow run storage (Phase 4C)."""

    def create_run(self, session, run: WorkflowRun) -> WorkflowRun: ...

    def get_run(self, session, run_id: str) -> WorkflowRun | None: ...

    def get_run_by_token(self, session, actor_id: str, run_token: str) -> WorkflowRun | None: ...

    def update_run(self, session, run: WorkflowRun) -> WorkflowRun: ...

    def list_runs_by_actor(self, session, actor_id: str, *, limit: int = 50) -> list[WorkflowRun]: ...

    def list_runs_filtered(
        self,
        session,
        *,
        actor_id: str | None = None,
        status: str | None = None,
        workflow_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[WorkflowRun]: ...

    def count_runs_filtered(
        self,
        session,
        *,
        actor_id: str | None = None,
        status: str | None = None,
        workflow_name: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
    ) -> int: ...

    def list_awaiting_runs(
        self, session, *, statuses: list[str] | None = None, limit: int = 50
    ) -> list[WorkflowRun]: ...

    def create_step(self, session, step: WorkflowStepRun) -> WorkflowStepRun: ...

    def get_step(self, session, step_id: str) -> WorkflowStepRun | None: ...

    def list_steps(self, session, run_id: str) -> list[WorkflowStepRun]: ...

    def update_step(self, session, step: WorkflowStepRun) -> WorkflowStepRun: ...


class WorkflowScheduleRepo(Protocol):
    """Workflow-schedule storage (Phase 4D)."""

    def create(self, session, schedule: WorkflowSchedule) -> WorkflowSchedule: ...

    def get(self, session, schedule_id: str) -> WorkflowSchedule | None: ...

    def update(self, session, schedule: WorkflowSchedule) -> WorkflowSchedule: ...

    def delete(self, session, schedule: WorkflowSchedule) -> bool: ...

    def list_by_actor(self, session, actor_id: str, *, limit: int = 50) -> list[WorkflowSchedule]: ...

    def list_due(self, session, now_iso: str, *, limit: int = 100) -> list[WorkflowSchedule]: ...

    def get_by_name(self, session, actor_id: str, name: str) -> WorkflowSchedule | None: ...


class WorkflowTemplateRepo(Protocol):
    """Published immutable workflow-template version storage."""

    def create(self, session, template: WorkflowTemplate) -> WorkflowTemplate: ...

    def get_latest(self, session, name: str) -> WorkflowTemplate | None: ...

    def get(self, session, name: str, version: int) -> WorkflowTemplate | None: ...

    def list(self, session, *, limit: int = 100) -> list[WorkflowTemplate]: ...


class WorkflowGovernanceRepo(Protocol):
    """Atomic admission/budget counters (Phase 4D)."""

    def get(self, session, kind: str, scope: str) -> WorkflowGovernanceCounter | None: ...

    def bump(
        self,
        session,
        *,
        kind: str,
        scope: str,
        delta: int = 1,
        cap: int | None = None,
    ) -> tuple[int, bool]:
        """Atomically add ``delta`` to the counter if it would not exceed ``cap``.

        Returns ``(resulting_count, incremented)``. When the increment is not
        allowed by ``cap``, ``incremented`` is False and the count is unchanged.
        """

    def reset(self, session, kind: str, scope: str) -> None: ...
