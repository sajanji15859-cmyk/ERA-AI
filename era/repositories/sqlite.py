"""SQLite repository implementations (the Phase 1C storage backend)."""

from __future__ import annotations

import threading

from sqlalchemy import func, select, text

from era.core.util import utcnow_iso
from era.models import (
    AgentRun,
    ApiKey,
    AuditLogEntry,
    CircuitBreakerStateRow,
    ConfirmationApproval,
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
from era.repositories.audit import build_audit_row, verify_audit_rows
from era.repositories.base import NewAuditEntry, VerifyResult
from era.security.signing import AuditSigner


class SQLiteAuditRepo:
    """SQLite audit storage. Append-only; computes the hash chain on write.

    A process-wide lock protects the chain's ``seq``/prev-hash read+compute
    against concurrent parallel workflow steps (Phase 4D). The lock only
    serializes append bookkeeping; executions themselves stay concurrent.
    """

    _append_lock = threading.Lock()

    def __init__(self, genesis_hash: str, signer: AuditSigner | None = None):
        self.genesis_hash = genesis_hash
        self.signer = signer

    # -- write ----------------------------------------------------------------
    def append(self, session, entry: NewAuditEntry) -> AuditLogEntry:
        with self._append_lock:
            last = self.get_last(session)
            row = build_audit_row(
                entry,
                seq=(last.seq + 1) if last else 1,
                prev_hash=last.entry_hash if last else self.genesis_hash,
                signer=self.signer,
            )
            session.add(row)
            session.flush()
        return row

    # -- read -----------------------------------------------------------------
    def list(self, session, *, limit: int = 100, offset: int = 0,
             action_type: str | None = None, outcome: str | None = None,
             confirmation_id: str | None = None) -> list[AuditLogEntry]:
        stmt = select(AuditLogEntry).order_by(AuditLogEntry.seq).limit(limit).offset(offset)
        if action_type is not None:
            stmt = stmt.where(AuditLogEntry.action_type == action_type)
        if outcome is not None:
            stmt = stmt.where(AuditLogEntry.outcome == outcome)
        if confirmation_id is not None:
            stmt = stmt.where(AuditLogEntry.confirmation_id == confirmation_id)
        return list(session.execute(stmt).scalars().all())

    def get(self, session, entry_id: int) -> AuditLogEntry | None:
        return session.get(AuditLogEntry, entry_id)

    def get_last(self, session) -> AuditLogEntry | None:
        stmt = select(AuditLogEntry).order_by(AuditLogEntry.seq.desc()).limit(1)
        return session.execute(stmt).scalars().first()

    # -- integrity ------------------------------------------------------------
    def verify(self, session) -> VerifyResult:
        rows = session.execute(
            select(AuditLogEntry).order_by(AuditLogEntry.seq)
        ).scalars().all()
        return verify_audit_rows(
            rows,
            genesis_hash=self.genesis_hash,
            signer=self.signer,
        )


class SQLiteConfirmationRepo:
    def create(self, session, confirmation: PendingConfirmation) -> PendingConfirmation:
        session.add(confirmation)
        session.flush()
        return confirmation

    def get(self, session, confirmation_id: str) -> PendingConfirmation | None:
        return session.get(PendingConfirmation, confirmation_id)

    def update(self, session, confirmation: PendingConfirmation) -> PendingConfirmation:
        session.add(confirmation)
        session.flush()
        return confirmation


class SQLitePolicyRepo:
    def get_current(self, session) -> PolicyVersion | None:
        stmt = select(PolicyVersion).order_by(PolicyVersion.version.desc()).limit(1)
        return session.execute(stmt).scalars().first()

    def create(self, session, version: int, document: dict, changed_by: str) -> PolicyVersion:
        row = PolicyVersion(version=version, document=document, changed_by=changed_by)
        session.add(row)
        session.flush()
        return row


class SQLiteUserRepo:
    def get(self, session, user_id: str) -> User | None:
        return session.get(User, user_id)

    def get_by_username(self, session, username: str) -> User | None:
        stmt = select(User).where(User.username == username)
        return session.execute(stmt).scalars().first()

    def create(self, session, user: User) -> User:
        session.add(user)
        session.flush()
        return user

    def update(self, session, user: User) -> User:
        session.add(user)
        session.flush()
        return user

    def list(self, session) -> list[User]:
        stmt = select(User).order_by(User.username)
        return list(session.execute(stmt).scalars().all())


class SQLiteApiKeyRepo:
    def get(self, session, key_id: str) -> ApiKey | None:
        return session.get(ApiKey, key_id)

    def get_by_hash(self, session, key_hash: str) -> ApiKey | None:
        stmt = select(ApiKey).where(ApiKey.key_hash == key_hash)
        return session.execute(stmt).scalars().first()

    def create(self, session, key: ApiKey) -> ApiKey:
        session.add(key)
        session.flush()
        return key

    def update(self, session, key: ApiKey) -> ApiKey:
        session.add(key)
        session.flush()
        return key

    def list_by_user(self, session, user_id: str) -> list[ApiKey]:
        stmt = select(ApiKey).where(ApiKey.user_id == user_id).order_by(ApiKey.created_at)
        return list(session.execute(stmt).scalars().all())

    def list(self, session) -> list[ApiKey]:
        stmt = select(ApiKey).order_by(ApiKey.created_at)
        return list(session.execute(stmt).scalars().all())


class SQLiteVaultRepo:
    """SQLite credential vault storage (Phase 3C). Ciphertext-only rows."""

    def create(self, session, secret: VaultSecret) -> VaultSecret:
        session.add(secret)
        session.flush()
        return secret

    def get(self, session, domain: str, name: str) -> VaultSecret | None:
        stmt = select(VaultSecret).where(VaultSecret.domain == domain,
                                         VaultSecret.name == name)
        return session.execute(stmt).scalars().first()

    def get_by_id(self, session, secret_id: str) -> VaultSecret | None:
        return session.get(VaultSecret, secret_id)

    def list(self, session, domain: str | None = None) -> list[VaultSecret]:
        stmt = select(VaultSecret)
        if domain is not None:
            stmt = stmt.where(VaultSecret.domain == domain)
        stmt = stmt.order_by(VaultSecret.domain, VaultSecret.name)
        return list(session.execute(stmt).scalars().all())

    def update(self, session, secret: VaultSecret) -> VaultSecret:
        session.add(secret)
        session.flush()
        return secret


class SQLiteAgentRunRepo:
    """Agent run persistence (Phase 3A)."""

    def create(self, session, run: AgentRun) -> AgentRun:
        session.add(run)
        session.flush()
        return run

    def get(self, session, run_id: str) -> AgentRun | None:
        return session.get(AgentRun, run_id)

    def update(self, session, run: AgentRun) -> AgentRun:
        session.add(run)
        session.flush()
        return run

    def list_by_actor(self, session, actor_id: str, *, limit: int = 50) -> list[AgentRun]:
        stmt = (select(AgentRun).where(AgentRun.actor_id == actor_id)
                .order_by(AgentRun.created_at.desc()).limit(limit))
        return list(session.execute(stmt).scalars().all())


class SQLiteMemoryRepo:
    """Long-term agent memory storage (Phase 3A)."""

    def create(self, session, entry: MemoryEntry) -> MemoryEntry:
        session.add(entry)
        session.flush()
        return entry

    def get(self, session, actor_id: str, namespace: str, key: str) -> MemoryEntry | None:
        stmt = select(MemoryEntry).where(
            MemoryEntry.actor_id == actor_id,
            MemoryEntry.namespace == namespace,
            MemoryEntry.key == key,
        )
        return session.execute(stmt).scalars().first()

    def update(self, session, entry: MemoryEntry) -> MemoryEntry:
        session.add(entry)
        session.flush()
        return entry

    def list_namespace(self, session, actor_id: str, namespace: str) -> list[MemoryEntry]:
        stmt = (select(MemoryEntry).where(
            MemoryEntry.actor_id == actor_id,
            MemoryEntry.namespace == namespace,
        ).order_by(MemoryEntry.updated_at))
        return list(session.execute(stmt).scalars().all())

    def delete(self, session, actor_id: str, namespace: str, key: str) -> bool:
        entry = self.get(session, actor_id, namespace, key)
        if entry is None:
            return False
        session.delete(entry)
        session.flush()
        return True


class SQLiteIdempotencyRepo:
    """Replay-dedup storage (Phase 3G)."""

    def create(self, session, record: IdempotencyRecord) -> IdempotencyRecord:
        session.add(record)
        session.flush()
        return record

    def get(self, session, actor_id: str, key_hash: str) -> IdempotencyRecord | None:
        stmt = select(IdempotencyRecord).where(
            IdempotencyRecord.actor_id == actor_id,
            IdempotencyRecord.key_hash == key_hash,
        )
        return session.execute(stmt).scalars().first()

    def update(self, session, record: IdempotencyRecord) -> IdempotencyRecord:
        session.add(record)
        session.flush()
        return record

    def delete(self, session, record: IdempotencyRecord) -> None:
        session.delete(record)
        session.flush()


class SQLiteJobRepo:
    """Background job storage (Phase 3G)."""

    def create(self, session, job: Job) -> Job:
        session.add(job)
        session.flush()
        return job

    def get(self, session, job_id: str) -> Job | None:
        return session.get(Job, job_id)

    def get_by_idempotency_key(self, session, actor_id: str, key_hash: str) -> Job | None:
        stmt = select(Job).where(
            Job.actor_id == actor_id,
            Job.idempotency_key_hash == key_hash,
        )
        return session.execute(stmt).scalars().first()

    def update(self, session, job: Job) -> Job:
        session.add(job)
        session.flush()
        return job

    def list_by_actor(self, session, actor_id: str, *, limit: int = 50) -> list[Job]:
        stmt = (select(Job).where(Job.actor_id == actor_id)
                .order_by(Job.created_at.desc()).limit(limit))
        return list(session.execute(stmt).scalars().all())

    def list_by_statuses(self, session, statuses: list[str]) -> list[Job]:
        stmt = select(Job).where(Job.status.in_(statuses))
        return list(session.execute(stmt).scalars().all())


class SQLiteScheduleRepo:
    """SQLite schedule repository (Phase 3H)."""

    def create(self, session, schedule: Schedule) -> Schedule:
        session.add(schedule)
        session.flush()
        return schedule

    def get(self, session, schedule_id: str) -> Schedule | None:
        return session.get(Schedule, schedule_id)

    def update(self, session, schedule: Schedule) -> Schedule:
        session.add(schedule)
        session.flush()
        return schedule

    def delete(self, session, schedule: Schedule) -> bool:
        session.delete(schedule)
        session.flush()
        return True

    def list_by_actor(self, session, actor_id: str, *, limit: int = 50) -> list[Schedule]:
        stmt = (select(Schedule).where(Schedule.actor_id == actor_id)
                .order_by(Schedule.created_at.desc()).limit(limit))
        return list(session.execute(stmt).scalars().all())

    def list_due(self, session, now_iso: str, *, limit: int = 100) -> list[Schedule]:
        stmt = (select(Schedule).where(
            Schedule.enabled.is_(True),
            Schedule.next_run_at.is_not(None),
            Schedule.next_run_at <= now_iso,
        ).order_by(Schedule.next_run_at.asc()).limit(limit))
        return list(session.execute(stmt).scalars().all())


class SQLiteWorkflowRunRepo:
    """Durable workflow run storage (Phase 4C)."""

    def create_run(self, session, run: WorkflowRun) -> WorkflowRun:
        session.add(run)
        session.flush()
        return run

    def get_run(self, session, run_id: str) -> WorkflowRun | None:
        return session.get(WorkflowRun, run_id)

    def get_run_by_token(self, session, actor_id: str, run_token: str) -> WorkflowRun | None:
        stmt = select(WorkflowRun).where(
            WorkflowRun.actor_id == actor_id,
            WorkflowRun.run_token == run_token,
        )
        return session.execute(stmt).scalars().first()

    def update_run(self, session, run: WorkflowRun) -> WorkflowRun:
        session.add(run)
        session.flush()
        return run

    def list_runs_by_actor(self, session, actor_id: str, *, limit: int = 50) -> list[WorkflowRun]:
        stmt = (select(WorkflowRun).where(WorkflowRun.actor_id == actor_id)
                .order_by(WorkflowRun.created_at.desc()).limit(limit))
        return list(session.execute(stmt).scalars().all())

    def _filtered_stmt(
        self,
        *,
        actor_id: str | None = None,
        status: str | None = None,
        workflow_name: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
    ):
        stmt = select(WorkflowRun)
        if actor_id is not None:
            stmt = stmt.where(WorkflowRun.actor_id == actor_id)
        if status is not None:
            stmt = stmt.where(WorkflowRun.status == status)
        if workflow_name is not None:
            stmt = stmt.where(WorkflowRun.workflow_name == workflow_name)
        if start_at is not None:
            stmt = stmt.where(WorkflowRun.created_at >= start_at)
        if end_at is not None:
            stmt = stmt.where(WorkflowRun.created_at <= end_at)
        return stmt

    def list_runs_filtered(
        self,
        session,
        *,
        actor_id: str | None = None,
        status: str | None = None,
        workflow_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[WorkflowRun]:
        stmt = (self._filtered_stmt(actor_id=actor_id, status=status,
                                    workflow_name=workflow_name)
                .order_by(WorkflowRun.created_at.desc())
                .limit(limit).offset(offset))
        return list(session.execute(stmt).scalars().all())

    def count_runs_filtered(
        self,
        session,
        *,
        actor_id: str | None = None,
        status: str | None = None,
        workflow_name: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
    ) -> int:
        stmt = self._filtered_stmt(actor_id=actor_id, status=status,
                                   workflow_name=workflow_name,
                                   start_at=start_at, end_at=end_at)
        stmt = stmt.with_only_columns(func.count(WorkflowRun.id))
        return int(session.execute(stmt).scalar() or 0)

    def list_awaiting_runs(
        self, session, *, statuses: list[str] | None = None, limit: int = 50
    ) -> list[WorkflowRun]:
        statuses = statuses or ["waiting_for_user", "ambiguous"]
        stmt = (select(WorkflowRun).where(WorkflowRun.status.in_(statuses))
                .order_by(WorkflowRun.updated_at.desc()).limit(limit))
        return list(session.execute(stmt).scalars().all())

    def create_step(self, session, step: WorkflowStepRun) -> WorkflowStepRun:
        session.add(step)
        session.flush()
        return step

    def get_step(self, session, step_id: str) -> WorkflowStepRun | None:
        return session.get(WorkflowStepRun, step_id)

    def list_steps(self, session, run_id: str) -> list[WorkflowStepRun]:
        stmt = (select(WorkflowStepRun).where(WorkflowStepRun.run_id == run_id)
                .order_by(WorkflowStepRun.step_index.asc()))
        return list(session.execute(stmt).scalars().all())

    def update_step(self, session, step: WorkflowStepRun) -> WorkflowStepRun:
        session.add(step)
        session.flush()
        return step


class SQLiteCircuitBreakerStateRepo:
    """Durable breaker snapshots; SQL shape is shared with PostgreSQL."""

    def get(self, session, provider_id: str) -> CircuitBreakerStateRow | None:
        return session.get(CircuitBreakerStateRow, provider_id)

    def upsert(
        self,
        session,
        *,
        provider_id: str,
        state: str,
        consecutive_failures: int,
        opened_at: float | None,
    ) -> CircuitBreakerStateRow:
        row = self.get(session, provider_id)
        if row is None:
            row = CircuitBreakerStateRow(provider_id=provider_id)
            session.add(row)
        row.state = state
        row.consecutive_failures = consecutive_failures
        row.opened_at = opened_at
        row.updated_at = utcnow_iso()
        session.flush()
        return row


class SQLiteWorkflowScheduleRepo:
    """SQLite workflow-schedule storage (Phase 4D)."""

    def create(self, session, schedule: WorkflowSchedule) -> WorkflowSchedule:
        session.add(schedule)
        session.flush()
        return schedule

    def get(self, session, schedule_id: str) -> WorkflowSchedule | None:
        return session.get(WorkflowSchedule, schedule_id)

    def update(self, session, schedule: WorkflowSchedule) -> WorkflowSchedule:
        session.add(schedule)
        session.flush()
        return schedule

    def delete(self, session, schedule: WorkflowSchedule) -> bool:
        session.delete(schedule)
        session.flush()
        return True

    def list_by_actor(self, session, actor_id: str, *, limit: int = 50) -> list[WorkflowSchedule]:
        stmt = (select(WorkflowSchedule)
                .where(WorkflowSchedule.actor_id == actor_id)
                .order_by(WorkflowSchedule.created_at.desc()).limit(limit))
        return list(session.execute(stmt).scalars().all())

    def list_due(self, session, now_iso: str, *, limit: int = 100) -> list[WorkflowSchedule]:
        stmt = (select(WorkflowSchedule).where(
            WorkflowSchedule.enabled.is_(True),
            WorkflowSchedule.next_run_at.is_not(None),
            WorkflowSchedule.next_run_at <= now_iso,
        ).order_by(WorkflowSchedule.next_run_at.asc()).limit(limit))
        return list(session.execute(stmt).scalars().all())

    def get_by_name(self, session, actor_id: str, name: str) -> WorkflowSchedule | None:
        stmt = select(WorkflowSchedule).where(
            WorkflowSchedule.actor_id == actor_id,
            WorkflowSchedule.name == name,
        )
        return session.execute(stmt).scalars().first()


class SQLiteWorkflowTemplateRepo:
    """SQLite immutable workflow-template version storage."""

    def create(self, session, template: WorkflowTemplate) -> WorkflowTemplate:
        session.add(template)
        session.flush()
        return template

    def get_latest(self, session, name: str) -> WorkflowTemplate | None:
        stmt = (select(WorkflowTemplate)
                .where(WorkflowTemplate.name == name,
                       WorkflowTemplate.status == "published")
                .order_by(WorkflowTemplate.version.desc()).limit(1))
        return session.execute(stmt).scalars().first()

    def get(self, session, name: str, version: int) -> WorkflowTemplate | None:
        stmt = select(WorkflowTemplate).where(
            WorkflowTemplate.name == name,
            WorkflowTemplate.version == version,
        )
        return session.execute(stmt).scalars().first()

    def list(self, session, *, limit: int = 100) -> list[WorkflowTemplate]:
        stmt = (select(WorkflowTemplate)
                .order_by(WorkflowTemplate.name.asc(),
                          WorkflowTemplate.version.desc()).limit(limit))
        return list(session.execute(stmt).scalars().all())


class SQLiteWorkflowGovernanceRepo:
    """SQLite atomic admission/budget counters (Phase 4D).

    Uses a portable ``INSERT ... ON CONFLICT ... DO UPDATE`` upsert. Because the
    counter's ``(kind, scope)`` is unique, two worker threads that race an
    admission guarantee serialize their updates at the row level: whichever
    wins first increments; the loser observes ``incremented=False`` when the cap
    has already been reached.
    """

    def get(self, session, kind: str, scope: str) -> WorkflowGovernanceCounter | None:
        stmt = select(WorkflowGovernanceCounter).where(
            WorkflowGovernanceCounter.kind == kind,
            WorkflowGovernanceCounter.scope == scope,
        )
        return session.execute(stmt).scalars().first()

    def bump(
        self,
        session,
        *,
        kind: str,
        scope: str,
        delta: int = 1,
        cap: int | None = None,
    ) -> tuple[int, bool]:
        cap = cap if cap is not None else 2**31 - 1
        # Atomic conditional UPDATE: only increments while the cap allows it.
        update = text(
            """
            UPDATE workflow_governance_counter
            SET count = count + :delta, updated_at = :now
            WHERE kind = :kind AND scope = :scope AND count + :delta <= :cap
            """
        )
        result = session.execute(update, {
            "kind": kind,
            "scope": scope,
            "delta": delta,
            "cap": cap,
            "now": utcnow_iso(),
        })
        if result.rowcount and int(result.rowcount) > 0:
            row = self.get(session, kind, scope)
            return (row.count if row is not None else 0, True)

        # No existing row or the cap is already reached. Try to insert when it
        # does not yet exist and the first delta fits under the cap.
        insert = text(
            """
            INSERT INTO workflow_governance_counter
                (id, kind, scope, count, updated_at)
            VALUES (:id, :kind, :scope, :delta, :now)
            ON CONFLICT(kind, scope) DO NOTHING
            """
        )
        inserted = session.execute(insert, {
            "id": f"{kind}:{scope}"[:64],
            "kind": kind,
            "scope": scope,
            "delta": delta,
            "now": utcnow_iso(),
        })
        if inserted.rowcount and int(inserted.rowcount) > 0:
            return delta, True
        row = self.get(session, kind, scope)
        return (row.count if row is not None else 0), False

    def reset(self, session, kind: str, scope: str) -> None:
        row = self.get(session, kind, scope)
        if row is not None:
            row.count = 0
            row.updated_at = utcnow_iso()
            session.add(row)
            session.flush()


class SQLiteConfirmationApprovalRepo:
    """SQLite dual-approval storage (Phase 4E)."""

    def create(self, session, approval) -> ConfirmationApproval:
        session.add(approval)
        session.flush()
        return approval

    def get_by_actor(self, session, confirmation_id: str,
                     actor_id: str) -> ConfirmationApproval | None:
        stmt = (
            select(ConfirmationApproval)
            .where(ConfirmationApproval.confirmation_id == confirmation_id)
            .where(ConfirmationApproval.actor_id == actor_id)
        )
        return session.execute(stmt).scalar_one_or_none()

    def list_for_confirmation(self, session,
                              confirmation_id: str) -> list[ConfirmationApproval]:
        stmt = (
            select(ConfirmationApproval)
            .where(ConfirmationApproval.confirmation_id == confirmation_id)
            .order_by(ConfirmationApproval.sequence)
        )
        return list(session.execute(stmt).scalars().all())

    def count_granted(self, session, confirmation_id: str) -> int:
        stmt = (
            select(func.count())
            .select_from(ConfirmationApproval)
            .where(ConfirmationApproval.confirmation_id == confirmation_id)
            .where(ConfirmationApproval.status == "GRANTED")
        )
        return int(session.execute(stmt).scalar_one())
