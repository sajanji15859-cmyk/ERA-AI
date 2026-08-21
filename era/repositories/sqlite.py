"""SQLite repository implementations (the Phase 1C storage backend)."""

from __future__ import annotations

from sqlalchemy import select

from era.core.util import utcnow_iso
from era.models import (
    AgentRun,
    ApiKey,
    AuditLogEntry,
    MemoryEntry,
    PendingConfirmation,
    PolicyVersion,
    User,
)
from era.repositories.base import NewAuditEntry, VerifyResult
from era.security.hashing import canonical_json, sha256_hex


class SQLiteAuditRepo:
    """SQLite audit storage. Append-only; computes the hash chain on write."""

    def __init__(self, genesis_hash: str):
        self.genesis_hash = genesis_hash

    # -- write ----------------------------------------------------------------
    def append(self, session, entry: NewAuditEntry) -> AuditLogEntry:
        last = self.get_last(session)
        seq = (last.seq + 1) if last else 1
        prev_hash = last.entry_hash if last else self.genesis_hash
        created_at = utcnow_iso()

        payload = {
            "seq": seq,
            "created_at": created_at,
            "actor_id": entry.actor_id,
            "action_type": entry.action_type,
            "action_params": entry.action_params,
            "risk_level": entry.risk_level,
            "decision": entry.decision,
            "outcome": entry.outcome,
            "confirmation_id": entry.confirmation_id,
            "result": entry.result,
            "error_code": entry.error_code,
            "provider_id": entry.provider_id,
            "capability_domain": entry.capability_domain,
            "credential_ref": entry.credential_ref,
            "policy_version": entry.policy_version,
            "app_version": entry.app_version,
            "meta": entry.meta,
            "prev_hash": prev_hash,
        }
        entry_hash = sha256_hex(canonical_json(payload))

        row = AuditLogEntry(
            seq=seq,
            created_at=created_at,
            actor_id=entry.actor_id,
            action_type=entry.action_type,
            action_params=entry.action_params,
            risk_level=entry.risk_level,
            decision=entry.decision,
            outcome=entry.outcome,
            confirmation_id=entry.confirmation_id,
            result=entry.result,
            error_code=entry.error_code,
            provider_id=entry.provider_id,
            capability_domain=entry.capability_domain,
            credential_ref=entry.credential_ref,
            policy_version=entry.policy_version,
            app_version=entry.app_version,
            meta=entry.meta,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
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
        rows = list(
            session.execute(select(AuditLogEntry).order_by(AuditLogEntry.seq)).scalars().all()
        )
        if not rows:
            return VerifyResult(valid=True, entry_count=0, message="empty log")

        prev = self.genesis_hash
        for row in rows:
            if row.prev_hash != prev:
                return VerifyResult(
                    valid=False, entry_count=len(rows),
                    first_mismatch_seq=row.seq,
                    message=f"broken chain link at seq {row.seq}",
                )
            expected = sha256_hex(canonical_json(self._payload_from_row(row)))
            if row.entry_hash != expected:
                return VerifyResult(
                    valid=False, entry_count=len(rows),
                    first_mismatch_seq=row.seq,
                    message=f"entry hash mismatch at seq {row.seq}",
                )
            prev = row.entry_hash
        return VerifyResult(valid=True, entry_count=len(rows), message="chain valid")

    @staticmethod
    def _payload_from_row(row: AuditLogEntry) -> dict:
        return {f: getattr(row, f) for f in AuditLogEntry.HASH_FIELDS}


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
