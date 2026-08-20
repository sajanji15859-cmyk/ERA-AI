"""SQLite repository implementations (the Phase 1C storage backend)."""

from __future__ import annotations

from sqlalchemy import select

from era.core.util import utcnow_iso
from era.models import AuditLogEntry, PendingConfirmation, PolicyVersion
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
             action_type: str | None = None, outcome: str | None = None) -> list[AuditLogEntry]:
        stmt = select(AuditLogEntry).order_by(AuditLogEntry.seq).limit(limit).offset(offset)
        if action_type is not None:
            stmt = stmt.where(AuditLogEntry.action_type == action_type)
        if outcome is not None:
            stmt = stmt.where(AuditLogEntry.outcome == outcome)
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
