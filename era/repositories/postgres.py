"""PostgreSQL repository implementations (Phase 3F).

The ORM queries used by the mutable repositories are deliberately shared with
the proven SQLite implementations. PostgreSQL-specific concurrency semantics
live where they matter: audit appends take a transaction-scoped advisory lock,
and circuit snapshots use an atomic ``ON CONFLICT`` upsert.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert

from era.core.util import utcnow_iso
from era.models import AuditLogEntry, CircuitBreakerStateRow
from era.repositories.audit import build_audit_row
from era.repositories.base import NewAuditEntry
from era.repositories.sqlite import (
    SQLiteAgentRunRepo,
    SQLiteApiKeyRepo,
    SQLiteAuditRepo,
    SQLiteConfirmationRepo,
    SQLiteMemoryRepo,
    SQLitePolicyRepo,
    SQLiteUserRepo,
    SQLiteVaultRepo,
)
from era.security.signing import AuditSigner

# Stable signed 64-bit key dedicated to serializing ERA's single global audit
# chain. pg_advisory_xact_lock is released automatically at transaction end.
_AUDIT_ADVISORY_LOCK_ID = 0x4552414155444954  # "ERAAUDIT"


class PostgresAuditRepo(SQLiteAuditRepo):
    """Concurrent-safe append-only PostgreSQL audit repository."""

    def __init__(self, genesis_hash: str, signer: AuditSigner | None = None):
        super().__init__(genesis_hash=genesis_hash, signer=signer)

    def append(self, session, entry: NewAuditEntry) -> AuditLogEntry:
        session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": _AUDIT_ADVISORY_LOCK_ID},
        )
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


class PostgresConfirmationRepo(SQLiteConfirmationRepo):
    """PostgreSQL confirmation lifecycle repository."""


class PostgresPolicyRepo(SQLitePolicyRepo):
    """PostgreSQL versioned-policy repository."""


class PostgresUserRepo(SQLiteUserRepo):
    """PostgreSQL user repository."""


class PostgresApiKeyRepo(SQLiteApiKeyRepo):
    """PostgreSQL hashed API-key repository."""


class PostgresVaultRepo(SQLiteVaultRepo):
    """PostgreSQL ciphertext-only vault repository."""


class PostgresAgentRunRepo(SQLiteAgentRunRepo):
    """PostgreSQL durable agent-run repository."""


class PostgresMemoryRepo(SQLiteMemoryRepo):
    """PostgreSQL long-term memory repository."""


class PostgresCircuitBreakerStateRepo:
    """Atomic PostgreSQL upserts for shared circuit-breaker snapshots."""

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
        values = {
            "provider_id": provider_id,
            "state": state,
            "consecutive_failures": consecutive_failures,
            "opened_at": opened_at,
            "updated_at": utcnow_iso(),
        }
        statement = (
            insert(CircuitBreakerStateRow)
            .values(**values)
            .on_conflict_do_update(
                index_elements=[CircuitBreakerStateRow.provider_id],
                set_={key: value for key, value in values.items() if key != "provider_id"},
            )
            .returning(CircuitBreakerStateRow)
        )
        return session.execute(statement).scalar_one()
