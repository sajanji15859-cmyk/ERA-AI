"""Repository protocols + shared value objects.

The service layer depends only on these protocols, so PostgreSQL (or another
DB) can replace SQLite later without touching business logic. Note that only
the *audit* repository is append-only; confirmations and policy legitimately
support create/update transitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from era.models import ApiKey, AuditLogEntry, PendingConfirmation, PolicyVersion, User


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
             action_type: str | None = None, outcome: str | None = None) -> list[AuditLogEntry]: ...

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
