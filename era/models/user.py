"""User and API-key models (Phase 2A server-side identity).

Credentials themselves never live here — only *hashes* of API keys and opaque
credential *references* (never raw secrets). The agent/LLM/permission layers
still see only opaque refs via ``ExecutionContext``.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Column, String

from era.core.util import utcnow_iso
from era.models.base import Base


class User(Base):
    __tablename__ = "user"

    id = Column(String, primary_key=True)  # UUID hex
    username = Column(String, unique=True, nullable=False, index=True)
    display_name = Column(String, nullable=True)
    role = Column(String, nullable=False)  # Role.value ("admin" | "user")
    disabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(String, nullable=False, default=utcnow_iso)
    #: Opaque credential refs per capability domain (e.g. {"email": "ref-..."}).
    #: NEVER raw secrets — the vault (Phase 2B) resolves these references.
    credential_refs = Column(JSON, nullable=False, default=dict)


class ApiKey(Base):
    __tablename__ = "api_key"

    id = Column(String, primary_key=True)  # UUID hex
    user_id = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False)
    #: SHA-256 of the raw key. The raw key is shown exactly once at creation
    #: and never stored — lookup is by hash.
    key_hash = Column(String, unique=True, nullable=False, index=True)
    prefix = Column(String, nullable=False)  # short display fragment, not the key
    created_at = Column(String, nullable=False, default=utcnow_iso)
    last_used_at = Column(String, nullable=True)
    revoked_at = Column(String, nullable=True)  # set on revocation
