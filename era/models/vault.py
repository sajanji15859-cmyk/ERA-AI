"""Credential vault persistence model (Phase 3C).

``VaultSecret`` stores provider secrets **encrypted at rest** (AES-256-GCM,
see :mod:`era.security.vault`). Plaintext values never touch the database —
only ciphertext, its nonce and non-sensitive metadata. Revocation is soft
(``revoked_at``) so the append-only audit log can bind later resolutions to
exactly the secret version that was active.
"""

from __future__ import annotations

from sqlalchemy import Column, Integer, LargeBinary, String, UniqueConstraint

from era.core.util import utcnow_iso
from era.models.base import Base
from era.security.vault import ALGORITHM


class VaultSecret(Base):
    __tablename__ = "vault_secret"

    __table_args__ = (
        UniqueConstraint("domain", "name", name="uq_vault_domain_name"),
    )

    id = Column(String, primary_key=True)  # UUID hex
    #: Capability domain (e.g. ``"email"``, ``"github"``, ``"llm"``).
    domain = Column(String, nullable=False, index=True)
    #: Provider-scoped secret name (e.g. ``"smtp_password"``).
    name = Column(String, nullable=False)
    #: Intended owning user. Defaults to the server-derived managing actor; an
    #: authenticated admin may explicitly assign another existing user.
    owner_user_id = Column(String, nullable=False, index=True)
    #: Encryption algorithm id (currently only :data:`era.security.vault.ALGORITHM`).
    algorithm = Column(String, nullable=False, default=ALGORITHM)
    ciphertext = Column(LargeBinary, nullable=False)
    #: Per-value 96-bit GCM nonce (never reused under the master key).
    nonce = Column(LargeBinary, nullable=False)
    #: Length of the plaintext value (chars) — metadata only, never the value.
    value_length = Column(Integer, nullable=False)
    #: Bumped on every rotation; lets audits bind resolutions to a version.
    revision = Column(Integer, nullable=False, default=1)
    created_at = Column(String, nullable=False, default=utcnow_iso)
    updated_at = Column(String, nullable=False, default=utcnow_iso)
    #: Soft revocation. A revoked row can be re-stored (rotated back to life);
    #: while revoked, ``resolve_ref`` fails closed.
    revoked_at = Column(String, nullable=True)
