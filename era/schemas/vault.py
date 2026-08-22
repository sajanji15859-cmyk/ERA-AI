"""Vault secret management schemas (Phase 3C).

Admin-only request/response schemas. Strict (``extra='forbid'``). The
**value** is accepted on write but is NEVER returned by any endpoint —
responses carry metadata only. The managing actor is server-derived; an admin
may explicitly assign ``owner_user_id`` so per-user provider resolution can be
enforced without sharing credentials across actors.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

from era.security.vault import MAX_VAULT_VALUE_LENGTH, VaultError, validate_vault_part


def _validate_part(v: Any, what: str) -> str:
    try:
        return validate_vault_part(v, what)
    except (VaultError, TypeError) as e:
        raise ValueError(str(e)) from None


class VaultSecretIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str
    name: str
    value: str
    #: Admin may assign a provider secret to its intended user. Defaults to the
    #: managing admin for backward compatibility.
    owner_user_id: str | None = None

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: Any) -> str:
        return _validate_part(v, "domain")

    @field_validator("name")
    @classmethod
    def _name(cls, v: Any) -> str:
        return _validate_part(v, "name")

    @field_validator("value")
    @classmethod
    def _value(cls, v: Any) -> str:
        if not isinstance(v, str) or not v:
            raise ValueError("value must be a non-empty string")
        if len(v) > MAX_VAULT_VALUE_LENGTH:
            raise ValueError(f"value too long (max {MAX_VAULT_VALUE_LENGTH} chars)")
        return v

    @field_validator("owner_user_id")
    @classmethod
    def _owner_user_id(cls, v: Any) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str) or not v.strip() or len(v) > 128:
            raise ValueError("owner_user_id must be a non-empty string up to 128 chars")
        return v.strip()


class VaultSecretOut(BaseModel):
    """Vault metadata. Deliberately has no value / ciphertext fields — a
    response object that can leak the secret is a contract violation."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    domain: str
    name: str
    owner_user_id: str
    algorithm: str
    value_length: int
    revision: int
    created_at: str
    updated_at: str
    revoked_at: str | None
