"""User / API-key management schemas (Phase 2A).

Admin-only request/response schemas. Strict (``extra='forbid'``) and validated;
identity is server-derived so callers never supply ``actor_id`` here.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from era.security.validation import (
    ValidationError_,
    validate_name,
)


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    role: str = "user"
    display_name: str | None = None
    credential_refs: dict[str, str] = Field(default_factory=dict)

    @field_validator("username")
    @classmethod
    def _username(cls, v: Any) -> str:
        try:
            return validate_name(v)
        except ValidationError_ as e:
            raise ValueError(str(e)) from None

    @field_validator("role")
    @classmethod
    def _role(cls, v: Any) -> str:
        if v not in ("admin", "user"):
            raise ValueError("role must be 'admin' or 'user'")
        return v


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    username: str
    display_name: str | None
    role: str
    disabled: bool
    created_at: str


class ApiKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str

    @field_validator("name")
    @classmethod
    def _name(cls, v: Any) -> str:
        try:
            return validate_name(v)
        except ValidationError_ as e:
            raise ValueError(str(e)) from None


class ApiKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: str
    user_id: str
    name: str
    prefix: str
    created_at: str
    last_used_at: str | None
    revoked_at: str | None


class CreatedApiKey(ApiKeyOut):
    """ApiKey metadata + the raw key, returned EXACTLY ONCE at creation."""

    raw_key: str
