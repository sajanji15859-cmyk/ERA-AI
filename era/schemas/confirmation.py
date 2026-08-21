"""Confirmation request/response schemas.

Phase 2A: strict (``extra='forbid'``) and validated; identity is server-side, so
the approve request no longer carries ``actor_id``/``session_id``/
``credential_refs``. The action params are still supplied so the confirmation
hash-binding (anti-substitution) and provider dispatch can proceed, but a
mismatch against the stored authorization is rejected by the execution gate.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from era.core.enums import Decision, RiskLevel
from era.security.validation import (
    ValidationError_,
    validate_action_type,
    validate_challenge,
    validate_params,
)


class ApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: str
    params: dict[str, Any] = Field(default_factory=dict)
    challenge: str | None = None

    @field_validator("action_type")
    @classmethod
    def _action_type(cls, v: Any) -> str:
        try:
            return validate_action_type(v)
        except ValidationError_ as e:
            raise ValueError(str(e)) from None

    @field_validator("params")
    @classmethod
    def _params(cls, v: Any) -> dict[str, Any]:
        try:
            return validate_params(v)
        except ValidationError_ as e:
            raise ValueError(str(e)) from None

    @field_validator("challenge")
    @classmethod
    def _challenge(cls, v: Any) -> str | None:
        try:
            return validate_challenge(v)
        except ValidationError_ as e:
            raise ValueError(str(e)) from None


class ConfirmationStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    action_type: str
    decision: Decision
    risk_level: RiskLevel
    status: str
    expires_at: str
    challenge_required: bool
    action_params: dict[str, Any]  # redacted, for display only
