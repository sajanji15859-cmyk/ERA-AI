"""Confirmation request/response schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from era.core.enums import Decision, RiskLevel


class ApproveRequest(BaseModel):
    action_type: str
    params: dict[str, Any] = Field(default_factory=dict)
    challenge: str | None = None
    actor_id: str = "api"
    session_id: str | None = None
    credential_refs: dict[str, str] = Field(default_factory=dict)


class ConfirmationStatus(BaseModel):
    id: str
    action_type: str
    decision: Decision
    risk_level: RiskLevel
    status: str
    expires_at: str
    challenge_required: bool
    action_params: dict[str, Any]  # redacted, for display only
