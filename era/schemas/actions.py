"""Action request/response schemas."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from era.core.enums import Decision, RiskLevel
from era.core.result import ActionResult


class ActionRequest(BaseModel):
    action_type: str
    params: dict[str, Any] = Field(default_factory=dict)
    actor_id: str = "api"
    session_id: str | None = None
    credential_refs: dict[str, str] = Field(default_factory=dict)  # opaque refs only


class EvaluateRequest(BaseModel):
    action_type: str
    params: dict[str, Any] = Field(default_factory=dict)


class EvaluateResponse(BaseModel):
    action_type: str
    decision: Decision
    risk_level: RiskLevel | None = None
    reason: str = ""


ExecutionStatus = Literal[
    "executed", "failed", "rejected", "confirmation_required", "denied"
]


class ExecutionResponse(BaseModel):
    status: ExecutionStatus
    decision: Decision
    confirmation_id: str | None = None
    challenge: str | None = None
    result: ActionResult | None = None
    message: str | None = None
