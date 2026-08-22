"""Action request/response schemas.

Phase 2A hardening: request schemas reject unknown fields (``extra='forbid'``)
and validate the action type and parameter payload bounds so malformed,
unexpected, oversized or unknown inputs are rejected before reaching any
service. Client-supplied identity fields (``actor_id``/``session_id``/
``credential_refs``) have been removed — identity is always derived server-side
from the authenticated principal.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from era.core.enums import Decision, RiskLevel
from era.core.result import ActionResult
from era.security.validation import (
    MAX_CONTENT_LEN,
    ValidationError_,
    validate_action_type,
    validate_params,
)


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: str
    params: dict[str, Any] = Field(default_factory=dict)
    #: Phase 3G: optional client idempotency key. Replaying the same key with
    #: the same request returns the recorded result instead of re-executing;
    #: the same key with a different request is a 409.
    idempotency_key: str | None = None
    #: Phase 3G: when True, execute in the background and return a job id
    #: immediately (poll GET /v1/jobs/{id}).
    async_: bool = Field(default=False, alias="async")

    @field_validator("action_type")
    @classmethod
    def _action_type(cls, v: Any) -> str:
        try:
            return validate_action_type(v)
        except ValidationError_ as e:
            raise ValueError(str(e)) from None

    @field_validator("idempotency_key")
    @classmethod
    def _idempotency_key(cls, v: Any) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str) or not v.strip():
            raise ValueError("idempotency_key must be a non-empty string")
        v = v.strip()
        if len(v) > 128:
            raise ValueError("idempotency_key too long")
        return v

    @field_validator("params")
    @classmethod
    def _params(cls, v: Any) -> dict[str, Any]:
        # Shape/structure check with the widest allowed string cap; the
        # action-aware limit is enforced by the model validator below.
        try:
            return validate_params(v, str_limit=MAX_CONTENT_LEN)
        except ValidationError_ as e:
            raise ValueError(str(e)) from None

    @model_validator(mode="after")
    def _action_aware_params(self) -> ActionRequest:
        try:
            validate_params(self.params, action_type=self.action_type)
        except ValidationError_ as e:
            raise ValueError(str(e)) from None
        return self


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: str
    params: dict[str, Any] = Field(default_factory=dict)

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
            return validate_params(v, str_limit=MAX_CONTENT_LEN)
        except ValidationError_ as e:
            raise ValueError(str(e)) from None

    @model_validator(mode="after")
    def _action_aware_params(self) -> EvaluateRequest:
        try:
            validate_params(self.params, action_type=self.action_type)
        except ValidationError_ as e:
            raise ValueError(str(e)) from None
        return self


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
    #: Phase 4C: machine-readable provider error code on failed/rejected steps,
    #: so the workflow engine can react deterministically (e.g.
    #: ``SIDE_EFFECT_UNKNOWN`` -> ambiguous, never auto-retried).
    error_code: str | None = None
