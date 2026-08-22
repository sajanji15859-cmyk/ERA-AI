"""Workflow API request/response schemas (Phase 4C).

Request schemas reject unknown fields (``extra='forbid'``). Run inputs carry
opaque params (URLs and vault references) only — never plaintext secrets.
Responses are sanitized: raw element refs, cookies, headers and page content
are never returned.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from era.core.util import utcnow_iso


class WorkflowRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Registered workflow name OR an inline strict-schema definition.
    workflow: str | None = None
    definition: dict[str, Any] | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    #: Exactly-once key (unique per actor); reusing it returns the existing run.
    run_token: str | None = None

    @field_validator("workflow")
    @classmethod
    def _workflow(cls, v: Any) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str) or not v.strip():
            raise ValueError("workflow must be a non-empty string")
        v = v.strip()
        if len(v) > 64:
            raise ValueError("workflow name too long")
        return v

    @field_validator("run_token")
    @classmethod
    def _run_token(cls, v: Any) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str) or not v.strip():
            raise ValueError("run_token must be a non-empty string")
        v = v.strip()
        if len(v) > 128:
            raise ValueError("run_token too long")
        return v


class WorkflowResumeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkflowResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["continue", "abort"]


class WorkflowStepOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str
    step_index: int
    action_type: str
    status: str
    attempt: int
    confirmation_id: str | None = None
    result_receipt: dict[str, Any] | None = None
    error_code: str | None = None
    error_message: str | None = None


class WorkflowRunOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    workflow_name: str
    workflow_version: int
    status: str
    current_step: int
    error: str | None = None
    run_token: str
    created_at: str = utcnow_iso()
    updated_at: str = utcnow_iso()
    steps: list[WorkflowStepOut] = Field(default_factory=list)
    definition_checksum: str


def run_to_out(run, steps) -> WorkflowRunOut:
    return WorkflowRunOut(
        id=run.id,
        workflow_name=run.workflow_name,
        workflow_version=run.workflow_version,
        status=run.status,
        current_step=run.current_step,
        error=run.error,
        run_token=run.run_token,
        created_at=run.created_at,
        updated_at=run.updated_at,
        definition_checksum=run.definition_checksum,
        steps=[
            WorkflowStepOut(
                step_id=s.step_id,
                step_index=s.step_index,
                action_type=s.action_type,
                status=s.status,
                attempt=s.attempt,
                confirmation_id=s.confirmation_id,
                result_receipt=s.result_receipt or None,
                error_code=s.error_code,
                error_message=s.error_message,
            )
            for s in (steps or [])
        ],
    )


__all__ = [
    "WorkflowResolveRequest",
    "WorkflowResumeRequest",
    "WorkflowRunOut",
    "WorkflowRunRequest",
    "WorkflowStepOut",
    "run_to_out",
]
