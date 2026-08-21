"""Agent run request/response schemas (Phase 3A)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from era.agents.models import AgentResult, RunRecord, TaskStatus
from era.security.validation import ValidationError_, validate_params

MAX_GOAL_LEN = 2000


class AgentRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    goal: str

    @field_validator("goal")
    @classmethod
    def _goal(cls, v: Any) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("goal must be a non-empty string")
        v = v.strip()
        if len(v) > MAX_GOAL_LEN:
            raise ValueError("goal too long")
        return v


class AgentTaskOut(BaseModel):
    id: str
    title: str
    action_type: str
    status: TaskStatus
    required: bool = True
    attempt: int = 0
    max_attempts: int = 3
    correction_note: str | None = None
    error: str | None = None
    waiting_on: list[str] = Field(default_factory=list)


class AgentRunOut(BaseModel):
    run_id: str
    goal: str
    status: str
    summary: str = ""
    tasks: list[AgentTaskOut] = Field(default_factory=list)
    result: AgentResult
    pending_confirmations: list[str] = Field(default_factory=list)
    error: str | None = None

    @classmethod
    def from_record(cls, record: RunRecord) -> "AgentRunOut":
        return cls(
            run_id=record.run_id,
            goal=record.goal,
            status=record.status.value,
            summary=record.result.summary,
            tasks=[AgentTaskOut(**t.model_dump(include={
                "id", "title", "action_type", "status", "required", "attempt",
                "max_attempts", "correction_note", "error", "waiting_on"})) for t in record.tasks],
            result=record.result,
            pending_confirmations=record.pending_confirmations,
            error=record.error,
        )


class AgentRunListOut(BaseModel):
    runs: list[AgentRunOut] = Field(default_factory=list)
