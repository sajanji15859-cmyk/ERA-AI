"""Agent run models: plans, tasks, observations, run records (Phase 3A).

These are the *orchestration* data structures of the ERA agent. They never
carry credentials and never replace the permission/audit core — every tool
execution still goes through :class:`era.services.execution_service.ExecutionService`.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    WAITING_FOR_USER = "waiting_for_user"
    SKIPPED = "skipped"


class RunStatus(StrEnum):
    PLANNING = "planning"
    RUNNING = "running"
    WAITING_FOR_USER = "waiting_for_user"
    COMPLETED = "completed"
    FAILED = "failed"
    BUDGET_EXCEEDED = "budget_exceeded"


class Task(BaseModel):
    """One actionable step of a plan.

    ``action_type`` must be a catalogued action (unknown types are DENYed by
    the permission engine). ``verify`` is an optional verification spec the
    loop checks after the tool observation (see ``era/agents/verifier.py``).
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    action_type: str
    params: dict[str, Any] = Field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    depends_on: list[str] = Field(default_factory=list)
    verify: dict[str, Any] | None = None
    required: bool = True
    attempt: int = 0
    max_attempts: int = 3
    observations: list[dict[str, Any]] = Field(default_factory=list)
    waiting_on: list[str] = Field(default_factory=list)  # confirmation ids
    correction_note: str | None = None
    error: str | None = None


class Plan(BaseModel):
    """A decomposition of the user goal into ordered tasks."""

    goal: str
    summary: str = ""
    tasks: list[Task] = Field(default_factory=list)
    created_by: str = "offline"  # "offline" | "llm"


class Observation(BaseModel):
    """The result of one tool execution, as the loop sees it."""

    task_id: str
    action_type: str
    status: str  # executed | failed | rejected | denied | confirmation_required
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    confirmation_id: str | None = None
    challenge: str | None = None
    error: str | None = None


class AgentResult(BaseModel):
    """Final (or paused) run summary. Cost/usage fields are budget counters."""

    status: RunStatus
    goal: str = ""
    summary: str = ""
    tasks_completed: int = 0
    tasks_failed: int = 0
    tasks_skipped: int = 0
    tool_calls: int = 0
    iterations: int = 0
    llm_calls: int = 0
    estimated_tokens: int = 0
    estimated_cost_usd: float = 0.0
    artifacts: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class RunRecord(BaseModel):
    """Serialisable snapshot of a run — persisted by the AgentService."""

    run_id: str
    actor_id: str
    goal: str
    status: RunStatus
    plan: Plan
    tasks: list[Task] = Field(default_factory=list)
    result: AgentResult = Field(default_factory=lambda: AgentResult(status=RunStatus.PLANNING))
    pending_confirmations: list[str] = Field(default_factory=list)
    error: str | None = None


class ApprovalResolution(BaseModel):
    """Outcome of one previously pending confirmation, resolved from the audit log."""

    confirmation_id: str
    outcome: str  # executed | failed | denied | expired
    note: str = ""
