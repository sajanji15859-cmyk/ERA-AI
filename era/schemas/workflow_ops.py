"""Phase 4D workflow operations / governance request & response schemas."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from era.security.validation import MAX_NAME_LEN, validate_name

_EXTRA_FORBID = ConfigDict(extra="forbid")


class WorkflowScheduleCreate(BaseModel):
    model_config = _EXTRA_FORBID

    name: str = Field(..., max_length=MAX_NAME_LEN)
    workflow: str = Field(..., max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)
    cron_expr: str | None = None
    interval_seconds: int | None = Field(default=None, ge=1)
    enabled: bool = True
    workflow_version: int | None = Field(default=None, ge=1)

    def model_post_init(self, context: Any, /) -> None:
        validate_name(self.name)
        if not self.cron_expr and not self.interval_seconds:
            raise ValueError("must specify either cron_expr or interval_seconds")
        if self.cron_expr:
            from era.core.cron import CronError, CronSchedule
            try:
                CronSchedule(self.cron_expr)
            except CronError as exc:
                raise ValueError(f"invalid cron_expr: {exc}") from exc


class WorkflowScheduleUpdate(BaseModel):
    model_config = _EXTRA_FORBID

    name: str | None = Field(default=None, max_length=MAX_NAME_LEN)
    params: dict[str, Any] | None = None
    cron_expr: str | None = None
    interval_seconds: int | None = Field(default=None, ge=1)
    workflow_version: int | None = Field(default=None, ge=1)
    enabled: bool | None = None

    def model_post_init(self, context: Any, /) -> None:
        if self.name is not None:
            validate_name(self.name)
        if self.cron_expr:
            from era.core.cron import CronError, CronSchedule
            try:
                CronSchedule(self.cron_expr)
            except CronError as exc:
                raise ValueError(f"invalid cron_expr: {exc}") from exc


class WorkflowScheduleOut(BaseModel):
    model_config = _EXTRA_FORBID

    schedule_id: str
    actor_id: str
    name: str
    workflow: str
    workflow_version: int | None = None
    params: dict[str, Any]
    cron_expr: str | None = None
    interval_seconds: int | None = None
    enabled: bool
    last_run_at: str | None = None
    next_run_at: str | None = None
    last_run_id: str | None = None
    created_at: str
    updated_at: str

    @classmethod
    def from_schedule(cls, row) -> WorkflowScheduleOut:
        return cls(
            schedule_id=row.id,
            actor_id=row.actor_id,
            name=row.name,
            workflow=row.workflow_name,
            workflow_version=row.workflow_version,
            params=dict(row.params_redacted or {}),
            cron_expr=row.cron_expr,
            interval_seconds=row.interval_seconds,
            enabled=bool(row.enabled),
            last_run_at=row.last_run_at,
            next_run_at=row.next_run_at,
            last_run_id=row.last_run_id,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


class WorkflowScheduleListOut(BaseModel):
    model_config = _EXTRA_FORBID

    schedules: list[WorkflowScheduleOut] = Field(default_factory=list)


class WorkflowTemplatePublishRequest(BaseModel):
    model_config = _EXTRA_FORBID

    definition: dict[str, Any]


class WorkflowTemplateOut(BaseModel):
    model_config = _EXTRA_FORBID

    name: str
    version: int
    params_schema: dict[str, Any]
    checksum: str
    status: str
    created_by: str
    created_at: str
    published_at: str


class WorkflowTemplateInstantiateRequest(BaseModel):
    model_config = _EXTRA_FORBID

    name: str
    version: int | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class WorkflowTemplateInstantiateOut(BaseModel):
    model_config = _EXTRA_FORBID

    name: str
    version: int
    checksum: str
    prepared: bool = True
    step_ids: list[str] = Field(default_factory=list)
    params_schema: dict[str, Any] = Field(default_factory=dict)


class WorkflowRunQuery(BaseModel):
    model_config = _EXTRA_FORBID

    status: str | None = None
    workflow: str | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
    start_at: str | None = None
    end_at: str | None = None


class WorkflowAggregationOut(BaseModel):
    model_config = _EXTRA_FORBID

    workflow: str | None = None
    total: int
    by_status: dict[str, int]
    durations: dict[str, float]


class WorkflowTimelineEventOut(BaseModel):
    model_config = _EXTRA_FORBID

    at: str | None = None
    kind: str
    step_id: str | None = None
    status: str | None = None
    confirmation_id: str | None = None
    error_code: str | None = None


class WorkflowOperatorResolveRequest(BaseModel):
    model_config = _EXTRA_FORBID

    decision: Literal["continue", "abort"]
    reason: str = Field(default="", max_length=500)


class WorkflowOperatorCancelRequest(BaseModel):
    model_config = _EXTRA_FORBID

    reason: str = Field(default="", max_length=500)


class WorkflowOperatorApproveRequest(BaseModel):
    model_config = _EXTRA_FORBID

    confirmation_id: str
    action_type: str
    action_params: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(default="", max_length=500)


__all__ = [
    "WorkflowAggregationOut",
    "WorkflowOperatorApproveRequest",
    "WorkflowOperatorCancelRequest",
    "WorkflowOperatorResolveRequest",
    "WorkflowRunQuery",
    "WorkflowScheduleCreate",
    "WorkflowScheduleListOut",
    "WorkflowScheduleOut",
    "WorkflowScheduleUpdate",
    "WorkflowTemplateInstantiateOut",
    "WorkflowTemplateInstantiateRequest",
    "WorkflowTemplateOut",
    "WorkflowTemplatePublishRequest",
    "WorkflowTimelineEventOut",
]
