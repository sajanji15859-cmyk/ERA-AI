"""Schedule request and response schemas (Phase 3H)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from era.core.cron import CronError, CronSchedule
from era.security.validation import (
    MAX_CONTENT_LEN,
    MAX_NAME_LEN,
    ValidationError_,
    validate_action_type,
    validate_name,
    validate_params,
)


class ScheduleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., max_length=MAX_NAME_LEN)
    action_type: str
    action_params: dict[str, Any] = Field(default_factory=dict)
    cron_expr: str | None = None
    interval_seconds: int | None = Field(default=None, ge=1)
    enabled: bool = True

    def model_post_init(self, context: Any, /) -> None:
        validate_name(self.name)
        validate_action_type(self.action_type)
        validate_params(self.action_params, action_type=self.action_type, str_limit=MAX_CONTENT_LEN)
        if not self.cron_expr and not self.interval_seconds:
            raise ValidationError_("must specify either cron_expr or interval_seconds")
        if self.cron_expr:
            try:
                CronSchedule(self.cron_expr)
            except CronError as e:
                raise ValidationError_(f"invalid cron_expr: {e}") from e


class ScheduleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=MAX_NAME_LEN)
    cron_expr: str | None = None
    interval_seconds: int | None = Field(default=None, ge=1)
    action_params: dict[str, Any] | None = None
    enabled: bool | None = None

    def model_post_init(self, context: Any, /) -> None:
        if self.name is not None:
            validate_name(self.name)
        if self.cron_expr is not None and self.cron_expr != "":
            try:
                CronSchedule(self.cron_expr)
            except CronError as e:
                raise ValidationError_(f"invalid cron_expr: {e}") from e
        if self.action_params is not None:
            validate_params(self.action_params, str_limit=MAX_CONTENT_LEN)


class ScheduleOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schedule_id: str
    actor_id: str
    name: str
    cron_expr: str | None = None
    interval_seconds: int | None = None
    action_type: str
    action_params: dict[str, Any]
    enabled: bool
    last_run_at: str | None = None
    next_run_at: str | None = None
    last_job_id: str | None = None
    created_at: str
    updated_at: str

    @classmethod
    def from_schedule(cls, schedule) -> ScheduleOut:
        return cls(
            schedule_id=schedule.id,
            actor_id=schedule.actor_id,
            name=schedule.name,
            cron_expr=schedule.cron_expr,
            interval_seconds=schedule.interval_seconds,
            action_type=schedule.action_type,
            action_params=dict(schedule.action_params or {}),
            enabled=bool(schedule.enabled),
            last_run_at=schedule.last_run_at,
            next_run_at=schedule.next_run_at,
            last_job_id=schedule.last_job_id,
            created_at=schedule.created_at,
            updated_at=schedule.updated_at,
        )


class ScheduleListOut(BaseModel):
    schedules: list[ScheduleOut] = Field(default_factory=list)
