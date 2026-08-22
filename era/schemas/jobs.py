"""Background job request/response schemas (Phase 3G)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from era.schemas.actions import ExecutionResponse


class JobOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str
    status: str  # queued | running | completed | failed
    action_type: str
    created_at: str
    updated_at: str
    result: ExecutionResponse | None = None
    error: str | None = None

    @classmethod
    def from_job(cls, job) -> JobOut:
        result = None
        if job.response_json:
            result = ExecutionResponse.model_validate(job.response_json)
        return cls(
            job_id=job.id,
            status=job.status,
            action_type=job.action_type,
            created_at=job.created_at,
            updated_at=job.updated_at,
            result=result,
            error=job.error,
        )


class JobListOut(BaseModel):
    jobs: list[JobOut] = Field(default_factory=list)
