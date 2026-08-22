"""Background job inspection endpoints (Phase 3G, authenticated).

* ``GET /v1/jobs`` — list the caller's own jobs (newest first).
* ``GET /v1/jobs/{job_id}`` — poll one job (owner only; jobs are actor-scoped
  exactly like agent runs).

Submitting a job happens through ``POST /v1/actions/execute`` with
``async=true``; reading jobs requires the ``jobs.read`` permission.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from era.api.deps import get_container, get_current_principal
from era.container import Container
from era.schemas.jobs import JobListOut, JobOut
from era.security.rbac import Permission

router = APIRouter()


def _job_service(container: Container):
    return container.job_service


@router.get("/v1/jobs", response_model=JobListOut)
def list_jobs(container: Container = Depends(get_container),
              principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.JOBS_READ)
    jobs = _job_service(container).list(principal.actor_id)
    return JobListOut(jobs=[JobOut.from_job(j) for j in jobs])


@router.get("/v1/jobs/{job_id}", response_model=JobOut)
def get_job(job_id: str, container: Container = Depends(get_container),
            principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.JOBS_READ)
    job = _job_service(container).get(job_id, principal.actor_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return JobOut.from_job(job)
