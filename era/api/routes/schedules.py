"""Scheduled recurring job API routes (Phase 3H, authenticated).

* ``GET /v1/schedules`` — list caller's recurring schedules
* ``POST /v1/schedules`` — create a new schedule (cron or interval)
* ``GET /v1/schedules/{schedule_id}`` — get one schedule
* ``PATCH /v1/schedules/{schedule_id}`` — update/toggle schedule
* ``DELETE /v1/schedules/{schedule_id}`` — delete schedule
* ``POST /v1/schedules/{schedule_id}/enable`` — enable schedule
* ``POST /v1/schedules/{schedule_id}/disable`` — disable schedule
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from era.api.deps import get_container, get_current_principal
from era.container import Container
from era.schemas.schedules import (
    ScheduleCreate,
    ScheduleListOut,
    ScheduleOut,
    ScheduleUpdate,
)
from era.security.exceptions import AuthorizationError
from era.security.rbac import Permission

router = APIRouter()


def _schedule_service(container: Container):
    return container.schedule_service


@router.get("/v1/schedules", response_model=ScheduleListOut)
def list_schedules(container: Container = Depends(get_container),
                   principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.SCHEDULES_READ)
    schedules = _schedule_service(container).list(principal.actor_id)
    return ScheduleListOut(schedules=[ScheduleOut.from_schedule(s) for s in schedules])


@router.post("/v1/schedules", response_model=ScheduleOut, status_code=status.HTTP_201_CREATED)
def create_schedule(body: ScheduleCreate,
                    container: Container = Depends(get_container),
                    principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.SCHEDULES_MANAGE)
    try:
        schedule = _schedule_service(container).create(
            actor_id=principal.actor_id,
            name=body.name,
            action_type=body.action_type,
            action_params=body.action_params,
            cron_expr=body.cron_expr,
            interval_seconds=body.interval_seconds,
            enabled=body.enabled,
        )
    except AuthorizationError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return ScheduleOut.from_schedule(schedule)


@router.get("/v1/schedules/{schedule_id}", response_model=ScheduleOut)
def get_schedule(schedule_id: str,
                 container: Container = Depends(get_container),
                 principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.SCHEDULES_READ)
    schedule = _schedule_service(container).get(schedule_id, principal.actor_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    return ScheduleOut.from_schedule(schedule)


@router.patch("/v1/schedules/{schedule_id}", response_model=ScheduleOut)
def update_schedule(schedule_id: str,
                    body: ScheduleUpdate,
                    container: Container = Depends(get_container),
                    principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.SCHEDULES_MANAGE)
    schedule = _schedule_service(container).update(
        schedule_id=schedule_id,
        actor_id=principal.actor_id,
        name=body.name,
        cron_expr=body.cron_expr,
        interval_seconds=body.interval_seconds,
        action_params=body.action_params,
        enabled=body.enabled,
    )
    if schedule is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    return ScheduleOut.from_schedule(schedule)


@router.delete("/v1/schedules/{schedule_id}")
def delete_schedule(schedule_id: str,
                    container: Container = Depends(get_container),
                    principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.SCHEDULES_MANAGE)
    deleted = _schedule_service(container).delete(schedule_id, principal.actor_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="schedule not found")
    return {"deleted": True, "schedule_id": schedule_id}


@router.post("/v1/schedules/{schedule_id}/enable", response_model=ScheduleOut)
def enable_schedule(schedule_id: str,
                    container: Container = Depends(get_container),
                    principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.SCHEDULES_MANAGE)
    schedule = _schedule_service(container).update(
        schedule_id=schedule_id,
        actor_id=principal.actor_id,
        enabled=True,
    )
    if schedule is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    return ScheduleOut.from_schedule(schedule)


@router.post("/v1/schedules/{schedule_id}/disable", response_model=ScheduleOut)
def disable_schedule(schedule_id: str,
                     container: Container = Depends(get_container),
                     principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.SCHEDULES_MANAGE)
    schedule = _schedule_service(container).update(
        schedule_id=schedule_id,
        actor_id=principal.actor_id,
        enabled=False,
    )
    if schedule is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    return ScheduleOut.from_schedule(schedule)
