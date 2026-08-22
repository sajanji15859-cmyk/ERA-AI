"""Phase 4D workflow operations & governance API routes.

Scheduling, templates, operator review and observability are exposed as
authenticated, actor-scoped read endpoints plus admin-only review endpoints.
Every route reuses the same service layer and fail-closed RBAC as the rest of
the API.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException

from era.api.deps import (
    build_ctx,
    get_container,
    get_current_principal,
)
from era.container import Container
from era.core.action import Action
from era.core.enums import RiskLevel
from era.core.tool_registry import ActionCatalog
from era.schemas.workflow_ops import (
    WorkflowAggregationOut,
    WorkflowOperatorApproveRequest,
    WorkflowOperatorCancelRequest,
    WorkflowOperatorResolveRequest,
    WorkflowScheduleCreate,
    WorkflowScheduleListOut,
    WorkflowScheduleOut,
    WorkflowScheduleUpdate,
    WorkflowTemplateInstantiateOut,
    WorkflowTemplateInstantiateRequest,
    WorkflowTemplateOut,
    WorkflowTemplatePublishRequest,
    WorkflowTimelineEventOut,
)
from era.schemas.workflows import WorkflowRunOut, run_to_out
from era.security.rbac import Permission, role_domain_allowed
from era.services.workflow_ops_service import (
    WorkflowScheduleError,
    WorkflowTemplateError,
)
from era.services.workflow_service import (
    WorkflowAlreadyTerminal,
    WorkflowNotFound,
    WorkflowStateError,
)
from era.workflows.definition import WorkflowDefinition

router = APIRouter()


def _domain_guard(catalog: ActionCatalog, role: str) -> Callable[[str], bool]:
    def guard(action_type: str) -> bool:
        spec = catalog.get(action_type)
        if spec is None or spec.risk_level is RiskLevel.FORBIDDEN:
            return False
        return role_domain_allowed(role, spec.capability_domain)
    return guard


@router.post("/v1/workflow-schedules", response_model=WorkflowScheduleOut,
             status_code=201)
def create_workflow_schedule(
    body: WorkflowScheduleCreate,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(principal.user, Permission.WORKFLOW_SCHEDULE)
    try:
        row = container.workflow_schedule_service.create(
            actor_id=principal.actor_id,
            actor_role=principal.user.role,
            name=body.name,
            workflow_name=body.workflow,
            params=body.params,
            cron_expr=body.cron_expr,
            interval_seconds=body.interval_seconds,
            enabled=body.enabled,
            workflow_version=body.workflow_version,
            domain_allowed=_domain_guard(container.catalog, principal.user.role),
        )
    except WorkflowScheduleError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return WorkflowScheduleOut.from_schedule(row)


@router.get("/v1/workflow-schedules", response_model=WorkflowScheduleListOut)
def list_workflow_schedules(
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(principal.user, Permission.WORKFLOW_SCHEDULE)
    rows = container.workflow_schedule_service.list(principal.actor_id)
    return WorkflowScheduleListOut(
        schedules=[WorkflowScheduleOut.from_schedule(r) for r in rows])


@router.get("/v1/workflow-schedules/{schedule_id}", response_model=WorkflowScheduleOut)
def get_workflow_schedule(
    schedule_id: str,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(principal.user, Permission.WORKFLOW_SCHEDULE)
    row = container.workflow_schedule_service.get(schedule_id, principal.actor_id)
    if row is None:
        raise HTTPException(status_code=404, detail="workflow schedule not found")
    return WorkflowScheduleOut.from_schedule(row)


@router.patch("/v1/workflow-schedules/{schedule_id}", response_model=WorkflowScheduleOut)
def update_workflow_schedule(
    schedule_id: str,
    body: WorkflowScheduleUpdate,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(principal.user, Permission.WORKFLOW_SCHEDULE)
    try:
        row = container.workflow_schedule_service.update(
            schedule_id, principal.actor_id,
            name=body.name, params=body.params, cron_expr=body.cron_expr,
            interval_seconds=body.interval_seconds,
            workflow_version=body.workflow_version, enabled=body.enabled,
        )
    except WorkflowScheduleError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if row is None:
        raise HTTPException(status_code=404, detail="workflow schedule not found")
    return WorkflowScheduleOut.from_schedule(row)


@router.delete("/v1/workflow-schedules/{schedule_id}")
def delete_workflow_schedule(
    schedule_id: str,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(principal.user, Permission.WORKFLOW_SCHEDULE)
    deleted = container.workflow_schedule_service.delete(schedule_id, principal.actor_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="workflow schedule not found")
    return {"deleted": True, "schedule_id": schedule_id}


# -- templates ---------------------------------------------------------------
@router.post("/v1/workflow-templates", response_model=WorkflowTemplateOut, status_code=201)
def publish_workflow_template(
    body: WorkflowTemplatePublishRequest,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(
        principal.user, Permission.WORKFLOW_TEMPLATES_MANAGE)
    try:
        definition = WorkflowDefinition.model_validate(body.definition)
        template = container.workflow_template_service.publish(
            definition, created_by=principal.actor_id)
    except WorkflowTemplateError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - validation error
        raise HTTPException(status_code=422, detail=f"invalid template: {exc}")
    return _template_out(template)


@router.get("/v1/workflow-templates", response_model=list[WorkflowTemplateOut])
def list_workflow_templates(
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(principal.user, Permission.WORKFLOW_READ)
    return [_template_out(t) for t in container.workflow_template_service.list()]


@router.post("/v1/workflow-templates/instantiate",
             response_model=WorkflowTemplateInstantiateOut)
def instantiate_workflow_template(
    body: WorkflowTemplateInstantiateRequest,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(
        principal.user, Permission.WORKFLOW_TEMPLATES_MANAGE)
    try:
        definition = container.workflow_template_service.instantiate(
            body.name, body.params, version=body.version)
    except WorkflowTemplateError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return WorkflowTemplateInstantiateOut(
        name=definition.name,
        version=definition.version,
        checksum=container.workflow_catalog.checksum(definition),
        prepared=True,
        step_ids=[s.id for s in definition.steps],
        params_schema=dict(definition.params_schema or {}),
    )


# -- operator review / observability ------------------------------------------
@router.get("/v1/workflows/awaiting", response_model=list[WorkflowRunOut])
def list_awaiting_workflows(
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(principal.user, Permission.WORKFLOW_REVIEW)
    runs = container.workflow_service.list_awaiting_runs()
    return [
        run_to_out(r, container.workflow_service.get_run(r.id, _admin_ctx(r))[1])
        for r in runs
    ]


@router.get("/v1/workflows/summary", response_model=dict)
def list_workflow_runs(
    status: str | None = None,
    workflow: str | None = None,
    limit: int = 50,
    offset: int = 0,
    start_at: str | None = None,
    end_at: str | None = None,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(principal.user, Permission.WORKFLOW_READ)
    ctx = build_ctx(principal)
    admin = principal.user.role == "admin"
    limit = min(max(int(limit), 1), 200)
    offset = max(int(offset), 0)
    runs = container.workflow_service.list_runs_filtered(
        ctx=ctx, status=status, workflow_name=workflow,
        limit=limit, offset=offset, admin=admin)
    return {
        "items": [run_to_out(r, container.workflow_service.get_run(r.id, ctx)[1])
                  for r in runs],
        "limit": limit,
        "offset": offset,
    }


@router.get("/v1/workflows/aggregate", response_model=WorkflowAggregationOut)
def aggregate_workflow_runs(
    workflow: str | None = None,
    start_at: str | None = None,
    end_at: str | None = None,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(principal.user, Permission.WORKFLOW_READ)
    ctx = build_ctx(principal)
    admin = principal.user.role == "admin"
    data = container.workflow_service.aggregate_runs(
        ctx=ctx, workflow_name=workflow, start_at=start_at,
        end_at=end_at, admin=admin)
    return WorkflowAggregationOut(**data)


@router.get("/v1/workflows/{run_id}/timeline",
            response_model=list[WorkflowTimelineEventOut])
def workflow_timeline(
    run_id: str,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    try:
        if principal.user.role == "admin":
            events = container.workflow_service.run_timeline(
                run_id, build_ctx(principal), admin=True)
        else:
            container.auth_service.require_permission(
                principal.user, Permission.WORKFLOW_READ)
            events = container.workflow_service.run_timeline(
                run_id, build_ctx(principal))
    except WorkflowNotFound:
        raise HTTPException(status_code=404, detail="workflow run not found")
    except WorkflowStateError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return [WorkflowTimelineEventOut(**e) for e in events]


@router.post("/v1/admin/workflows/{run_id}/resolve", response_model=WorkflowRunOut)
def admin_resolve_workflow(
    run_id: str,
    body: WorkflowOperatorResolveRequest,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(
        principal.user, Permission.WORKFLOW_REVIEW)
    try:
        run = container.workflow_service.admin_resolve_ambiguous(
            run_id, build_ctx(principal), body.decision, body.reason)
    except WorkflowNotFound:
        raise HTTPException(status_code=404, detail="workflow run not found")
    except (WorkflowStateError, WorkflowAlreadyTerminal) as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return run_to_out(run, container.workflow_service.get_run(run.id, _admin_ctx(run))[1])


@router.post("/v1/admin/workflows/{run_id}/cancel", response_model=WorkflowRunOut)
def admin_cancel_workflow(
    run_id: str,
    body: WorkflowOperatorCancelRequest,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(
        principal.user, Permission.WORKFLOW_REVIEW)
    try:
        run = container.workflow_service.admin_cancel(
            run_id, build_ctx(principal), body.reason)
    except WorkflowNotFound:
        raise HTTPException(status_code=404, detail="workflow run not found")
    except WorkflowStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return run_to_out(run, container.workflow_service.get_run(run.id, _admin_ctx(run))[1])


@router.post("/v1/admin/confirmations/{confirmation_id}/approve")
def admin_approve_confirmation(
    confirmation_id: str,
    body: WorkflowOperatorApproveRequest,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
):
    container.auth_service.require_permission(
        principal.user, Permission.WORKFLOW_REVIEW)
    if body.confirmation_id != confirmation_id:
        raise HTTPException(status_code=422,
                            detail="confirmation_id mismatch")
    action = Action(action_type=body.action_type, params=body.action_params)
    try:
        resp = container.workflow_service.admin_approve(
            confirmation_id, build_ctx(principal), action, body.reason)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=409, detail=str(exc))
    return resp.model_dump(mode="json")


def _template_out(template) -> WorkflowTemplateOut:
    return WorkflowTemplateOut(
        name=template.name,
        version=template.version,
        params_schema=dict(template.params_schema or {}),
        checksum=template.checksum,
        status=template.status,
        created_by=template.created_by,
        created_at=template.created_at,
        published_at=template.published_at,
    )


def _admin_ctx(run):
    from era.core.context import ExecutionContext
    return ExecutionContext(actor_id=run.actor_id, execution_scope=run.execution_scope)
