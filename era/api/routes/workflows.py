"""Workflow API endpoints (Phase 4C).

Workflow runs are gated like any action (RBAC domain + permission engine) and
their inner steps are dispatched through ``ExecutionService`` (own gates).
Run inputs carry only opaque params (URLs and vault references); responses are
sanitized. Webpage content can never define, modify or start a workflow — a run
only ever executes a registered or strictly-validated definition.
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
from era.core.enums import Decision, Outcome, RiskLevel
from era.core.tool_registry import ActionCatalog
from era.db import transaction
from era.schemas.workflows import (
    WorkflowResolveRequest,
    WorkflowResumeRequest,
    WorkflowRunOut,
    WorkflowRunRequest,
    run_to_out,
)
from era.security.rbac import Permission, role_domain_allowed
from era.services.workflow_service import (
    WorkflowAlreadyTerminal,
    WorkflowNotAllowed,
    WorkflowNotFound,
    WorkflowServiceError,
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


@router.post("/v1/workflows/run", response_model=WorkflowRunOut)
def run_workflow(body: WorkflowRunRequest,
                 container: Container = Depends(get_container),
                 principal=Depends(get_current_principal)):
    auth = container.auth_service
    auth.require_permission(principal.user, Permission.ACTIONS_EXECUTE)
    # Workflow-level RBAC domain gate (outer gate; inner steps are gated too).
    try:
        auth.authorize_action(principal.user, "browser.workflow_run")
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=403,
                            detail="forbidden: role not allowed to run workflows")

    # Workflow-level permission-engine gate. The action is MUTATING by default
    # (CONFIRM), but we only require it to not be DENY here: every mutating
    # inner step still requests its own confirmation through the engine, and a
    # policy that forbids browser.workflow_run stops the run entirely.
    policy = container.policy_service.get_current()
    wf_action = Action(action_type="browser.workflow_run", params={
        "workflow": body.workflow or "inline",
        "params": body.params,
    })
    decision = container.permission_engine.evaluate(wf_action, policy)
    if decision == Decision.DENY:
        raise HTTPException(status_code=403, detail="workflow run denied by policy")

    # Resolve the definition (registered name or inline strict-schema def).
    if body.definition is not None:
        try:
            definition = WorkflowDefinition.model_validate(body.definition)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"invalid workflow definition: {exc}")
    else:
        definition = body.workflow

    ctx = build_ctx(principal)
    try:
        run = container.workflow_service.start(
            definition=definition,
            params=body.params,
            ctx=ctx,
            run_token=body.run_token or "",
            domain_allowed=_domain_guard(container.catalog, principal.user.role),
        )
    except WorkflowNotAllowed as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except WorkflowServiceError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    _audit_start(container, ctx, decision, body)
    _steps = container.workflow_service.get_run(run.id, ctx)[1]
    return run_to_out(run, _steps)


@router.post("/v1/workflows/{run_id}/resume", response_model=WorkflowRunOut)
def resume_workflow(run_id: str, body: WorkflowResumeRequest,
                    container: Container = Depends(get_container),
                    principal=Depends(get_current_principal)):
    del body
    container.auth_service.require_permission(
        principal.user, Permission.ACTIONS_EXECUTE)
    ctx = build_ctx(principal)
    try:
        run = container.workflow_service.resume(
            run_id, ctx,
            domain_allowed=_domain_guard(container.catalog, principal.user.role),
        )
    except WorkflowNotFound:
        raise HTTPException(status_code=404, detail="workflow run not found")
    except WorkflowStateError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except WorkflowAlreadyTerminal as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    _steps = container.workflow_service.get_run(run.id, ctx)[1]
    return run_to_out(run, _steps)


@router.post("/v1/workflows/{run_id}/cancel", response_model=WorkflowRunOut)
def cancel_workflow(run_id: str, container: Container = Depends(get_container),
                    principal=Depends(get_current_principal)):
    container.auth_service.require_permission(
        principal.user, Permission.ACTIONS_EXECUTE)
    ctx = build_ctx(principal)
    try:
        run = container.workflow_service.cancel(run_id, ctx)
    except WorkflowNotFound:
        raise HTTPException(status_code=404, detail="workflow run not found")
    except WorkflowStateError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    _steps = container.workflow_service.get_run(run.id, ctx)[1]
    return run_to_out(run, _steps)


@router.post("/v1/workflows/{run_id}/resolve", response_model=WorkflowRunOut)
def resolve_workflow(run_id: str, body: WorkflowResolveRequest,
                     container: Container = Depends(get_container),
                     principal=Depends(get_current_principal)):
    container.auth_service.require_permission(
        principal.user, Permission.ACTIONS_EXECUTE)
    ctx = build_ctx(principal)
    try:
        run = container.workflow_service.resolve_ambiguous(
            run_id, ctx, body.decision)
    except WorkflowNotFound:
        raise HTTPException(status_code=404, detail="workflow run not found")
    except WorkflowStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    _steps = container.workflow_service.get_run(run.id, ctx)[1]
    return run_to_out(run, _steps)


@router.get("/v1/workflows/{run_id}", response_model=WorkflowRunOut)
def get_workflow(run_id: str, container: Container = Depends(get_container),
                 principal=Depends(get_current_principal)):
    ctx = build_ctx(principal)
    try:
        run, steps = container.workflow_service.get_run(run_id, ctx)
    except WorkflowNotFound:
        raise HTTPException(status_code=404, detail="workflow run not found")
    except WorkflowStateError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return run_to_out(run, steps)


@router.get("/v1/workflows", response_model=list[WorkflowRunOut])
def list_workflows(container: Container = Depends(get_container),
                   principal=Depends(get_current_principal)):
    container.auth_service.require_permission(
        principal.user, Permission.ACTIONS_EXECUTE)
    ctx = build_ctx(principal)
    runs = container.workflow_service.list_runs(ctx)
    return [
        run_to_out(run, container.workflow_service.get_run(run.id, ctx)[1])
        for run in runs
    ]


def _audit_start(container: Container, ctx, decision: Decision, body) -> None:
    """Record a workflow-level audit marker (inner steps are audited too)."""
    policy = container.policy_service.get_current()
    with transaction(container.session_factory) as session:
        container.audit_service.record(
            session,
            action=Action(action_type="browser.workflow_run", params={
                "workflow": body.workflow or "inline",
                "params": body.params,
            }),
            ctx=ctx,
            risk_level=RiskLevel.MUTATING,
            decision=decision,
            outcome=Outcome.AUTHORIZED,
            policy_version=policy.version if policy else 0,
            provider_id=None,
            capability_domain="browser",
        )
