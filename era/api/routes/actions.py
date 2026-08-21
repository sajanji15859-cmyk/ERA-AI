"""Action evaluation and execution endpoints (Phase 2A protected)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from era.api.deps import (
    build_ctx,
    get_container,
    get_current_principal,
    require_permission,
)
from era.container import Container
from era.core.action import Action
from era.schemas.actions import (
    ActionRequest,
    EvaluateRequest,
    EvaluateResponse,
    ExecutionResponse,
)
from era.security.exceptions import AuthorizationError
from era.security.rbac import Permission

router = APIRouter()


@router.post("/v1/actions/evaluate", response_model=EvaluateResponse)
def evaluate(body: EvaluateRequest, container: Container = Depends(get_container),
             user=Depends(require_permission(Permission.ACTIONS_EVALUATE))):
    """Dry-run: return the Decision with no side effects and no audit entry."""
    action = Action(action_type=body.action_type, params=body.params)
    policy = container.policy_service.get_current()
    decision = container.permission_engine.evaluate(action, policy)
    spec = container.catalog.get(body.action_type)
    risk_level = spec.risk_level if spec else None
    if spec is None:
        reason = "unknown action type"
    elif policy is None:
        reason = "missing/malformed policy"
    else:
        reason = "evaluated"
    return EvaluateResponse(
        action_type=body.action_type, decision=decision,
        risk_level=risk_level, reason=reason,
    )


@router.post("/v1/actions/execute", response_model=ExecutionResponse)
def execute(body: ActionRequest, container: Container = Depends(get_container),
            principal=Depends(get_current_principal)):
    """Execute an action: authenticate -> RBAC authorize -> execution gate.

    Identity is derived server-side from the principal (never from the body).
    RBAC domain authorization is an outer gate; the permission engine +
    confirmation + execution gate still apply independently.
    """
    auth = container.auth_service
    auth.require_permission(principal.user, Permission.ACTIONS_EXECUTE)
    try:
        auth.authorize_action(principal.user, body.action_type)
    except AuthorizationError:
        raise HTTPException(status_code=403,
                            detail="forbidden: role not allowed for action")

    action = Action(action_type=body.action_type, params=body.params)
    return container.execution_service.request(action, build_ctx(principal))
