"""Confirmation resolution endpoints (Phase 2A protected + actor-bound)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from era.api.deps import (
    build_ctx,
    get_container,
    get_current_principal,
)
from era.container import Container
from era.core.action import Action
from era.core.enums import Decision, RiskLevel
from era.db import transaction
from era.schemas.actions import ExecutionResponse
from era.schemas.confirmation import ApproveRequest, ConfirmationStatus
from era.security.rbac import Permission

router = APIRouter()


@router.get("/v1/confirmations/{confirmation_id}", response_model=ConfirmationStatus)
def get_confirmation(confirmation_id: str, container: Container = Depends(get_container),
                     principal=Depends(get_current_principal)):
    """Return confirmation status. Access is limited to the initiating actor
    (or an admin), so confirmation ids cannot be enumerated by other users."""
    with transaction(container.session_factory) as session:
        conf = container.confirmation_service.get(session, confirmation_id)
    if conf is None:
        raise HTTPException(status_code=404, detail="confirmation not found")
    if conf.actor_id is not None and conf.actor_id != principal.actor_id \
            and not container.auth_service.is_admin(principal.user):
        raise HTTPException(status_code=403, detail="forbidden")
    return ConfirmationStatus(
        id=conf.id,
        action_type=conf.action_type,
        decision=Decision(conf.decision),
        risk_level=RiskLevel(conf.risk_level),
        status=conf.status,
        expires_at=conf.expires_at,
        challenge_required=conf.decision == Decision.CONFIRM_STRONG.value,
        action_params=conf.action_params_redacted,
    )


@router.post("/v1/confirmations/{confirmation_id}/approve", response_model=ExecutionResponse)
def approve(confirmation_id: str, body: ApproveRequest,
            container: Container = Depends(get_container),
            principal=Depends(get_current_principal)):
    auth = container.auth_service
    auth.require_permission(principal.user, Permission.ACTIONS_CONFIRM)
    action = Action(action_type=body.action_type, params=body.params)
    return container.execution_service.approve(
        confirmation_id, action, build_ctx(principal), body.challenge,
    )


@router.post("/v1/confirmations/{confirmation_id}/deny", response_model=ExecutionResponse)
def deny(confirmation_id: str, container: Container = Depends(get_container),
         principal=Depends(get_current_principal)):
    auth = container.auth_service
    auth.require_permission(principal.user, Permission.ACTIONS_CONFIRM)
    return container.execution_service.deny(confirmation_id, build_ctx(principal))
