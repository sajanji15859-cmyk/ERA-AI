"""Confirmation resolution endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from era.api.deps import get_container
from era.container import Container
from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import Decision, RiskLevel
from era.db import transaction
from era.schemas.actions import ExecutionResponse
from era.schemas.confirmation import ApproveRequest, ConfirmationStatus

router = APIRouter()


@router.get("/v1/confirmations/{confirmation_id}", response_model=ConfirmationStatus)
def get_confirmation(confirmation_id: str, container: Container = Depends(get_container)):
    with transaction(container.session_factory) as session:
        conf = container.confirmation_service.get(session, confirmation_id)
    if conf is None:
        raise HTTPException(status_code=404, detail="confirmation not found")
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
            container: Container = Depends(get_container)):
    action = Action(action_type=body.action_type, params=body.params)
    ctx = ExecutionContext(
        actor_id=body.actor_id, session_id=body.session_id,
        credentials={"refs": body.credential_refs},
    )
    return container.execution_service.approve(confirmation_id, action, ctx, body.challenge)


@router.post("/v1/confirmations/{confirmation_id}/deny", response_model=ExecutionResponse)
def deny(confirmation_id: str, container: Container = Depends(get_container)):
    ctx = ExecutionContext(actor_id="api")
    return container.execution_service.deny(confirmation_id, ctx)
