"""Phase 4E — operator review / dual-approval endpoints.

* ``GET /v1/operator/pending-confirmations`` — list pending CONFIRM_STRONG
  confirmations (admin only).
* ``POST /v1/operator/confirmations/{id}/approve`` — grant an approval
  (admin or the original actor for primary approval).
* ``POST /v1/operator/confirmations/{id}/deny`` — deny an approval.
* ``GET /v1/operator/confirmations/{id}/approvals`` — list approvals for a
  confirmation.

All endpoints require the ``operator.review`` RBAC permission (admin role).
The operator UI uses these to show a "Pending Approvals" panel and allow
admins to grant secondary approvals on FINANCIAL / BOOKING actions.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from era.api.deps import get_container, get_current_principal, require_permission
from era.container import Container
from era.db import transaction
from era.models.confirmation import STATUS_PENDING
from era.models.confirmation_approval import APPROVAL_DENIED, APPROVAL_GRANTED
from era.security.rbac import Permission
from era.services.dual_approval import (
    ApprovalAlreadyExists,
    ConfirmationNotPending,
    DualApprovalError,
)

router = APIRouter()


class ApprovalRequest(BaseModel):
    """Optional IP/UA context for non-repudiation tracking."""
    ip: str | None = None
    user_agent: str | None = None


class ApprovalRecord(BaseModel):
    id: str
    actor_id: str
    status: str
    sequence: int
    context_hash: str | None
    created_at: str


class ApprovalListResponse(BaseModel):
    confirmation_id: str
    required_approvals: int
    approvals: list[ApprovalRecord]
    dispatchable: bool
    denied: bool


@router.get("/v1/operator/pending-confirmations")
def list_pending_confirmations(
    container: Container = Depends(get_container),
    user=Depends(require_permission(Permission.OPERATOR_REVIEW)),
):
    """List all PENDING confirmations requiring operator attention (admin)."""
    with transaction(container.session_factory) as session:
        from sqlalchemy import select

        from era.models.confirmation import PendingConfirmation
        stmt = (
            select(PendingConfirmation)
            .where(PendingConfirmation.status == STATUS_PENDING)
            .order_by(PendingConfirmation.created_at.desc())
            .limit(100)
        )
        confirmations = session.execute(stmt).scalars().all()

    results = []
    for conf in confirmations:
        from era.core.enums import Decision
        results.append({
            "id": conf.id,
            "action_type": conf.action_type,
            "risk_level": conf.risk_level,
            "decision": conf.decision,
            "actor_id": conf.actor_id,
            "created_at": conf.created_at,
            "expires_at": conf.expires_at,
            "challenge_required": conf.decision == Decision.CONFIRM_STRONG.value,
            "params_redacted": conf.action_params_redacted,
        })
    return {"confirmations": results}


@router.get("/v1/operator/confirmations/{confirmation_id}/approvals",
            response_model=ApprovalListResponse)
def get_approvals(
    confirmation_id: str,
    container: Container = Depends(get_container),
    user=Depends(require_permission(Permission.OPERATOR_REVIEW)),
):
    """List all approvals for a confirmation (admin)."""
    with transaction(container.session_factory) as session:
        conf = container.confirmation_service.get(session, confirmation_id)
    if conf is None:
        raise HTTPException(status_code=404, detail="confirmation not found")

    approvals = container.dual_approval_service.get_approvals(confirmation_id)
    return ApprovalListResponse(
        confirmation_id=confirmation_id,
        required_approvals=container.dual_approval_service.required_approvals(
            conf.risk_level),
        approvals=[
            ApprovalRecord(
                id=a.id,
                actor_id=a.actor_id,
                status=a.status,
                sequence=a.sequence,
                context_hash=a.context_hash,
                created_at=a.created_at,
            )
            for a in approvals
        ],
        dispatchable=container.dual_approval_service.is_dispatchable(conf),
        denied=container.dual_approval_service.is_denied(conf),
    )


@router.post("/v1/operator/confirmations/{confirmation_id}/approve")
def approve(
    confirmation_id: str,
    body: ApprovalRequest | None = None,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
    user=Depends(require_permission(Permission.OPERATOR_REVIEW)),
):
    """Grant an approval for a confirmation (admin operator action)."""
    context_hash = None
    if body:
        context_hash = container.dual_approval_service.build_context_hash(
            ip=body.ip, user_agent=body.user_agent)

    try:
        approval = container.dual_approval_service.record_approval(
            confirmation_id=confirmation_id,
            actor_id=principal.actor_id,
            status=APPROVAL_GRANTED,
            context_hash=context_hash,
        )
    except ApprovalAlreadyExists as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ConfirmationNotPending as e:
        raise HTTPException(status_code=409, detail=str(e))
    except DualApprovalError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "id": approval.id,
        "confirmation_id": approval.confirmation_id,
        "actor_id": approval.actor_id,
        "status": approval.status,
        "sequence": approval.sequence,
        "created_at": approval.created_at,
    }


@router.post("/v1/operator/confirmations/{confirmation_id}/deny")
def deny(
    confirmation_id: str,
    body: ApprovalRequest | None = None,
    container: Container = Depends(get_container),
    principal=Depends(get_current_principal),
    user=Depends(require_permission(Permission.OPERATOR_REVIEW)),
):
    """Deny an approval for a confirmation (admin operator action)."""
    context_hash = None
    if body:
        context_hash = container.dual_approval_service.build_context_hash(
            ip=body.ip, user_agent=body.user_agent)

    try:
        approval = container.dual_approval_service.record_approval(
            confirmation_id=confirmation_id,
            actor_id=principal.actor_id,
            status=APPROVAL_DENIED,
            context_hash=context_hash,
        )
    except ApprovalAlreadyExists as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ConfirmationNotPending as e:
        raise HTTPException(status_code=409, detail=str(e))
    except DualApprovalError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "id": approval.id,
        "confirmation_id": approval.confirmation_id,
        "actor_id": approval.actor_id,
        "status": approval.status,
        "sequence": approval.sequence,
        "created_at": approval.created_at,
    }
