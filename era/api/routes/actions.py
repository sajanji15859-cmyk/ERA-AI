"""Action evaluation and execution endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from era.api.deps import get_container
from era.container import Container
from era.core.action import Action
from era.core.context import ExecutionContext
from era.schemas.actions import (
    ActionRequest,
    EvaluateRequest,
    EvaluateResponse,
    ExecutionResponse,
)

router = APIRouter()


def _ctx(req) -> ExecutionContext:
    return ExecutionContext(
        actor_id=req.actor_id,
        session_id=req.session_id,
        credentials={"refs": req.credential_refs},
    )


@router.post("/v1/actions/evaluate", response_model=EvaluateResponse)
def evaluate(body: EvaluateRequest, container: Container = Depends(get_container)):
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
def execute(body: ActionRequest, container: Container = Depends(get_container)):
    action = Action(action_type=body.action_type, params=body.params)
    return container.execution_service.request(action, _ctx(body))
