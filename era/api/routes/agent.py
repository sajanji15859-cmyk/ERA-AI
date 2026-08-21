"""Agent run + chat endpoints (Phase 3A/3B, authenticated + permission-gated).

* ``POST /v1/agent/runs`` — start a run for a goal. Executes synchronously
  until completion, budget exhaustion, or the first human-approval gate
  (status ``waiting_for_user`` with pending confirmation ids).
* ``GET /v1/agent/runs`` / ``GET /v1/agent/runs/{id}`` — inspect runs
  (owner or admin only).
* ``POST /v1/agent/runs/{id}/continue`` — after the operator has
  approved/denied pending confirmations through the existing
  ``/v1/confirmations/{id}`` endpoints, continue the loop. Resolutions are
  derived from the append-only audit log.
* ``POST /v1/agent/chat`` — SSE chat (Phase 3B): start a run or continue a
  paused one, streaming typed events (``text/event-stream``).
* ``GET /v1/agent/runs/{id}/events`` — replay a run's event history
  (in-memory, bounded).

All routes require the ``agent.run`` permission and the agent runtime enabled
(``ERA_AGENT_ENABLED=true``), otherwise 503.
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from era.agents.events import AgentEvent
from era.api.deps import build_ctx, get_container, get_current_principal
from era.container import Container
from era.schemas.agent import (
    AgentEventListOut,
    AgentEventOut,
    AgentRunListOut,
    AgentRunOut,
    AgentRunRequest,
    ChatRequest,
)
from era.security.rbac import Permission

router = APIRouter()


def _agent_service(container: Container):
    if container.agent_service is None:
        raise HTTPException(status_code=503,
                            detail="agent runtime not enabled (set ERA_AGENT_ENABLED=true)")
    return container.agent_service


def _require_owner(container: Container, run_id: str, principal) -> object:
    record = _agent_service(container).get_run(run_id, principal.actor_id)
    if record is None:
        raise HTTPException(status_code=404, detail="agent run not found")
    return record


def _sse(events: Iterator[AgentEvent]) -> Iterator[str]:
    """Format agent events as an SSE body."""
    for ev in events:
        yield f"data: {ev.model_dump_json()}\n\n"


@router.post("/v1/agent/runs", response_model=AgentRunOut)
def start_run(body: AgentRunRequest, container: Container = Depends(get_container),
              principal=Depends(get_current_principal)):
    auth = container.auth_service
    auth.require_permission(principal.user, Permission.AGENT_RUN)
    try:
        record = _agent_service(container).start_run(
            body.goal, build_ctx(principal), role=principal.user.role)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return AgentRunOut.from_record(record)


@router.get("/v1/agent/runs", response_model=AgentRunListOut)
def list_runs(container: Container = Depends(get_container),
              principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.AGENT_RUN)
    records = _agent_service(container).list_runs(principal.actor_id)
    return AgentRunListOut(runs=[AgentRunOut.from_record(r) for r in records])


@router.get("/v1/agent/runs/{run_id}", response_model=AgentRunOut)
def get_run(run_id: str, container: Container = Depends(get_container),
            principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.AGENT_RUN)
    record = _require_owner(container, run_id, principal)
    return AgentRunOut.from_record(record)


@router.post("/v1/agent/runs/{run_id}/continue", response_model=AgentRunOut)
def continue_run(run_id: str, container: Container = Depends(get_container),
                 principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.AGENT_RUN)
    service = _agent_service(container)
    record = service.continue_run(run_id, build_ctx(principal), role=principal.user.role)
    if record is None:
        raise HTTPException(status_code=404, detail="agent run not found")
    return AgentRunOut.from_record(record)


@router.get("/v1/agent/runs/{run_id}/events", response_model=AgentEventListOut)
def get_run_events(run_id: str, container: Container = Depends(get_container),
                   principal=Depends(get_current_principal)):
    container.auth_service.require_permission(principal.user, Permission.AGENT_RUN)
    service = _agent_service(container)
    events = service.get_events(run_id, principal.actor_id)
    if events is None:
        raise HTTPException(status_code=404, detail="agent run not found")
    return AgentEventListOut(events=[AgentEventOut(**ev.model_dump()) for ev in events])


@router.post("/v1/agent/chat")
def chat(body: ChatRequest, container: Container = Depends(get_container),
         principal=Depends(get_current_principal)):
    """SSE chat: start a new run, or continue a paused run via ``run_id``."""
    auth = container.auth_service
    auth.require_permission(principal.user, Permission.AGENT_RUN)
    service = _agent_service(container)
    ctx = build_ctx(principal)
    role = principal.user.role

    if body.run_id is None:
        try:
            events = service.start_run_stream(body.message, ctx, role=role)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    else:
        # Ownership is checked inside continue_run_stream; surface 404 eagerly
        # when the run belongs to someone else (or does not exist).
        record = service.get_run(body.run_id, principal.actor_id)
        if record is None:
            raise HTTPException(status_code=404, detail="agent run not found")
        events = service.continue_run_stream(body.run_id, ctx, role=role)

    return StreamingResponse(_sse(events), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})
