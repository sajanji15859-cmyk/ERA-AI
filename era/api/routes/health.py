"""Phase 4E — health check endpoint.

``GET /v1/health`` returns a bounded, non-secret health report:

* **database** — can the DB session be opened?
* **scheduler_leader** — who is the current scheduler leader and is it stale?
* **circuit_breakers** — aggregate state of all registered provider circuits.
* **app_version** — the running ERA version.

The endpoint is public (no auth required) so load balancers and monitoring
can probe it. It exposes no credentials, audit entries, policy or user data.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from era.api.deps import get_container
from era.container import Container

router = APIRouter()


class HealthResponse(BaseModel):
    status: str  # "healthy" | "degraded" | "unhealthy"
    app_version: str
    database: str  # "ok" | "error"
    scheduler_leader: dict
    circuit_breakers: dict


@router.get("/v1/health", response_model=HealthResponse)
def health(container: Container = Depends(get_container)):
    """Public health check (no auth)."""
    # Database connectivity.
    db_status = "ok"
    try:
        from era.db import transaction
        with transaction(container.session_factory) as session:
            session.execute(
                __import__("sqlalchemy").text("SELECT 1"))
    except Exception:  # noqa: BLE001
        db_status = "error"

    # Scheduler leader info.
    leader_info = container.scheduler_leader_service.get_leader_info()

    # Circuit breaker aggregate.
    breaker_states: dict[str, str] = {}
    try:
        for pid in container.registry.provider_ids:
            breaker = container.execution_service.circuit_breakers.get(pid)
            breaker_states[pid] = breaker.state.value if hasattr(breaker.state, "value") else str(breaker.state)
    except Exception:  # noqa: BLE001, S110
        pass

    # Overall health status.
    overall = "healthy"
    if db_status == "error":
        overall = "unhealthy"
    elif any(v == "OPEN" for v in breaker_states.values()):
        overall = "degraded"

    return HealthResponse(
        status=overall,
        app_version=container.settings.app_version,
        database=db_status,
        scheduler_leader=leader_info,
        circuit_breakers=breaker_states,
    )
