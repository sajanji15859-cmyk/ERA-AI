"""FastAPI application factory.

With ``ERA_AGENT_ENABLED=true`` the app builds the agent runtime container
(real Workspace/Web/Browser providers + AgentService) and mounts agent routes;
otherwise the Phase 1C–2A container and routes are exactly as before.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from era.api.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from era.api.rate_limit import RateLimitMiddleware
from era.api.routes import (
    actions,
    admin,
    audit,
    confirmations,
    health,
    jobs,
    operator,
    policy,
    providers,
    schedules,
    ui,
    vault,
    workflow_ops,
    workflows,
)
from era.config import Settings
from era.container import build_container

_WEB_STATIC = Path(__file__).resolve().parent / "web" / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    if settings.agent_enabled:
        from era.agent_runtime import build_agent_container
        container = build_agent_container(settings)
        title = "ERA AI — Agent (Phase 5A)"
    else:
        container = build_container(settings)
        title = "ERA AI — Phase 5A"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        # Phase 4E: release scheduler leadership on graceful shutdown.
        if container.scheduler_leader_service is not None:
            try:
                container.scheduler_leader_service.release()
            except Exception:  # noqa: BLE001, S110 — best effort on shutdown
                pass
        # Phase 3G & 3H: stop background workers on clean shutdown.
        if container.job_service is not None:
            container.job_service.shutdown()
        if container.schedule_service is not None:
            container.schedule_service.shutdown()
        # Phase 4A: stop Chromium and discard every ephemeral browser context.
        for provider in container.registry.list_providers():
            close = getattr(provider, "close", None)
            if callable(close):
                close()

    app = FastAPI(title=title, version=settings.app_version, lifespan=lifespan)
    app.state.container = container

    # Input hardening: reject oversized request bodies before any handler.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    # Phase 3F: authenticated calls consume both per-key and per-IP buckets;
    # unauthenticated calls are constrained by source IP.
    app.add_middleware(
        RateLimitMiddleware,
        enabled=settings.rate_limit_enabled,
        key_limit=settings.rate_limit_requests,
        ip_limit=settings.rate_limit_ip_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )
    # Response hardening (Phase 3E): CSP + clickjacking/MIME-sniffing defenses
    # on every response, including the static dashboard and SSE streams.
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(health.router)
    app.include_router(actions.router)
    app.include_router(confirmations.router)
    app.include_router(audit.router)
    app.include_router(policy.router)
    app.include_router(providers.router)
    app.include_router(admin.router)
    app.include_router(vault.router)
    app.include_router(jobs.router)
    app.include_router(schedules.router)
    app.include_router(workflow_ops.router)
    app.include_router(workflows.router)
    app.include_router(operator.router)
    if settings.agent_enabled:
        from era.api.routes import agent
        app.include_router(agent.router)

    # Phase 3E: web chat dashboard (served last so it never shadows API routes).
    app.include_router(ui.router)
    if _WEB_STATIC.is_dir():
        app.mount("/static", StaticFiles(directory=str(_WEB_STATIC)), name="static")

    return app


# Run with:  uvicorn era.main:create_app --factory
