"""FastAPI application factory.

With ``ERA_AGENT_ENABLED=true`` the app builds the agent runtime container
(real Workspace/Web providers + AgentService) and mounts the agent routes;
otherwise the Phase 1C–2A container and routes are exactly as before.
"""

from __future__ import annotations

from fastapi import FastAPI

from era.api.middleware import BodySizeLimitMiddleware
from era.api.routes import actions, admin, audit, confirmations, policy, providers
from era.config import Settings
from era.container import build_container


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    if settings.agent_enabled:
        from era.agent_runtime import build_agent_container
        container = build_agent_container(settings)
        title = "ERA AI — Agent (Phase 3A)"
    else:
        container = build_container(settings)
        title = "ERA AI — Phase 2A"

    app = FastAPI(title=title, version=settings.app_version)
    app.state.container = container

    # Input hardening: reject oversized request bodies before any handler.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)

    app.include_router(actions.router)
    app.include_router(confirmations.router)
    app.include_router(audit.router)
    app.include_router(policy.router)
    app.include_router(providers.router)
    app.include_router(admin.router)
    if settings.agent_enabled:
        from era.api.routes import agent
        app.include_router(agent.router)

    return app


# Run with:  uvicorn era.main:create_app --factory
