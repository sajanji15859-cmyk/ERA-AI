"""FastAPI application factory.

With ``ERA_AGENT_ENABLED=true`` the app builds the agent runtime container
(real Workspace/Web providers + AgentService) and mounts the agent routes;
otherwise the Phase 1C–2A container and routes are exactly as before.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from era.api.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from era.api.routes import actions, admin, audit, confirmations, policy, providers, ui, vault
from era.config import Settings
from era.container import build_container

_WEB_STATIC = Path(__file__).resolve().parent / "web" / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    if settings.agent_enabled:
        from era.agent_runtime import build_agent_container
        container = build_agent_container(settings)
        title = "ERA AI — Agent (Phase 3A/3B/3C/3D/3E)"
    else:
        container = build_container(settings)
        title = "ERA AI — Phase 2A/3C"

    app = FastAPI(title=title, version=settings.app_version)
    app.state.container = container

    # Input hardening: reject oversized request bodies before any handler.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    # Response hardening (Phase 3E): CSP + clickjacking/MIME-sniffing defenses
    # on every response, including the static dashboard and SSE streams.
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(actions.router)
    app.include_router(confirmations.router)
    app.include_router(audit.router)
    app.include_router(policy.router)
    app.include_router(providers.router)
    app.include_router(admin.router)
    app.include_router(vault.router)
    if settings.agent_enabled:
        from era.api.routes import agent
        app.include_router(agent.router)

    # Phase 3E: web chat dashboard (served last so it never shadows API routes).
    app.include_router(ui.router)
    if _WEB_STATIC.is_dir():
        app.mount("/static", StaticFiles(directory=str(_WEB_STATIC)), name="static")

    return app


# Run with:  uvicorn era.main:create_app --factory
