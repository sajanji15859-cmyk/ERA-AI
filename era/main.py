"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI

from era.api.routes import actions, audit, confirmations, policy, providers
from era.config import Settings
from era.container import build_container


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="ERA AI — Phase 1E", version=settings.app_version)
    app.state.container = build_container(settings)

    app.include_router(actions.router)
    app.include_router(confirmations.router)
    app.include_router(audit.router)
    app.include_router(policy.router)
    app.include_router(providers.router)

    return app


# Run with:  uvicorn era.main:create_app --factory
