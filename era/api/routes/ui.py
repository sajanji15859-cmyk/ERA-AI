"""Web UI serving + identity introspection endpoints (Phase 3E).

* ``GET /`` — serves the single-page chat dashboard (the login screen first;
  the app authenticates the same way as the API: ``Authorization: Bearer
  <api-key>``).
* ``GET /v1/me`` — authenticated identity check for the UI login screen: who
  does the presented key belong to, and is the agent runtime enabled.

The dashboard is static (no build step) and talks only to the same-origin API,
so the Phase 2A auth model applies unchanged — no CORS, no secret leakage, and
every action still goes through the authenticated + permission-gated API.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse

from era.api.deps import get_container, get_current_principal
from era.container import Container
from era.schemas.auth import MeOut

router = APIRouter()

_STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "web" / "static"

_INDEX_HEADERS = {"Cache-Control": "no-store"}


@router.get("/", include_in_schema=False)
def index() -> FileResponse:
    """Serve the dashboard entry point (never cached, so updates show)."""
    return FileResponse(_STATIC_DIR / "index.html", media_type="text/html",
                        headers=_INDEX_HEADERS)


@router.get("/v1/me", response_model=MeOut)
def me(container: Container = Depends(get_container),
       principal=Depends(get_current_principal)):
    """Return the authenticated identity + runtime flags for the UI.

    Requires only a valid API key (any role); it is the UI's "who am I" check
    after the operator pastes a key, and reports whether the agent runtime is
    enabled so the dashboard can explain a 503 instead of failing silently.
    """
    user = principal.user
    return MeOut(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        role=user.role,
        agent_enabled=bool(container.settings.agent_enabled),
        app_version=container.settings.app_version,
    )
