"""FastAPI dependencies: container access, authentication, authorization.

Phase 2A introduces server-side identity: every protected route resolves the
authenticated caller from the ``Authorization: Bearer <api-key>`` header via
:meth:`AuthService.authenticate_token`. Client-supplied identity (``actor_id``,
``session_id``, credential refs) is never trusted — the server derives it from
the authenticated principal.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, Request

from era.container import Container
from era.core.context import ExecutionContext
from era.security.exceptions import AuthenticationError, AuthorizationError
from era.services.auth_service import AuthenticatedPrincipal


def get_container(request: Request) -> Container:
    return request.app.state.container


def get_auth_service(request: Request):
    return request.app.state.container.auth_service


def _bearer_token(request: Request) -> str | None:
    """Extract the raw token from the ``Authorization`` header (Bearer scheme)."""
    authorization = request.headers.get("authorization")
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, credentials = parts
    if scheme.lower() != "bearer" or not credentials.strip():
        return None
    return credentials.strip()


def get_current_principal(
    request: Request,
    auth_service=Depends(get_auth_service),
) -> AuthenticatedPrincipal:
    """Authenticate the request and return the server-derived principal.

    Raises HTTP 401 on missing / invalid / revoked / disabled credentials.
    """
    token = _bearer_token(request)
    try:
        return auth_service.authenticate_token(token)
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="authentication required")


def get_current_user(principal: AuthenticatedPrincipal = Depends(get_current_principal)):
    """Return the authenticated :class:`~era.models.user.User`."""
    return principal.user


def require_permission(permission: str) -> Callable[..., Any]:
    """Dependency factory: require ``permission`` on the authenticated user.

    Raises HTTP 401 if unauthenticated; HTTP 403 if the caller lacks the
    permission (fail closed — unauthorized callers are never allowed through).
    """
    def dependency(
        user=Depends(get_current_user),
        auth_service=Depends(get_auth_service),
    ):
        try:
            auth_service.require_permission(user, permission)
        except AuthorizationError:
            raise HTTPException(status_code=403, detail=f"forbidden: missing {permission}")
        return user
    return dependency


def build_ctx(principal: AuthenticatedPrincipal,
              session_id: str | None = None) -> ExecutionContext:
    """Build the server-side execution context for an authenticated principal.

    ``actor_id`` = the server-derived user id; ``session_id`` = the API-key id
    that authenticated the request; ``credentials`` = the user's own opaque
    credential refs (never supplied by the client).
    """
    return ExecutionContext(
        actor_id=principal.actor_id,
        session_id=session_id or principal.session_id,
        credentials={"refs": dict(principal.user.credential_refs or {})},
    )
