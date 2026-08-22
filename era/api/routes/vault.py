"""Credential vault management endpoints (Phase 3C).

All endpoints are **admin-only** (``vault.manage``). The secret value is
accepted on write but is never returned by any endpoint — responses are
metadata only. With no master key configured the vault is disabled and
mutations / resolution fail closed (HTTP 503 here).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from era.api.deps import get_container, require_permission
from era.container import Container
from era.schemas.vault import VaultSecretIn, VaultSecretOut
from era.security.rbac import Permission
from era.security.vault import VaultError

router = APIRouter()


def _vault_error_http(exc: VaultError) -> HTTPException:
    if exc.code == "disabled":
        return HTTPException(status_code=503, detail="credential vault disabled "
                                    "(set ERA_VAULT_MASTER_KEY)")
    if exc.code == "not_found":
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


@router.post("/v1/vault/secrets", response_model=VaultSecretOut)
def store_or_rotate_secret(body: VaultSecretIn,
                           container: Container = Depends(get_container),
                           user=Depends(require_permission(Permission.VAULT_MANAGE))):
    """Create a vault secret, or rotate it if it already exists (revived if revoked).

    Returns metadata only — the value is shown exactly once in the request and
    never again, mirroring the API-key lifecycle.
    """
    owner_user_id = body.owner_user_id or user.id
    if body.owner_user_id and container.auth_service.get_user(body.owner_user_id) is None:
        raise HTTPException(status_code=404, detail="owner user not found")
    try:
        secret = container.vault_service.store_or_rotate_secret(
            domain=body.domain, name=body.name, value=body.value,
            actor_id=user.id, owner_user_id=owner_user_id,
        )
    except VaultError as exc:
        raise _vault_error_http(exc) from None
    return VaultSecretOut.model_validate(secret)


@router.get("/v1/vault/secrets", response_model=list[VaultSecretOut])
def list_secrets(domain: str | None = Query(default=None),
                 container: Container = Depends(get_container),
                 user=Depends(require_permission(Permission.VAULT_MANAGE))):
    """List vault metadata (never values), optionally filtered by domain."""
    try:
        secrets = container.vault_service.list_secrets(domain)
    except VaultError as exc:
        raise _vault_error_http(exc) from None
    return [VaultSecretOut.model_validate(s) for s in secrets]


@router.post("/v1/vault/secrets/{domain}/{name}/revoke", response_model=VaultSecretOut)
def revoke_secret(domain: str, name: str,
                  container: Container = Depends(get_container),
                  user=Depends(require_permission(Permission.VAULT_MANAGE))):
    """Revoke a secret: it can no longer be resolved (soft revoke, audited)."""
    try:
        secret = container.vault_service.revoke_secret(
            domain=domain, name=name, actor_id=user.id,
        )
    except VaultError as exc:
        raise _vault_error_http(exc) from None
    return VaultSecretOut.model_validate(secret)
