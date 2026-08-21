"""Admin user / API-key management endpoints (Phase 2A).

All endpoints are admin-only. Creating an API key returns the raw key exactly
once — the server stores only its SHA-256 hash.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from era.api.deps import get_container, require_permission
from era.container import Container
from era.schemas.auth import (
    ApiKeyCreate,
    ApiKeyOut,
    CreatedApiKey,
    UserCreate,
    UserOut,
)
from era.security.rbac import Permission

router = APIRouter()


@router.post("/v1/users", response_model=UserOut)
def create_user(body: UserCreate, container: Container = Depends(get_container),
                user=Depends(require_permission(Permission.USERS_MANAGE))):
    created = container.auth_service.create_user(
        username=body.username, role=body.role,
        display_name=body.display_name, credential_refs=body.credential_refs,
    )
    return UserOut.model_validate(created)


@router.get("/v1/users", response_model=list[UserOut])
def list_users(container: Container = Depends(get_container),
               user=Depends(require_permission(Permission.USERS_MANAGE))):
    return [UserOut.model_validate(u) for u in container.auth_service.list_users()]


@router.post("/v1/users/{user_id}/disable", response_model=UserOut)
def disable_user(user_id: str, container: Container = Depends(get_container),
                 user=Depends(require_permission(Permission.USERS_MANAGE))):
    updated = container.auth_service.set_user_disabled(user_id, disabled=True)
    if updated is None:
        raise HTTPException(status_code=404, detail="user not found")
    return UserOut.model_validate(updated)


@router.post("/v1/users/{user_id}/enable", response_model=UserOut)
def enable_user(user_id: str, container: Container = Depends(get_container),
                user=Depends(require_permission(Permission.USERS_MANAGE))):
    updated = container.auth_service.set_user_disabled(user_id, disabled=False)
    if updated is None:
        raise HTTPException(status_code=404, detail="user not found")
    return UserOut.model_validate(updated)


@router.post("/v1/users/{user_id}/api-keys", response_model=CreatedApiKey)
def create_api_key(user_id: str, body: ApiKeyCreate,
                   container: Container = Depends(get_container),
                   user=Depends(require_permission(Permission.API_KEYS_MANAGE))):
    try:
        key, raw = container.auth_service.create_api_key(user_id, body.name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from None
    return CreatedApiKey(**ApiKeyOut.model_validate(key).model_dump(), raw_key=raw)


@router.get("/v1/users/{user_id}/api-keys", response_model=list[ApiKeyOut])
def list_user_keys(user_id: str, container: Container = Depends(get_container),
                   user=Depends(require_permission(Permission.API_KEYS_MANAGE))):
    return [ApiKeyOut.model_validate(k) for k in container.auth_service.list_keys(user_id)]


@router.post("/v1/api-keys/{key_id}/revoke", response_model=ApiKeyOut)
def revoke_key(key_id: str, container: Container = Depends(get_container),
               user=Depends(require_permission(Permission.API_KEYS_MANAGE))):
    key = container.auth_service.revoke_key(key_id)
    if key is None:
        raise HTTPException(status_code=404, detail="api key not found")
    return ApiKeyOut.model_validate(key)
