"""Provider introspection endpoints (Phase 1E).

Read-only: lists the currently registered ToolProviders and their metadata.
No provider is invoked, no network is opened and no credentials are exposed.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from era.api.deps import get_container
from era.container import Container
from era.core.provider_info import describe_provider

router = APIRouter()


@router.get("/v1/providers")
def list_providers(container: Container = Depends(get_container)) -> dict[str, Any]:
    return {"providers": [info.to_dict() for info in container.registry.describe_all()]}


@router.get("/v1/providers/{provider_id}")
def get_provider(provider_id: str, container: Container = Depends(get_container)) -> dict[str, Any]:
    provider = container.registry.get_provider(provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="provider not found")
    return describe_provider(provider).to_dict()
