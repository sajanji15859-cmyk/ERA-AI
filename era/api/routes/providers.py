"""Provider introspection endpoints (Phase 1E).

Read-only: lists the currently registered ToolProviders and their metadata.
No provider is invoked, no network is opened and no credentials are exposed.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from era.api.deps import get_container, require_permission
from era.container import Container
from era.core.provider_info import describe_provider
from era.security.rbac import Permission

router = APIRouter()


@router.get("/v1/providers")
def list_providers(container: Container = Depends(get_container),
                   user=Depends(require_permission(Permission.PROVIDERS_READ))) -> dict[str, Any]:
    return {"providers": [info.to_dict() for info in container.registry.describe_all()]}


@router.get("/v1/providers/whatsapp/webhook", response_class=PlainTextResponse)
def verify_whatsapp_webhook(
    hub_mode: str | None = Query(default=None, alias="hub.mode"),
    hub_verify_token: str | None = Query(default=None, alias="hub.verify_token"),
    hub_challenge: str | None = Query(default=None, alias="hub.challenge"),
    container: Container = Depends(get_container),
):
    """Meta webhook verification; intentionally public but token-bound."""
    provider = container.registry.get_provider("whatsapp")
    verify = getattr(provider, "verify_webhook_token", None)
    if hub_mode != "subscribe" or not callable(verify) or not verify(hub_verify_token):
        raise HTTPException(status_code=403, detail="webhook verification failed")
    return PlainTextResponse(hub_challenge or "")


@router.post("/v1/providers/whatsapp/webhook")
async def ingest_whatsapp_webhook(request: Request, container: Container = Depends(get_container)):
    """Accept only HMAC-authenticated Meta webhook payloads; never dispatch tools."""
    provider = container.registry.get_provider("whatsapp")
    ingest = getattr(provider, "ingest_webhook", None)
    verify_signature = getattr(provider, "verify_webhook_signature", None)
    if not callable(ingest) or not callable(verify_signature):
        raise HTTPException(status_code=404, detail="WhatsApp webhook is not configured")
    raw = await request.body()
    if not verify_signature(raw, request.headers.get("X-Hub-Signature-256")):
        raise HTTPException(status_code=403, detail="webhook signature verification failed")
    try:
        import json
        payload = json.loads(raw)
        count = ingest(payload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid webhook payload") from exc
    return {"accepted": count}


@router.get("/v1/providers/{provider_id}")
def get_provider(provider_id: str, container: Container = Depends(get_container),
                 user=Depends(require_permission(Permission.PROVIDERS_READ))) -> dict[str, Any]:
    provider = container.registry.get_provider(provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="provider not found")
    return describe_provider(provider).to_dict()
