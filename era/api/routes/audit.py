"""Read-only audit endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from era.api.deps import get_container
from era.container import Container
from era.db import transaction
from era.schemas.audit import AuditEntryOut, VerifyResponse

router = APIRouter()


@router.get("/v1/audit/verify", response_model=VerifyResponse)
def verify(container: Container = Depends(get_container)):
    with transaction(container.session_factory) as session:
        result = container.audit_service.verify(session)
    return VerifyResponse(
        valid=result.valid,
        entry_count=result.entry_count,
        first_mismatch_seq=result.first_mismatch_seq,
        message=result.message,
    )


@router.get("/v1/audit/{entry_id}", response_model=AuditEntryOut)
def get_entry(entry_id: int, container: Container = Depends(get_container)):
    with transaction(container.session_factory) as session:
        entry = container.audit_service.get(session, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="audit entry not found")
    return AuditEntryOut.model_validate(entry)


@router.get("/v1/audit", response_model=list[AuditEntryOut])
def list_entries(limit: int = 100, offset: int = 0,
                 action_type: str | None = None, outcome: str | None = None,
                 container: Container = Depends(get_container)):
    with transaction(container.session_factory) as session:
        entries = container.audit_service.list(
            session, limit=limit, offset=offset,
            action_type=action_type, outcome=outcome,
        )
    return [AuditEntryOut.model_validate(e) for e in entries]
