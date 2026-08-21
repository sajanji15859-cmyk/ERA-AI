"""Audit read/verify response schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    seq: int
    created_at: str
    actor_id: str
    action_type: str
    action_params: dict[str, Any]
    risk_level: str
    decision: str
    outcome: str
    confirmation_id: str | None
    result: str | None
    provider_id: str | None
    capability_domain: str | None
    credential_ref: str | None
    policy_version: int
    app_version: str
    prev_hash: str
    entry_hash: str
    signing_algorithm: str | None = None
    signing_key_id: str | None = None
    signature: str | None = None


class VerifyResponse(BaseModel):
    valid: bool
    entry_count: int
    first_mismatch_seq: int | None = None
    message: str
