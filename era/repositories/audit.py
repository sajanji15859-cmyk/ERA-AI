"""Shared deterministic audit-chain construction and verification."""

from __future__ import annotations

from collections.abc import Iterable

from era.core.util import utcnow_iso
from era.models import AuditLogEntry
from era.repositories.base import NewAuditEntry, VerifyResult
from era.security.hashing import canonical_json, sha256_hex
from era.security.signing import AuditSigner


def build_audit_row(
    entry: NewAuditEntry,
    *,
    seq: int,
    prev_hash: str,
    signer: AuditSigner | None,
) -> AuditLogEntry:
    created_at = utcnow_iso()
    payload = {
        "seq": seq,
        "created_at": created_at,
        "actor_id": entry.actor_id,
        "action_type": entry.action_type,
        "action_params": entry.action_params,
        "risk_level": entry.risk_level,
        "decision": entry.decision,
        "outcome": entry.outcome,
        "confirmation_id": entry.confirmation_id,
        "result": entry.result,
        "error_code": entry.error_code,
        "provider_id": entry.provider_id,
        "capability_domain": entry.capability_domain,
        "credential_ref": entry.credential_ref,
        "policy_version": entry.policy_version,
        "app_version": entry.app_version,
        "meta": entry.meta,
        "prev_hash": prev_hash,
    }
    entry_hash = sha256_hex(canonical_json(payload))
    return AuditLogEntry(
        **payload,
        entry_hash=entry_hash,
        signing_algorithm=signer.algorithm if signer else None,
        signing_key_id=signer.key_id if signer else None,
        signature=signer.sign(entry_hash) if signer else None,
    )


def verify_audit_rows(
    rows: Iterable[AuditLogEntry],
    *,
    genesis_hash: str,
    signer: AuditSigner | None,
) -> VerifyResult:
    materialized = list(rows)
    if not materialized:
        return VerifyResult(valid=True, entry_count=0, message="empty log")

    prev = genesis_hash
    for row in materialized:
        if row.prev_hash != prev:
            return _mismatch(materialized, row, "broken chain link")
        expected = sha256_hex(canonical_json(_payload_from_row(row)))
        if row.entry_hash != expected:
            return _mismatch(materialized, row, "entry hash mismatch")
        signing_error = _verify_signature(row, signer)
        if signing_error:
            return _mismatch(materialized, row, signing_error)
        prev = row.entry_hash

    mode = f"signed by {signer.key_id}" if signer else "legacy unsigned"
    return VerifyResult(
        valid=True,
        entry_count=len(materialized),
        message=f"chain valid ({mode})",
    )


def _verify_signature(row: AuditLogEntry, signer: AuditSigner | None) -> str | None:
    signed = bool(row.signing_algorithm or row.signing_key_id or row.signature)
    if signer is None:
        return "signing key unavailable for signed entry" if signed else None
    if row.signing_algorithm != signer.algorithm:
        return "audit signing algorithm mismatch"
    if row.signing_key_id != signer.key_id:
        return "audit signing key id mismatch"
    if not row.signature or not signer.verify(row.entry_hash, row.signature):
        return "audit signature mismatch"
    return None


def _payload_from_row(row: AuditLogEntry) -> dict:
    return {field: getattr(row, field) for field in AuditLogEntry.HASH_FIELDS}


def _mismatch(rows: list[AuditLogEntry], row: AuditLogEntry, reason: str) -> VerifyResult:
    return VerifyResult(
        valid=False,
        entry_count=len(rows),
        first_mismatch_seq=row.seq,
        message=f"{reason} at seq {row.seq}",
    )
