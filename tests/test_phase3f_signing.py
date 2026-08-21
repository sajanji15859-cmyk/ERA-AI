"""Phase 3F keyed audit signing and verification."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from era.config import Settings
from era.container import build_container
from era.core.action import Action
from era.core.context import ExecutionContext
from era.db import transaction
from era.security.signing import Ed25519AuditSigner, HMACAuditSigner


def test_hmac_sign_verify_and_wrong_key_rejected():
    signer = HMACAuditSigner(b"a" * 32, key_id="audit-2026")
    signature = signer.sign("f" * 64)

    assert signer.verify("f" * 64, signature) is True
    assert signer.verify("e" * 64, signature) is False
    assert HMACAuditSigner(b"b" * 32, key_id="audit-2026").verify(
        "f" * 64, signature
    ) is False


def test_ed25519_asymmetric_signing_can_be_verified_with_public_key_only():
    private_key = Ed25519PrivateKey.generate()
    signer = Ed25519AuditSigner(private_key=private_key, key_id="ed-1")
    verifier = Ed25519AuditSigner(public_key=private_key.public_key(), key_id="ed-1")
    signature = signer.sign("1" * 64)

    assert verifier.verify("1" * 64, signature) is True
    assert verifier.verify("2" * 64, signature) is False


def test_signed_audit_chain_and_signature_tamper_detection(tmp_path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path}/signed.db",
        audit_signing_algorithm="hmac-sha256",
        audit_signing_key="phase-3f-test-signing-key-material!",
        audit_signing_key_id="test-key-1",
    )
    container = build_container(settings)
    container.execution_service.request(
        Action(action_type="stub.noop"),
        ExecutionContext(actor_id="signing-test"),
    )

    with transaction(container.session_factory) as session:
        rows = container.audit_service.list(session)
        verified = container.audit_service.verify(session)
    assert verified.valid is True
    assert len(rows) == 2
    assert all(row.signing_algorithm == "hmac-sha256" for row in rows)
    assert all(row.signing_key_id == "test-key-1" for row in rows)
    assert all(row.signature for row in rows)

    # Simulate a privileged database attacker. The append-only guard must be
    # removed first; changing only the signature leaves the SHA chain intact,
    # but keyed verification still detects it.
    with container.engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER era_audit_log_no_update")
        connection.execute(
            text("UPDATE audit_log SET signature = :signature WHERE seq = 1"),
            {"signature": "forged"},
        )
    with transaction(container.session_factory) as session:
        tampered = container.audit_service.verify(session)
    assert tampered.valid is False
    assert tampered.first_mismatch_seq == 1
    assert "signature mismatch" in tampered.message
