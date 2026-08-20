"""Append-only audit log: immutability, hash chain, tamper detection, redaction."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import DatabaseError

from era.core.context import ExecutionContext
from era.db import transaction
from tests.conftest import action


def test_append_only_api_surface(container):
    repo = container.audit_service.audit_repo
    assert not hasattr(repo, "update")
    assert not hasattr(repo, "delete")


def test_db_trigger_blocks_update(container):
    container.execution_service.request(action("stub.noop"), ExecutionContext(actor_id="t"))
    with container.engine.begin() as conn, pytest.raises(DatabaseError):
        conn.exec_driver_sql("UPDATE audit_log SET result='x' WHERE seq=1")


def test_db_trigger_blocks_delete(container):
    container.execution_service.request(action("stub.noop"), ExecutionContext(actor_id="t"))
    with container.engine.begin() as conn, pytest.raises(DatabaseError):
        conn.exec_driver_sql("DELETE FROM audit_log WHERE seq=1")


def test_hash_chain_valid(container):
    for _ in range(5):
        container.execution_service.request(action("stub.noop"), ExecutionContext(actor_id="t"))
    with transaction(container.session_factory) as session:
        result = container.audit_service.verify(session)
    assert result.valid is True
    assert result.entry_count == 10  # AUTHORIZED + EXECUTED per request


def test_tamper_detected(container):
    container.execution_service.request(action("stub.noop"), ExecutionContext(actor_id="t"))
    # Simulate tampering by dropping the guard trigger and editing a row.
    with container.engine.begin() as conn:
        conn.exec_driver_sql("DROP TRIGGER IF EXISTS era_audit_log_no_update")
        conn.exec_driver_sql("UPDATE audit_log SET result='TAMPERED' WHERE seq=1")

    with transaction(container.session_factory) as session:
        result = container.audit_service.verify(session)
    assert result.valid is False
    assert result.first_mismatch_seq == 1


def test_seq_monotonic(container):
    for _ in range(3):
        container.execution_service.request(action("stub.noop"), ExecutionContext(actor_id="t"))
    with transaction(container.session_factory) as session:
        seqs = [e.seq for e in container.audit_service.list(session)]
    assert seqs == sorted(seqs)
    assert seqs == list(range(1, len(seqs) + 1))


def test_provider_and_credential_ref_recorded(container):
    ctx = ExecutionContext(actor_id="t", credentials={"refs": {"web": "cred-123"}})
    container.execution_service.request(action("web.search", query="hi"), ctx)
    with transaction(container.session_factory) as session:
        entries = [e for e in container.audit_service.list(session) if e.action_type == "web.search"]
    assert any(e.provider_id == "stub" for e in entries)
    assert any(e.credential_ref == "cred-123" for e in entries)
