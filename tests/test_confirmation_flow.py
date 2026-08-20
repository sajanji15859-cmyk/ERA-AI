"""Confirmation lifecycle: approve/deny/expiry/single-use/replay/hash/challenge."""

from __future__ import annotations

from era.core.context import ExecutionContext
from era.core.enums import Decision
from era.db import transaction
from tests.conftest import action


def test_confirm_then_approve(container):
    resp = container.execution_service.request(
        action("email.send", to="x@example.com", body="hi"),
        ExecutionContext(actor_id="t"),
    )
    assert resp.status == "confirmation_required"
    assert resp.decision == Decision.CONFIRM
    assert resp.confirmation_id

    approved = container.execution_service.approve(
        resp.confirmation_id,
        action("email.send", to="x@example.com", body="hi"),
        ExecutionContext(actor_id="t"),
    )
    assert approved.status == "executed"


def test_approve_with_substituted_params_denied(container):
    resp = container.execution_service.request(
        action("email.send", to="a@example.com", body="hi"),
        ExecutionContext(actor_id="t"),
    )
    # Different params -> hash mismatch -> fail closed (REJECTED).
    denied = container.execution_service.approve(
        resp.confirmation_id,
        action("email.send", to="b@example.com", body="hijacked"),
        ExecutionContext(actor_id="t"),
    )
    assert denied.status == "denied"
    assert "hash mismatch" in (denied.message or "")


def test_deny_flow(container):
    resp = container.execution_service.request(
        action("email.send", to="x@example.com"),
        ExecutionContext(actor_id="t"),
    )
    denied = container.execution_service.deny(resp.confirmation_id, ExecutionContext(actor_id="t"))
    assert denied.status == "denied"

    with transaction(container.session_factory) as session:
        outcomes = [e.outcome for e in container.audit_service.list(session)]
    assert "DENIED_BY_USER" in outcomes


def test_replay_second_approve_rejected(container):
    resp = container.execution_service.request(
        action("email.send", to="x@example.com"),
        ExecutionContext(actor_id="t"),
    )
    a = action("email.send", to="x@example.com")
    first = container.execution_service.approve(resp.confirmation_id, a, ExecutionContext(actor_id="t"))
    assert first.status == "executed"
    second = container.execution_service.approve(resp.confirmation_id, a, ExecutionContext(actor_id="t"))
    assert second.status == "denied"
    assert "already resolved" in (second.message or "")


def test_expired_confirmation(container):
    resp = container.execution_service.request(
        action("email.send", to="x@example.com"),
        ExecutionContext(actor_id="t"),
    )
    # Force expiry by rewriting the stored timestamp.
    with transaction(container.session_factory) as session:
        conf = container.confirmation_service.get(session, resp.confirmation_id)
        conf.expires_at = "2000-01-01T00:00:00.000000+00:00"
        container.confirmation_service.confirmation_repo.update(session, conf)

    denied = container.execution_service.approve(
        resp.confirmation_id,
        action("email.send", to="x@example.com"),
        ExecutionContext(actor_id="t"),
    )
    assert denied.status == "denied"
    assert "expired" in (denied.message or "")


def test_challenge_required_for_strong(container):
    a = action("fs.delete", path="/important")

    # Wrong challenge -> denied, and the single-use confirmation is consumed
    # (fail closed: a failed attempt must not be retryable / brute-forceable).
    resp1 = container.execution_service.request(a, ExecutionContext(actor_id="t"))
    assert resp1.decision == Decision.CONFIRM_STRONG
    assert resp1.challenge
    wrong = container.execution_service.approve(resp1.confirmation_id, a,
                                                ExecutionContext(actor_id="t"),
                                                challenge="not-the-challenge")
    assert wrong.status == "denied"
    assert "challenge" in (wrong.message or "")

    # A fresh confirmation with the correct challenge -> executed.
    resp2 = container.execution_service.request(a, ExecutionContext(actor_id="t"))
    ok = container.execution_service.approve(resp2.confirmation_id, a,
                                             ExecutionContext(actor_id="t"),
                                             challenge=resp2.challenge)
    assert ok.status == "executed"


def test_confirm_creates_pending_audit(container):
    container.execution_service.request(
        action("email.send", to="x@example.com"),
        ExecutionContext(actor_id="t"),
    )
    with transaction(container.session_factory) as session:
        outcomes = [e.outcome for e in container.audit_service.list(session)]
    assert "PENDING" in outcomes
