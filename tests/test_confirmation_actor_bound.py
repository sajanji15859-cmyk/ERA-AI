"""Phase 2A: confirmation actor-binding regression tests."""

from __future__ import annotations

from era.core.context import ExecutionContext
from era.db import transaction
from tests.conftest import action, make_container


def test_same_actor_approve_still_works(tmp_path):
    c = make_container(tmp_path)
    a = action("email.send", to="a@example.com")
    resp = c.execution_service.request(a, ExecutionContext(actor_id="alice"))
    assert resp.status == "confirmation_required"

    done = c.execution_service.approve(
        resp.confirmation_id, a, ExecutionContext(actor_id="alice"),
    )
    assert done.status == "executed"


def test_different_actor_approve_denied(tmp_path):
    c = make_container(tmp_path)
    a = action("email.send", to="a@example.com")
    resp = c.execution_service.request(a, ExecutionContext(actor_id="alice"))
    assert resp.status == "confirmation_required"

    denied = c.execution_service.approve(
        resp.confirmation_id, a, ExecutionContext(actor_id="mallory"),
    )
    assert denied.status == "denied"

    # The confirmation is consumed (single-use), so alice cannot recover it.
    retry = c.execution_service.approve(
        resp.confirmation_id, a, ExecutionContext(actor_id="alice"),
    )
    assert retry.status == "denied"


def test_different_actor_deny_denied(tmp_path):
    c = make_container(tmp_path)
    a = action("email.send", to="a@example.com")
    resp = c.execution_service.request(a, ExecutionContext(actor_id="alice"))

    denied = c.execution_service.deny(resp.confirmation_id, ExecutionContext(actor_id="mallory"))
    assert denied.status == "denied"

    # Actor binding did not consume the confirmation; alice can still deny it.
    with transaction(c.session_factory) as session:
        conf = c.confirmation_service.get(session, resp.confirmation_id)
        assert conf.status == "PENDING"

    ok = c.execution_service.deny(resp.confirmation_id, ExecutionContext(actor_id="alice"))
    assert ok.status == "denied"


def test_confirmation_actor_id_recorded(tmp_path):
    c = make_container(tmp_path)
    resp = c.execution_service.request(
        action("email.send", to="a@example.com"), ExecutionContext(actor_id="alice"),
    )
    with transaction(c.session_factory) as session:
        conf = c.confirmation_service.get(session, resp.confirmation_id)
        assert conf.actor_id == "alice"
