"""Security regression lock for Phase 1C/1D guarantees."""

from __future__ import annotations

from era.core.context import ExecutionContext
from era.core.enums import Decision
from era.core.result import ActionResult
from era.db import transaction
from era.security.hashing import action_fingerprint
from era.security.redaction import REDACTED
from tests.conftest import action, make_container


class CountingProvider:
    id = "counting"
    action_types = frozenset({"stub.noop", "email.send", "fs.delete"})

    def __init__(self):
        self.calls = 0

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        self.calls += 1
        return ActionResult(success=True, summary="ok")


def test_fail_closed_unknown_and_missing_policy(tmp_path):
    c = make_container(tmp_path)
    resp = c.execution_service.request(action("nope.x"), ExecutionContext(actor_id="t"))
    assert resp.status == "denied"
    assert resp.decision == Decision.DENY


def test_confirmation_single_use(tmp_path):
    provider = CountingProvider()
    c = make_container(tmp_path, providers=[provider])
    a = action("email.send", to="a@x.com")
    pending = c.execution_service.request(a, ExecutionContext(actor_id="t"))
    first = c.execution_service.approve(pending.confirmation_id, a, ExecutionContext(actor_id="t"))
    second = c.execution_service.approve(pending.confirmation_id, a, ExecutionContext(actor_id="t"))
    assert first.status == "executed"
    assert second.status == "denied"
    assert provider.calls == 1


def test_ttl_expiry(tmp_path):
    provider = CountingProvider()
    c = make_container(tmp_path, providers=[provider])
    a = action("email.send", to="a@x.com")
    pending = c.execution_service.request(a, ExecutionContext(actor_id="t"))
    with transaction(c.session_factory) as session:
        conf = c.confirmation_service.get(session, pending.confirmation_id)
        conf.expires_at = "2000-01-01T00:00:00+00:00"
        c.confirmation_service.confirmation_repo.update(session, conf)
    denied = c.execution_service.approve(pending.confirmation_id, a, ExecutionContext(actor_id="t"))
    assert denied.status == "denied"
    assert "expired" in (denied.message or "")
    assert provider.calls == 0


def test_action_hash_binding(tmp_path):
    provider = CountingProvider()
    c = make_container(tmp_path, providers=[provider])
    pending = c.execution_service.request(
        action("email.send", to="a@x.com"), ExecutionContext(actor_id="t"),
    )
    denied = c.execution_service.approve(
        pending.confirmation_id,
        action("email.send", to="b@x.com"),
        ExecutionContext(actor_id="t"),
    )
    assert denied.status == "denied"
    assert "hash mismatch" in (denied.message or "")
    assert provider.calls == 0
    fp1 = action_fingerprint("email.send", {"to": "a@x.com"}, "COMMUNICATION")
    fp2 = action_fingerprint("email.send", {"to": "b@x.com"}, "COMMUNICATION")
    assert fp1 != fp2


def test_confirm_strong_challenge(tmp_path):
    provider = CountingProvider()
    c = make_container(tmp_path, providers=[provider])
    a = action("fs.delete", path="/x")
    pending = c.execution_service.request(a, ExecutionContext(actor_id="t"))
    assert pending.decision == Decision.CONFIRM_STRONG
    assert pending.challenge
    missing = c.execution_service.approve(pending.confirmation_id, a, ExecutionContext(actor_id="t"))
    assert missing.status == "denied"
    assert provider.calls == 0

    pending2 = c.execution_service.request(a, ExecutionContext(actor_id="t"))
    ok = c.execution_service.approve(
        pending2.confirmation_id, a, ExecutionContext(actor_id="t"), challenge=pending2.challenge,
    )
    assert ok.status == "executed"
    assert provider.calls == 1


def test_audit_write_failure_prevents_provider_execution(tmp_path):
    provider = CountingProvider()
    c = make_container(tmp_path, providers=[provider])

    def boom(session, **kwargs):
        raise RuntimeError("audit down")

    c.audit_service.record = boom
    try:
        c.execution_service.request(action("stub.noop"), ExecutionContext(actor_id="t"))
        raised = False
    except RuntimeError:
        raised = True
    assert raised
    assert provider.calls == 0


def test_secret_redaction(tmp_path):
    c = make_container(tmp_path)
    c.execution_service.request(
        action("web.search", query="q", api_key="sk-SUPERSECRET"),
        ExecutionContext(actor_id="t"),
    )
    with transaction(c.session_factory) as session:
        entries = [e for e in c.audit_service.list(session) if e.action_type == "web.search"]
    assert entries
    for e in entries:
        assert e.action_params.get("api_key") == REDACTED
        assert "sk-SUPERSECRET" not in str(e.action_params)


def test_forbidden_request_never_executes_even_if_engine_allows(tmp_path):
    provider = CountingProvider()
    c = make_container(tmp_path, providers=[provider])
    c.permission_engine.evaluate = lambda action, policy: Decision.ALLOW
    for action_type in ("secret.export", "account.delete"):
        resp = c.execution_service.request(action(action_type), ExecutionContext(actor_id="t"))
        assert resp.status == "denied"
        assert resp.decision == Decision.DENY
    assert provider.calls == 0


def test_forbidden_cannot_enter_confirmation_flow(tmp_path):
    provider = CountingProvider()
    c = make_container(tmp_path, providers=[provider])
    c.permission_engine.evaluate = lambda action, policy: Decision.CONFIRM_STRONG
    resp = c.execution_service.request(action("secret.export"), ExecutionContext(actor_id="t"))
    assert resp.status == "denied"
    assert resp.confirmation_id is None
    assert provider.calls == 0


def test_forbidden_approve_of_stale_confirmation_denied(tmp_path):
    """A confirmation row cannot be used to ride a FORBIDDEN action."""
    from era.core.enums import RiskLevel
    from era.db import transaction as txn

    provider = CountingProvider()
    c = make_container(tmp_path, providers=[provider])
    a = action("secret.export")
    with txn(c.session_factory) as session:
        conf, challenge = c.confirmation_service.create(
            session, action=a, risk_level=RiskLevel.FORBIDDEN,
            decision=Decision.ALLOW, policy_version=1,
        )
        cid = conf.id
    denied = c.execution_service.approve(cid, a, ExecutionContext(actor_id="t"), challenge=challenge)
    assert denied.status == "denied"
    assert denied.decision == Decision.DENY
    assert provider.calls == 0


def test_append_only_audit_integrity(tmp_path):
    c = make_container(tmp_path)
    c.execution_service.request(action("stub.noop"), ExecutionContext(actor_id="t"))
    with transaction(c.session_factory) as session:
        result = c.audit_service.verify(session)
    assert result.valid is True
    repo = c.audit_service.audit_repo
    assert not hasattr(repo, "update")
    assert not hasattr(repo, "delete")
