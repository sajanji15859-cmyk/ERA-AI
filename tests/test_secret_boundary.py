"""Secret/credential boundary: redaction, no leaks, references-only."""

from __future__ import annotations

from era.core.context import ExecutionContext
from era.core.llm import LLMRequest
from era.core.result import ActionResult
from era.db import transaction
from era.security.redaction import REDACTED, redact
from tests.conftest import action


def test_redaction_helper():
    assert redact({"api_key": "secret", "nested": {"token": "x", "ok": 1}}) == {
        "api_key": REDACTED, "nested": {"token": REDACTED, "ok": 1},
    }


def test_secret_redacted_in_audit(container):
    container.execution_service.request(
        action("web.search", query="python", api_key="sk-SUPERSECRET"),
        ExecutionContext(actor_id="t"),
    )
    with transaction(container.session_factory) as session:
        entries = [e for e in container.audit_service.list(session) if e.action_type == "web.search"]
    for e in entries:
        assert e.action_params.get("api_key") == REDACTED
        assert "sk-SUPERSECRET" not in str(e.action_params)


def test_no_secret_in_response(container):
    resp = container.execution_service.request(
        action("web.search", query="python", api_key="sk-SUPERSECRET"),
        ExecutionContext(actor_id="t"),
    )
    assert "sk-SUPERSECRET" not in resp.model_dump_json()


def test_llm_request_has_no_secret_field():
    # No field may carry a raw credential (API key, secret, password, token).
    credential_hints = ("api_key", "secret", "password", "credential",
                        "authorization", "api_token", "refresh_token")
    fields = LLMRequest.model_fields
    for name in fields:
        assert not any(h in name.lower() for h in credential_hints), name
    # A request references a model by an opaque id, never a key.
    req = LLMRequest(model_ref="openai/gpt-x", messages=[{"role": "user", "content": "hi"}])
    assert "sk-" not in req.model_dump_json()


class CaptureProvider:
    id = "capture"
    action_types = frozenset({"stub.noop"})

    def __init__(self):
        self.seen = None

    def validate(self, action):
        return None

    def execute(self, action, ctx):
        self.seen = (action, ctx)
        return ActionResult(success=True, summary="ok")


def test_provider_receives_refs_not_secrets(tmp_path):
    from tests.conftest import make_container
    provider = CaptureProvider()
    c = make_container(tmp_path, providers=[provider])
    ctx = ExecutionContext(actor_id="t", credentials={"refs": {"core": "ref-abc"}})
    c.execution_service.request(action("stub.noop"), ctx)
    # The provider is given references, never raw secrets.
    seen_ctx = provider.seen[1]
    assert seen_ctx.credentials.refs == {"core": "ref-abc"}
    assert "supersecret" not in seen_ctx.model_dump_json()
