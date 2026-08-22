"""Tests for Phase 3H: param_schema enforcement and consolidation."""

from __future__ import annotations

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import Decision, Outcome
from era.core.result import ProviderErrorCode
from era.registry.actions import ACTION_CATALOG
from era.security.validation import ValidationError_, validate_param_schema
from tests.conftest import make_container


def test_catalog_param_schemas_populated():
    """All non-forbidden actions in ACTION_CATALOG have param_schema defined."""
    for spec in ACTION_CATALOG:
        assert spec.param_schema is not None, f"{spec.action_type} missing param_schema"
        assert isinstance(spec.param_schema, dict)


def test_schema_rejects_missing_required_field(tmp_path):
    """ExecutionService rejects action missing required param with VALIDATION."""
    c = make_container(tmp_path)
    # fs.read requires "path"
    a = Action(action_type="fs.read", params={})
    resp = c.execution_service.request(a, ExecutionContext(actor_id="test-user"))
    assert resp.status == "rejected"
    assert resp.decision == Decision.ALLOW
    assert "missing required parameter" in (resp.message or "")


def test_schema_rejects_unknown_parameter_fail_closed(tmp_path):
    """ExecutionService rejects unknown extra fields fail-closed."""
    c = make_container(tmp_path)
    # fs.list only permits "path"
    a = Action(action_type="fs.list", params={"path": "docs", "unauthorized_extra_arg": 123})
    resp = c.execution_service.request(a, ExecutionContext(actor_id="test-user"))
    assert resp.status == "rejected"
    assert resp.decision == Decision.ALLOW
    assert "unknown parameter" in (resp.message or "")


def test_schema_rejects_invalid_type(tmp_path):
    """ExecutionService rejects parameters with invalid types."""
    c = make_container(tmp_path)
    # web.fetch requires url as string, not integer
    a = Action(action_type="web.fetch", params={"url": 12345})
    resp = c.execution_service.request(a, ExecutionContext(actor_id="test-user"))
    assert resp.status == "rejected"
    assert "must be a string" in (resp.message or "")


def test_schema_validation_audit_record(tmp_path):
    """Validation rejections are recorded in audit log with error_code=VALIDATION."""
    c = make_container(tmp_path)
    a = Action(action_type="github.repo_get", params={"invalid_key": "x"})
    c.execution_service.request(a, ExecutionContext(actor_id="test-user"))
    with c.session_factory() as session:
        entries = c.audit_service.list(session, action_type="github.repo_get")
    assert any(e.outcome == Outcome.REJECTED.value and e.error_code == ProviderErrorCode.VALIDATION.value
               for e in entries)


def test_stub_noop_accepts_arbitrary_params(tmp_path):
    """stub.noop allows generic or empty params without over-strict break."""
    c = make_container(tmp_path)
    a1 = Action(action_type="stub.noop", params={})
    resp1 = c.execution_service.request(a1, ExecutionContext(actor_id="test-user"))
    assert resp1.status == "executed"

    a2 = Action(action_type="stub.noop", params={"custom": "val", "num": 42})
    resp2 = c.execution_service.request(a2, ExecutionContext(actor_id="test-user"))
    assert resp2.status == "executed"


def test_validate_param_schema_direct():
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "minLength": 2, "maxLength": 10},
            "age": {"type": "integer", "minimum": 0, "maximum": 150},
            "role": {"type": "string", "enum": ["admin", "user"]},
        },
        "required": ["name"],
    }
    # Valid
    assert validate_param_schema({"name": "alice", "age": 30, "role": "admin"}, schema) == {
        "name": "alice", "age": 30, "role": "admin"
    }

    # Missing required
    with pytest.raises(ValidationError_, match="missing required parameter"):
        validate_param_schema({"age": 30}, schema)

    # Unknown parameter
    with pytest.raises(ValidationError_, match="unknown parameter"):
        validate_param_schema({"name": "alice", "extra": True}, schema)

    # Type mismatch
    with pytest.raises(ValidationError_, match="must be an integer"):
        validate_param_schema({"name": "alice", "age": "thirty"}, schema)

    # Enum violation
    with pytest.raises(ValidationError_, match="must be one of"):
        validate_param_schema({"name": "alice", "role": "superuser"}, schema)

    # Length violation
    with pytest.raises(ValidationError_, match="at least 2 chars"):
        validate_param_schema({"name": "a"}, schema)

    # Range violation
    with pytest.raises(ValidationError_, match=">= 0"):
        validate_param_schema({"name": "alice", "age": -5}, schema)
