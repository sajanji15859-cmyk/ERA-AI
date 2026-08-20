"""Permission engine: decision matrix, precedence, fail-closed behaviour."""

from __future__ import annotations

from era.core.action import Action
from era.core.enums import Decision
from era.registry.actions import ACTION_CATALOG
from era.schemas.policy import ActionRule
from era.services.permission_engine import PermissionEngine
from era.services.policy import default_policy


def _engine() -> PermissionEngine:
    return PermissionEngine(ACTION_CATALOG)


def test_tier_defaults_matrix():
    eng = _engine()
    policy = default_policy()
    cases = {
        "web.search": Decision.ALLOW,          # SAFE
        "email.read": Decision.ALLOW,          # SENSITIVE
        "email.send": Decision.CONFIRM,        # COMMUNICATION
        "fs.write": Decision.CONFIRM,          # MUTATING
        "device.payment": Decision.CONFIRM_STRONG,  # FINANCIAL
        "booking.confirm": Decision.CONFIRM_STRONG,  # BOOKING
        "fs.delete": Decision.CONFIRM_STRONG,  # DESTRUCTIVE
        "secret.export": Decision.DENY,        # FORBIDDEN
    }
    for action_type, expected in cases.items():
        assert eng.evaluate(Action(action_type=action_type), policy) == expected, action_type


def test_web_fetch_is_not_safe():
    # web.fetch is SENSITIVE (SSRF surface), never SAFE — see registry docstring.
    from era.registry.actions import ACTION_CATALOG as cat
    assert cat.get("web.fetch").risk_level.value == "SENSITIVE"


def test_unknown_action_denied():
    eng = _engine()
    assert eng.evaluate(Action(action_type="mystery.action"), default_policy()) == Decision.DENY


def test_missing_policy_denies_all():
    eng = _engine()
    assert eng.evaluate(Action(action_type="web.search"), None) == Decision.DENY
    assert eng.evaluate(Action(action_type="fs.delete"), None) == Decision.DENY


def test_override_beats_tier_default():
    eng = _engine()
    policy = default_policy()
    policy.overrides["fs.write"] = ActionRule(decision=Decision.ALLOW)
    assert eng.evaluate(Action(action_type="fs.write"), policy) == Decision.ALLOW


def test_param_scoped_override():
    eng = _engine()
    policy = default_policy()
    policy.overrides["fs.write"] = ActionRule(decision=Decision.ALLOW, when={"path": "/tmp"})
    assert eng.evaluate(Action(action_type="fs.write", params={"path": "/tmp"}), policy) == Decision.ALLOW
    # Predicate doesn't match -> fall through to tier default (CONFIRM).
    assert eng.evaluate(Action(action_type="fs.write", params={"path": "/etc"}), policy) == Decision.CONFIRM
