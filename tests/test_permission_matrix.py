"""Exhaustive permission-matrix + catalog metadata consistency."""

from __future__ import annotations

from era.core.action import Action
from era.core.enums import Decision, RiskLevel
from era.registry.actions import ACTION_CATALOG, ActionType
from era.schemas.policy import ActionRule, Policy
from era.services.permission_engine import PermissionEngine
from era.services.policy import DEFAULT_TIER_DEFAULTS, default_policy

EXPECTED_RISK: dict[str, RiskLevel] = {
    "stub.noop": RiskLevel.SAFE,
    "web.search": RiskLevel.SAFE,
    "web.fetch": RiskLevel.SENSITIVE,
    "web.download": RiskLevel.MUTATING,
    "browser.navigate": RiskLevel.SENSITIVE,
    "browser.screenshot": RiskLevel.SENSITIVE,
    "browser.extract_dom": RiskLevel.SAFE,
    "browser.click": RiskLevel.MUTATING,
    "browser.fill": RiskLevel.MUTATING,
    "browser.submit": RiskLevel.MUTATING,
    "email.read": RiskLevel.SENSITIVE,
    "email.search": RiskLevel.SENSITIVE,
    "email.draft": RiskLevel.MUTATING,
    "email.send": RiskLevel.COMMUNICATION,
    "whatsapp.read": RiskLevel.SENSITIVE,
    "whatsapp.send": RiskLevel.COMMUNICATION,
    "whatsapp.react": RiskLevel.COMMUNICATION,
    "booking.search": RiskLevel.SENSITIVE,
    "booking.hold": RiskLevel.MUTATING,
    "booking.confirm": RiskLevel.BOOKING,
    "booking.cancel": RiskLevel.BOOKING,
    "fs.list": RiskLevel.SAFE,
    "fs.read": RiskLevel.SENSITIVE,
    "fs.write": RiskLevel.MUTATING,
    "fs.move": RiskLevel.MUTATING,
    "fs.delete": RiskLevel.DESTRUCTIVE,
    "photo.view": RiskLevel.SENSITIVE,
    "photo.edit": RiskLevel.MUTATING,
    "photo.upload": RiskLevel.MUTATING,
    "photo.delete": RiskLevel.DESTRUCTIVE,
    "device.shell": RiskLevel.DESTRUCTIVE,
    "device.app_launch": RiskLevel.MUTATING,
    "device.ui_click": RiskLevel.MUTATING,
    "device.screenshot": RiskLevel.SENSITIVE,
    "device.photo_capture": RiskLevel.SENSITIVE,
    "device.location": RiskLevel.SENSITIVE,
    "device.notification": RiskLevel.SENSITIVE,
    "device.contacts": RiskLevel.SENSITIVE,
    "device.sms_read": RiskLevel.SENSITIVE,
    "device.sms_send": RiskLevel.COMMUNICATION,
    "device.install_app": RiskLevel.MUTATING,
    "device.uninstall_app": RiskLevel.DESTRUCTIVE,
    "device.settings_change": RiskLevel.DESTRUCTIVE,
    "device.payment": RiskLevel.FINANCIAL,
    "github.repo_get": RiskLevel.SAFE,
    "github.issue_list": RiskLevel.SAFE,
    "github.issue_get": RiskLevel.SAFE,
    "github.issue_create": RiskLevel.MUTATING,
    "github.issue_comment": RiskLevel.MUTATING,
    "github.pr_list": RiskLevel.SAFE,
    "github.pr_get": RiskLevel.SAFE,
    "github.pr_create": RiskLevel.MUTATING,
    "github.file_get": RiskLevel.SENSITIVE,
    "github.file_commit": RiskLevel.MUTATING,
    "code.run": RiskLevel.MUTATING,
    "code.exec": RiskLevel.MUTATING,
    "image.generate": RiskLevel.MUTATING,
    "secret.export": RiskLevel.FORBIDDEN,
    "account.delete": RiskLevel.FORBIDDEN,
}

EXPECTED_DOMAIN: dict[str, str] = {
    "stub.noop": "core",
    "web.search": "web",
    "web.fetch": "web",
    "web.download": "web",
    "browser.navigate": "browser",
    "browser.screenshot": "browser",
    "browser.extract_dom": "browser",
    "browser.click": "browser",
    "browser.fill": "browser",
    "browser.submit": "browser",
    "email.read": "email",
    "email.search": "email",
    "email.draft": "email",
    "email.send": "email",
    "whatsapp.read": "whatsapp",
    "whatsapp.send": "whatsapp",
    "whatsapp.react": "whatsapp",
    "booking.search": "booking",
    "booking.hold": "booking",
    "booking.confirm": "booking",
    "booking.cancel": "booking",
    "fs.list": "file",
    "fs.read": "file",
    "fs.write": "file",
    "fs.move": "file",
    "fs.delete": "file",
    "photo.view": "file",
    "photo.edit": "file",
    "photo.upload": "file",
    "photo.delete": "file",
    "github.repo_get": "github",
    "github.issue_list": "github",
    "github.issue_get": "github",
    "github.issue_create": "github",
    "github.issue_comment": "github",
    "github.pr_list": "github",
    "github.pr_get": "github",
    "github.pr_create": "github",
    "github.file_get": "github",
    "github.file_commit": "github",
    "code.run": "code",
    "code.exec": "code",
    "image.generate": "image",
    "secret.export": "core",
    "account.delete": "core",
}

EXPECTED_SECRETS: dict[str, frozenset[str]] = {
    "web.search": frozenset({"api_key"}),
    "web.fetch": frozenset({"api_key"}),
    "web.download": frozenset({"api_key"}),
    "email.read": frozenset({"token", "refresh_token"}),
    "email.search": frozenset({"token", "refresh_token"}),
    "email.draft": frozenset({"token", "refresh_token"}),
    "email.send": frozenset({"token", "refresh_token"}),
    "whatsapp.read": frozenset({"token"}),
    "whatsapp.send": frozenset({"token"}),
    "whatsapp.react": frozenset({"token"}),
    "booking.search": frozenset({"token", "payment_token"}),
    "booking.hold": frozenset({"token", "payment_token"}),
    "booking.confirm": frozenset({"token", "payment_token"}),
    "booking.cancel": frozenset({"token", "payment_token"}),
    "image.generate": frozenset({"api_key"}),
    "fs.read": frozenset({"token"}),
    "fs.write": frozenset({"token"}),
    "fs.move": frozenset({"token"}),
    "fs.delete": frozenset({"token"}),
    "photo.view": frozenset({"token"}),
    "photo.edit": frozenset({"token"}),
    "photo.upload": frozenset({"token"}),
    "photo.delete": frozenset({"token"}),
    "github.repo_get": frozenset({"token"}),
    "github.issue_list": frozenset({"token"}),
    "github.issue_get": frozenset({"token"}),
    "github.issue_create": frozenset({"token"}),
    "github.issue_comment": frozenset({"token"}),
    "github.pr_list": frozenset({"token"}),
    "github.pr_get": frozenset({"token"}),
    "github.pr_create": frozenset({"token"}),
    "github.file_get": frozenset({"token"}),
    "github.file_commit": frozenset({"token"}),
}


def _engine() -> PermissionEngine:
    return PermissionEngine(ACTION_CATALOG)


def test_catalog_covers_every_action_type():
    catalogued = {s.action_type for s in ACTION_CATALOG}
    enumerated = {a.value for a in ActionType}
    assert catalogued == enumerated
    assert catalogued == set(EXPECTED_RISK)


def test_every_registered_action_risk_tier():
    for action_type, risk in EXPECTED_RISK.items():
        spec = ACTION_CATALOG.get(action_type)
        assert spec is not None, action_type
        assert spec.risk_level == risk, action_type


def test_capability_domains():
    for spec in ACTION_CATALOG:
        if spec.action_type.startswith("device."):
            assert spec.capability_domain == "device", spec.action_type
        else:
            assert spec.capability_domain == EXPECTED_DOMAIN[spec.action_type]


def test_secret_fields_consistency():
    for spec in ACTION_CATALOG:
        expected = EXPECTED_SECRETS.get(spec.action_type, frozenset())
        if spec.capability_domain == "device":
            expected = frozenset({"pairing_token"})
        assert spec.secret_fields == expected, spec.action_type


def test_default_policy_covers_every_risk_tier():
    assert set(DEFAULT_TIER_DEFAULTS) == set(RiskLevel)
    policy = default_policy()
    assert set(policy.tier_defaults) == set(RiskLevel)


def test_exhaustive_default_decisions():
    eng = _engine()
    policy = default_policy()
    for spec in ACTION_CATALOG:
        expected = DEFAULT_TIER_DEFAULTS[spec.risk_level]
        got = eng.evaluate(Action(action_type=spec.action_type), policy)
        assert got == expected, f"{spec.action_type}: {got} != {expected}"


def test_confirm_vs_confirm_strong_boundary():
    policy = default_policy()
    confirm = {RiskLevel.COMMUNICATION, RiskLevel.MUTATING}
    strong = {RiskLevel.FINANCIAL, RiskLevel.BOOKING, RiskLevel.DESTRUCTIVE}
    for spec in ACTION_CATALOG:
        d = policy.tier_defaults[spec.risk_level]
        if spec.risk_level in confirm:
            assert d == Decision.CONFIRM, spec.action_type
        if spec.risk_level in strong:
            assert d == Decision.CONFIRM_STRONG, spec.action_type
        if spec.risk_level is RiskLevel.FORBIDDEN:
            assert d == Decision.DENY, spec.action_type
        if spec.risk_level in (RiskLevel.SAFE, RiskLevel.SENSITIVE):
            assert d == Decision.ALLOW, spec.action_type


def test_unknown_action_denied():
    assert _engine().evaluate(Action(action_type="not.a.thing"), default_policy()) == Decision.DENY


def test_empty_action_type_denied():
    assert _engine().evaluate(Action(action_type=""), default_policy()) == Decision.DENY


def test_missing_policy_denied():
    assert _engine().evaluate(Action(action_type="web.search"), None) == Decision.DENY


def test_malformed_policy_object_denied():
    eng = _engine()
    action = Action(action_type="web.search")
    assert eng.evaluate(action, {"tier_defaults": {}}) == Decision.DENY  # type: ignore[arg-type]
    assert eng.evaluate(action, "nope") == Decision.DENY  # type: ignore[arg-type]


def test_empty_tier_defaults_denied():
    policy = Policy(version=1, tier_defaults={})
    assert _engine().evaluate(Action(action_type="web.search"), policy) == Decision.DENY


def test_unmapped_tier_denied():
    policy = Policy(version=1, tier_defaults={RiskLevel.MUTATING: Decision.CONFIRM})
    # SAFE is unmapped -> DENY
    assert _engine().evaluate(Action(action_type="web.search"), policy) == Decision.DENY


def test_ambiguous_override_denied():
    policy = default_policy()
    policy.overrides["web.search"] = object()  # type: ignore[assignment]
    assert _engine().evaluate(Action(action_type="web.search"), policy) == Decision.DENY


def test_override_predicate_exception_denied():
    class Boom(ActionRule):
        def matches(self, params):
            raise RuntimeError("boom")

    policy = default_policy()
    policy.overrides["web.search"] = Boom(decision=Decision.ALLOW)
    assert _engine().evaluate(Action(action_type="web.search"), policy) == Decision.DENY


FORBIDDEN_ACTIONS = ("secret.export", "account.delete")


def test_forbidden_never_overridden_to_allow_or_confirm():
    eng = _engine()
    for action_type in FORBIDDEN_ACTIONS:
        for decision in (Decision.ALLOW, Decision.CONFIRM, Decision.CONFIRM_STRONG, Decision.DENY):
            policy = default_policy()
            policy.tier_defaults[RiskLevel.FORBIDDEN] = decision
            policy.overrides[action_type] = ActionRule(decision=decision)
            got = eng.evaluate(Action(action_type=action_type), policy)
            assert got == Decision.DENY, f"{action_type} + {decision}"


def test_forbidden_survives_malformed_and_broad_allow():
    eng = _engine()
    for action_type in FORBIDDEN_ACTIONS:
        action = Action(action_type=action_type)
        assert eng.evaluate(action, None) == Decision.DENY
        assert eng.evaluate(action, "bad") == Decision.DENY  # type: ignore[arg-type]
        allow_all = Policy(
            version=99,
            tier_defaults={level: Decision.ALLOW for level in RiskLevel},
            overrides={action_type: ActionRule(decision=Decision.ALLOW)},
        )
        assert eng.evaluate(action, allow_all) == Decision.DENY
