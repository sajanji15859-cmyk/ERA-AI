"""The permission engine — a pure, side-effect-free evaluator.

``(action, policy) -> Decision`` with no I/O, so it is deterministic and free of
TOCTOU between evaluation and persistence. Every ambiguity defaults to DENY.
"""

from __future__ import annotations

from era.core.action import Action
from era.core.enums import Decision, RiskLevel
from era.core.tool_registry import ActionCatalog
from era.schemas.policy import Policy


class PermissionEngine:
    def __init__(self, catalog: ActionCatalog):
        self.catalog = catalog

    def evaluate(self, action: Action, policy: Policy | None) -> Decision:
        # Missing/malformed policy -> deny all (fail closed).
        if policy is None or not isinstance(policy, Policy):
            return Decision.DENY
        if not action.action_type or not isinstance(action.action_type, str):
            return Decision.DENY

        # Unknown action type -> deny (fail closed).
        spec = self.catalog.get(action.action_type)
        if spec is None:
            return Decision.DENY

        # FORBIDDEN is override-proof: never ALLOW / CONFIRM / CONFIRM_STRONG.
        if spec.risk_level is RiskLevel.FORBIDDEN:
            return Decision.DENY

        # Incomplete / unmapped tier table is ambiguous -> DENY.
        if not policy.tier_defaults:
            return Decision.DENY

        # Explicit per-action override (with optional param predicate).
        rule = policy.overrides.get(action.action_type)
        if rule is not None:
            if not hasattr(rule, "matches") or not hasattr(rule, "decision"):
                return Decision.DENY
            try:
                matched = rule.matches(action.params)
            except Exception:  # noqa: BLE001 — fail closed on predicate errors
                return Decision.DENY
            if matched:
                decision = rule.decision
                return decision if isinstance(decision, Decision) else Decision.DENY

        # Tier default (fall back to deny if the tier is somehow unmapped).
        decision = policy.tier_defaults.get(spec.risk_level, Decision.DENY)
        return decision if isinstance(decision, Decision) else Decision.DENY
