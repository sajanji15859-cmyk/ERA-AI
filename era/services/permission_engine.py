"""The permission engine — a pure, side-effect-free evaluator.

``(action, policy) -> Decision`` with no I/O, so it is deterministic and free of
TOCTOU between evaluation and persistence. Every ambiguity defaults to DENY.
"""

from __future__ import annotations

from era.core.action import Action
from era.core.enums import Decision
from era.core.tool_registry import ActionCatalog
from era.schemas.policy import Policy


class PermissionEngine:
    def __init__(self, catalog: ActionCatalog):
        self.catalog = catalog

    def evaluate(self, action: Action, policy: Policy | None) -> Decision:
        # Missing/malformed policy -> deny all (fail closed).
        if policy is None:
            return Decision.DENY

        # Unknown action type -> deny (fail closed).
        spec = self.catalog.get(action.action_type)
        if spec is None:
            return Decision.DENY

        # Explicit per-action override (with optional param predicate).
        rule = policy.overrides.get(action.action_type)
        if rule is not None and rule.matches(action.params):
            return rule.decision

        # Tier default (fall back to deny if the tier is somehow unmapped).
        return policy.tier_defaults.get(spec.risk_level, Decision.DENY)
