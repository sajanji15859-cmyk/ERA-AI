"""Policy document schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from era.core.enums import Decision, RiskLevel


class ActionRule(BaseModel):
    """An explicit per-action policy rule, optionally scoped by a param predicate."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision
    when: dict[str, Any] | None = None  # simple equality predicate on params

    def matches(self, params: dict[str, Any]) -> bool:
        if self.when is None:
            return True
        return all(params.get(k) == v for k, v in self.when.items())


class Policy(BaseModel):
    """A versioned permission policy document."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    tier_defaults: dict[RiskLevel, Decision]
    overrides: dict[str, ActionRule] = Field(default_factory=dict)
    missing_policy_default: Decision = Decision.DENY


class PolicyOut(BaseModel):
    version: int
    document: Policy
    created_at: datetime | str
    changed_by: str
