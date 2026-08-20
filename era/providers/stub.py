"""StubProvider — a no-op executor standing in for every future capability.

Registered for all catalogued action types so the permission gate, confirmation
flow and audit log can be exercised end-to-end in Phase 1C without any real
network, messaging, booking, cloud or device transport. It performs no real
work and returns a deterministic canned result.
"""

from __future__ import annotations

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ActionResult
from era.registry.actions import ActionType


class StubProvider:
    id = "stub"
    action_types = frozenset(a.value for a in ActionType)

    def validate(self, action: Action) -> None:
        # No validation constraints for the stub.
        return None

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        return ActionResult(
            success=True,
            summary=f"stub executed {action.action_type}",
            data={"provider": self.id},
        )
