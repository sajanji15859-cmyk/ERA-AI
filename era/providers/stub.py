"""StubProvider — a no-op executor standing in for every future capability.

Registered for all catalogued action types so the permission gate, confirmation
flow and audit log can be exercised end-to-end in Phase 1C without any real
network, messaging, booking, cloud or device transport. It performs no real
work and returns a deterministic canned result.
"""

from __future__ import annotations

from collections.abc import Iterable

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult
from era.registry.actions import ActionType


class StubProvider:
    id = "stub"
    #: Class-level default (unchanged since 1C): the stub claims every
    #: catalogued action type.
    action_types = frozenset(a.value for a in ActionType)

    def __init__(self, exclude: Iterable[str] | None = None):
        # Real providers withdraw the action types they own by constructing the
        # stub with an iterable (list/set/frozenset all work). The instance
        # attribute then shadows the class default. Default construction keeps
        # legacy all-stub behavior for deliberately offline containers.
        excluded = frozenset(exclude or ())
        if excluded:
            self.action_types = frozenset(a.value for a in ActionType) - excluded

    def validate(self, action: Action) -> None:
        # No validation constraints for the stub.
        return None

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        return ActionResult(
            success=True,
            summary=f"stub executed {action.action_type}",
            data={"provider": self.id},
        )

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.1.0",
            display_name="Stub (offline no-op)",
            is_stub=True,
            capabilities=("noop",),
        )
