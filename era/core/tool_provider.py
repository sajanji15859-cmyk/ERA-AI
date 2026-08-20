"""The ToolProvider service-provider interface (SPI).

Every future capability — Web, Email, WhatsApp, Booking, File/Photo, Android
device automation, model inference — implements this protocol and registers its
action types with the :class:`~era.core.tool_registry.ToolRegistry`. The
permission/audit core depends only on this protocol, never on a concrete
provider.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ActionResult


@runtime_checkable
class ToolProvider(Protocol):
    """A tool/capability. Implementations own credential access and execution."""

    id: str
    action_types: frozenset[str]

    def validate(self, action: Action) -> None:
        """Pre-flight validation of ``action.params``.

        Raise :class:`ToolError` to reject. Used by the execution service before
        dispatch (e.g. a future WebProvider rejects disallowed URLs here to
        prevent SSRF/private-network access).
        """

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        """Perform the action. Raise :class:`ToolError` on failure.

        Must resolve credentials from its own store (never from ``ctx`` values
        or params) and must not return secrets in the result.
        """
