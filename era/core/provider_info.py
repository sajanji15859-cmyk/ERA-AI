"""Provider introspection metadata (Phase 1E).

:class:`ProviderInfo` is the provider-agnostic description surfaced to the
registry, API and diagnostics. :func:`describe_provider` extracts it from any
:class:`~era.core.tool_provider.ToolProvider` — including legacy providers that
do not implement ``describe()`` — so introspection never breaks an existing
provider.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from era.core.tool_provider import ToolProvider


@dataclass(frozen=True)
class ProviderInfo:
    """Static, non-secret description of a registered provider."""

    id: str
    action_types: frozenset[str]
    version: str = "unknown"
    #: Human-readable label for diagnostics/UI.
    display_name: str = ""
    #: True only for offline/no-op test doubles (stub/mock). Never True for a
    #: real networked provider.
    is_stub: bool = False
    #: Free-form, non-secret capabilities metadata.
    capabilities: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action_types": sorted(self.action_types),
            "version": self.version,
            "display_name": self.display_name,
            "is_stub": self.is_stub,
            "capabilities": list(self.capabilities),
        }


def describe_provider(provider: ToolProvider) -> ProviderInfo:
    """Return a :class:`ProviderInfo` for ``provider``.

    A provider MAY implement ``describe()`` returning a :class:`ProviderInfo`
    (or a mapping of its fields). If it does not, a safe default is synthesised
    from ``provider.id`` and ``provider.action_types`` so introspection is
    always available and never raises.
    """

    pid = getattr(provider, "id", "unknown")
    action_types = getattr(provider, "action_types", frozenset())
    if not isinstance(action_types, frozenset):
        action_types = frozenset(action_types)

    describe = getattr(provider, "describe", None)
    if callable(describe):
        try:
            info = describe()
        except Exception:  # noqa: BLE001 — a buggy describe() must not break introspection
            info = None
        if isinstance(info, ProviderInfo):
            return info
        if isinstance(info, dict):
            return ProviderInfo(
                id=str(info.get("id", pid)),
                action_types=frozenset(info.get("action_types", action_types)),
                version=str(info.get("version", "unknown")),
                display_name=str(info.get("display_name", "")),
                is_stub=bool(info.get("is_stub", False)),
                capabilities=tuple(info.get("capabilities", ())),
            )

    return ProviderInfo(
        id=str(pid),
        action_types=action_types,
        version=_attr(provider, "version", "unknown"),
        display_name=_attr(provider, "display_name", str(pid)),
        is_stub=_attr(provider, "is_stub", False),
        capabilities=tuple(_attr(provider, "capabilities", ())),
    )


def _attr(obj: Any, name: str, default: Any) -> Any:
    value = getattr(obj, name, default)
    return value if value is not None else default
