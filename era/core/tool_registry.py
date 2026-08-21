"""Static action catalog + runtime provider wiring."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from era.core.enums import RiskLevel
from era.core.provider_info import ProviderInfo, describe_provider
from era.core.tool_provider import ToolProvider


@dataclass(frozen=True)
class ActionSpec:
    """Static description of an action type: risk, domain, secret fields, schema."""

    action_type: str
    risk_level: RiskLevel
    capability_domain: str
    secret_fields: frozenset[str] = field(default_factory=frozenset)
    param_schema: dict[str, Any] | None = None


class ActionCatalog:
    """Authoritative catalog of known action types.

    Any action type not present here is *unknown* and therefore DENYed by the
    permission engine (fail closed).
    """

    def __init__(self, specs: Iterable[ActionSpec]):
        self._specs: dict[str, ActionSpec] = {s.action_type: s for s in specs}

    def get(self, action_type: str) -> ActionSpec | None:
        return self._specs.get(action_type)

    def __contains__(self, action_type: str) -> bool:
        return action_type in self._specs

    def __iter__(self):
        return iter(self._specs.values())


class ToolRegistry:
    """Runtime wiring: maps ``action_type`` -> ``ToolProvider`` instance.

    Distinct from the catalog: the catalog says *what* an action is and how
    risky it is; the registry says *which provider* (if any) currently handles
    it. An action can be catalogued but unregistered (no provider) — it will be
    authorized but then REJECTED at dispatch, never executed.
    """

    def __init__(self):
        self._providers: dict[str, ToolProvider] = {}
        self._by_id: dict[str, ToolProvider] = {}

    def register(self, provider: ToolProvider) -> None:
        if provider.id in self._by_id:
            raise ValueError(f"provider {provider.id!r} is already registered")
        for action_type in provider.action_types:
            if action_type in self._providers:
                raise ValueError(f"action_type {action_type!r} is already registered")
            self._providers[action_type] = provider
        self._by_id[provider.id] = provider

    def get(self, action_type: str) -> ToolProvider | None:
        return self._providers.get(action_type)

    def get_provider(self, provider_id: str) -> ToolProvider | None:
        """Look up a provider instance by its ``id``."""
        return self._by_id.get(provider_id)

    def describe(self, action_type: str) -> ProviderInfo | None:
        """Return metadata for the provider handling ``action_type``, if any."""
        provider = self.get(action_type)
        return describe_provider(provider) if provider is not None else None

    def describe_all(self) -> list[ProviderInfo]:
        """Return metadata for every registered provider (de-duplicated by id)."""
        return [describe_provider(p) for p in self._by_id.values()]

    @property
    def provider_ids(self) -> frozenset[str]:
        return frozenset(self._by_id)

    def list_providers(self) -> list[ToolProvider]:
        """All registered provider instances (de-duplicated by id)."""
        return list(self._by_id.values())
