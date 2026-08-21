"""Reusable ToolProvider SPI contract.

Future providers (Web, Email, WhatsApp, Booking, File/Photo, Android) should
pass ``assert_provider_contract`` without changing this module. The suite is
offline: it never opens sockets, reads credentials, or performs real work.
"""

from __future__ import annotations

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ActionResult, ToolError
from era.core.tool_provider import ToolProvider
from era.registry.actions import ACTION_CATALOG
from era.security.redaction import REDACTED

# Substrings that must never appear in a provider result payload.
_SECRET_FRAGMENTS = ("sk-", "password", "oauth", "Bearer ", "secret-value")


def assert_provider_contract(provider: object, *, sample_action: Action | None = None) -> None:
    """Assert ``provider`` satisfies the ToolProvider SPI.

    Parameters
    ----------
    provider:
        Any object claiming to be a ToolProvider.
    sample_action:
        Optional action to exercise ``validate`` / ``execute``. Defaults to the
        first catalogued action the provider declares, or ``stub.noop``.
    """
    assert isinstance(provider, ToolProvider)
    assert isinstance(provider.id, str) and provider.id, "provider.id must be a non-empty str"
    assert isinstance(provider.action_types, frozenset) and provider.action_types
    assert all(isinstance(t, str) and t for t in provider.action_types)

    # Providers may only claim catalogued types (or tests will notice drift).
    unknown = [t for t in provider.action_types if ACTION_CATALOG.get(t) is None]
    assert not unknown, f"uncatalogued action types: {unknown}"

    action = sample_action or _pick_action(provider)
    assert action.action_type in provider.action_types

    # validate must be side-effect-free enough to call twice, and must not
    # require network. ToolError is allowed (params rejected); other errors
    # are contract violations.
    try:
        provider.validate(action)
        provider.validate(action)
    except ToolError:
        pass

    ctx = ExecutionContext(actor_id="contract-test", credentials={"refs": {"test": "opaque-ref"}})
    try:
        result = provider.execute(action, ctx)
    except ToolError:
        return  # failure is a valid contract outcome

    assert isinstance(result, ActionResult)
    assert isinstance(result.success, bool)
    assert isinstance(result.summary, str)
    assert isinstance(result.data, dict)
    blob = result.model_dump_json()
    assert REDACTED not in action.action_type  # sanity
    for frag in _SECRET_FRAGMENTS:
        assert frag not in blob, f"secret fragment {frag!r} leaked in result"
    assert "pairing_token" not in blob
    assert "refresh_token" not in blob


def _pick_action(provider) -> Action:
    if "stub.noop" in provider.action_types:
        return Action(action_type="stub.noop")
    first = next(iter(sorted(provider.action_types)))
    return Action(action_type=first)
