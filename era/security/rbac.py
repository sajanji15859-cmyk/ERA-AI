"""Role-based authorization primitives (Phase 2A).

This is the *outer* gate. It authorizes WHO may reach a protected operation and
which capability domains a role may act on. It is layered strictly **in front of**
the existing permission engine — it never replaces it. An action still must pass
BOTH this RBAC layer AND the permission engine + confirmation flow + execution
gate before any provider runs. Unknown roles and unknown domains are always
denied (fail closed).
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    """User roles. Unknown role strings are always treated as having no
    permissions (the lookup helpers return False / empty for them)."""

    ADMIN = "admin"
    USER = "user"


class Permission:
    """Capability identifiers granted to roles.

    ``admin`` holds every permission; ``user`` holds the day-to-day agent
    operator permissions but NOT audit-read, policy-write or account/key
    management (those remain admin-only in Phase 2A).
    """

    POLICY_READ = "policy.read"
    POLICY_WRITE = "policy.write"
    AUDIT_READ = "audit.read"
    PROVIDERS_READ = "providers.read"
    ACTIONS_EVALUATE = "actions.evaluate"
    ACTIONS_EXECUTE = "actions.execute"
    ACTIONS_CONFIRM = "actions.confirm"
    USERS_MANAGE = "users.manage"
    API_KEYS_MANAGE = "api_keys.manage"


ALL_PERMISSIONS: frozenset[str] = frozenset({
    Permission.POLICY_READ,
    Permission.POLICY_WRITE,
    Permission.AUDIT_READ,
    Permission.PROVIDERS_READ,
    Permission.ACTIONS_EVALUATE,
    Permission.ACTIONS_EXECUTE,
    Permission.ACTIONS_CONFIRM,
    Permission.USERS_MANAGE,
    Permission.API_KEYS_MANAGE,
})

ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ADMIN: ALL_PERMISSIONS,
    Role.USER: frozenset({
        Permission.POLICY_READ,
        Permission.PROVIDERS_READ,
        Permission.ACTIONS_EVALUATE,
        Permission.ACTIONS_EXECUTE,
        Permission.ACTIONS_CONFIRM,
    }),
}

#: Capability domains each role may act on. ``None`` = wildcard (all domains).
#: ``device`` is deliberately NOT granted to the default ``user`` role: device
#: automation is a high-risk boundary and stays admin-only until a dedicated
#: on-device capability phase.
ACTION_DOMAIN_ALLOWLIST: dict[Role, frozenset[str] | None] = {
    Role.ADMIN: None,  # wildcard: every capability domain
    Role.USER: frozenset({
        "core",
        "web",
        "email",
        "whatsapp",
        "booking",
        "file",
    }),
}


def coerce_role(value: str | Role | None) -> Role | None:
    """Return the validated :class:`Role`, or ``None`` for an unknown value.

    Unknown/malformed roles map to ``None`` so callers fail closed.
    """
    if isinstance(value, Role):
        return value
    try:
        return Role(str(value))
    except (TypeError, ValueError):
        return None


def role_has_permission(role: Role | str | None, permission: str) -> bool:
    """True iff ``role`` (or any string) grants ``permission``.

    Unknown role or unknown permission -> False (fail closed).
    """
    r = coerce_role(role)
    if r is None:
        return False
    return permission in ROLE_PERMISSIONS.get(r, frozenset())


def role_domain_allowed(role: Role | str | None, domain: str | None) -> bool:
    """True iff ``role`` may act on capability domain ``domain``.

    ``None``/unknown domain or unknown role -> False (fail closed). Admin is a
    wildcard (``None`` in the allowlist means *everything*).
    """
    r = coerce_role(role)
    if r is None or not domain:
        return False
    allowed = ACTION_DOMAIN_ALLOWLIST.get(r)
    if allowed is None:
        # ADMIN wildcard.
        return True
    return domain in allowed
