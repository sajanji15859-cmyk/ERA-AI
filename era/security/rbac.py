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
    #: Phase 3A: start/continue/inspect agent runs.
    AGENT_RUN = "agent.run"
    #: Phase 3C: manage provider secrets (store / rotate / revoke).
    #: Admin-only — day-to-day ``user`` roles never touch the vault.
    VAULT_MANAGE = "vault.manage"
    #: Phase 3G: read the caller's own background job status/results.
    JOBS_READ = "jobs.read"
    #: Phase 3H: manage recurring/scheduled jobs (create / update / delete / toggle).
    SCHEDULES_MANAGE = "schedules.manage"
    SCHEDULES_READ = "schedules.read"
    #: Phase 4D: schedule workflows (create/update/delete/toggle).
    WORKFLOW_SCHEDULE = "workflow.schedule"
    #: Phase 4D: manage workflow templates (publish / list).
    WORKFLOW_TEMPLATES_MANAGE = "workflow.templates.manage"
    #: Phase 4D: operator review surface (awaiting runs, timeline, cross-actor resolve).
    WORKFLOW_REVIEW = "workflow.review"
    #: Phase 4D: read workflows / templates / aggregation. Owner scope for runs.
    WORKFLOW_READ = "workflow.read"


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
    Permission.AGENT_RUN,
    Permission.VAULT_MANAGE,
    Permission.JOBS_READ,
    Permission.SCHEDULES_MANAGE,
    Permission.SCHEDULES_READ,
    Permission.WORKFLOW_SCHEDULE,
    Permission.WORKFLOW_TEMPLATES_MANAGE,
    Permission.WORKFLOW_REVIEW,
    Permission.WORKFLOW_READ,
})

ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ADMIN: ALL_PERMISSIONS,
    Role.USER: frozenset({
        Permission.POLICY_READ,
        Permission.PROVIDERS_READ,
        Permission.ACTIONS_EVALUATE,
        Permission.ACTIONS_EXECUTE,
        Permission.ACTIONS_CONFIRM,
        Permission.AGENT_RUN,
        Permission.JOBS_READ,
        Permission.SCHEDULES_MANAGE,
        Permission.SCHEDULES_READ,
        Permission.WORKFLOW_SCHEDULE,
        Permission.WORKFLOW_READ,
    }),
}

#: Capability domains each role may act on. Both role entries are explicit so
#: an unknown future domain remains denied until deliberately reviewed (fail
#: closed). ``device`` is deliberately NOT granted to the default ``user``
#: role: device automation remains an admin-only boundary.
_ALL_ACTION_DOMAINS = frozenset({
    "core",
    "web",
    "browser",
    "email",
    "whatsapp",
    "booking",
    "file",
    "device",
    "github",
    "code",
    "image",
})

ACTION_DOMAIN_ALLOWLIST: dict[Role, frozenset[str]] = {
    Role.ADMIN: _ALL_ACTION_DOMAINS,
    Role.USER: frozenset({
        "core",
        "web",
        "browser",
        "email",
        "whatsapp",
        "booking",
        "file",
        "github",
        "code",
        "image",
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

    ``None``/unknown domain or unknown role -> False (fail closed). Admin has
    every explicitly reviewed domain, not a wildcard for future domains.
    """
    r = coerce_role(role)
    if r is None or not domain:
        return False
    allowed = ACTION_DOMAIN_ALLOWLIST.get(r, frozenset())
    return domain in allowed
