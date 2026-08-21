"""Authentication + authorization service (Phase 2A).

Responsibilities:
* **Authenticate** an API key presented on a request, resolving it (by SHA-256
  hash) to a real, server-side :class:`User`. The raw key is never stored; the
  hash is. Disabled users and revoked keys are rejected.
* **Authorize** — check role permissions and capability-domain allowlists.
* **Manage** users and API keys (used by the admin API and the CLI).

The service depends only on repository protocols (consistent with every other
service) and on the action catalog (to map an action type to its capability
domain for the domain allowlist).
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass

from era.core.tool_registry import ActionCatalog
from era.core.util import utcnow_iso
from era.db import transaction
from era.models import ApiKey, User
from era.repositories.base import ApiKeyRepo, UserRepo
from era.security.exceptions import AuthenticationError, AuthorizationError
from era.security.hashing import sha256_hex
from era.security.rbac import (
    Permission,
    Role,
    role_domain_allowed,
    role_has_permission,
)
from era.security.validation import validate_name

DEFAULT_ADMIN_USERNAME = "admin"
KEY_PREFIX = "era_"


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """The authenticated identity derived server-side from a presented key.

    ``actor_id`` is the user id (server-derived, not client-supplied).
    ``session_id`` is the API-key id that authenticated the request — a stable
    per-client identity used as the session for execution context.
    """

    user: User
    api_key: ApiKey

    @property
    def actor_id(self) -> str:
        return self.user.id

    @property
    def session_id(self) -> str:
        return self.api_key.id


def generate_api_key() -> tuple[str, str, str]:
    """Generate (raw_key, sha256(raw_key), prefix). The raw key is shown to the
    operator exactly once and never stored; only the hash is persisted."""
    secret = secrets.token_urlsafe(32)
    raw = f"{KEY_PREFIX}{secret}"
    return raw, sha256_hex(raw), secret[:10]


class AuthService:
    def __init__(self, session_factory, user_repo: UserRepo, api_key_repo: ApiKeyRepo,
                 catalog: ActionCatalog, settings):
        self.session_factory = session_factory
        self.user_repo = user_repo
        self.api_key_repo = api_key_repo
        self.catalog = catalog
        self.settings = settings

    # -- bootstrap -----------------------------------------------------------
    def bootstrap_admin(self) -> None:
        """Ensure the default admin user exists (idempotent).

        Only the *user record* is created here — the operator must mint an API
        key via the CLI/API (the raw key is only ever shown once at creation).
        """
        with transaction(self.session_factory) as session:
            if self.user_repo.get_by_username(session, DEFAULT_ADMIN_USERNAME) is None:
                user = User(
                    id=uuid.uuid4().hex,
                    username=DEFAULT_ADMIN_USERNAME,
                    display_name="System Administrator",
                    role=Role.ADMIN.value,
                    disabled=False,
                    credential_refs={},
                )
                self.user_repo.create(session, user)

    # -- authentication ------------------------------------------------------
    def authenticate_token(self, token: str | None) -> AuthenticatedPrincipal:
        """Authenticate a raw API token -> :class:`AuthenticatedPrincipal`.

        Fail closed: a missing, unknown, revoked, or disabled-owner token is an
        :class:`AuthenticationError`. We never fall back to anonymous access.
        """
        if not token or not isinstance(token, str) or not token:
            raise AuthenticationError("missing API token")
        key_hash = sha256_hex(token)
        with transaction(self.session_factory) as session:
            key = self.api_key_repo.get_by_hash(session, key_hash)
            if key is None:
                raise AuthenticationError("unknown API token")
            if key.revoked_at is not None:
                raise AuthenticationError("API token revoked")
            user = self.user_repo.get(session, key.user_id)
            if user is None or user.disabled:
                raise AuthenticationError("user disabled or not found")
            key.last_used_at = utcnow_iso()
            self.api_key_repo.update(session, key)
        return AuthenticatedPrincipal(user=user, api_key=key)

    # -- authorization -------------------------------------------------------
    def require_permission(self, user: User, permission: str) -> None:
        """Raise :class:`AuthorizationError` unless the user's role grants it."""
        if user is None or user.disabled:
            raise AuthorizationError("user not active")
        if not role_has_permission(user.role, permission):
            raise AuthorizationError(f"missing permission: {permission}")

    def authorize_action(self, user: User, action_type: str) -> None:
        """Raise :class:`AuthorizationError` unless the role may act on the
        action's capability domain. Unknown action/domain -> denied (fail closed).

        This is the RBAC *outer* gate. The permission engine still independently
        gates the same action (unknown action -> DENY), so the two layers agree
        on fail-closed semantics without weakening either.
        """
        if user is None or user.disabled:
            raise AuthorizationError("user not active")
        spec = self.catalog.get(action_type)
        domain = spec.capability_domain if spec else None
        if not role_domain_allowed(user.role, domain):
            raise AuthorizationError(f"role not allowed for action: {action_type}")

    def is_admin(self, user: User) -> bool:
        return role_has_permission(user.role, Permission.USERS_MANAGE)

    # -- user management -----------------------------------------------------
    def create_user(self, *, username: str, role: str, display_name: str | None = None,
                    disabled: bool = False, credential_refs: dict | None = None) -> User:
        username = validate_name(username)
        if display_name is not None:
            validate_name(display_name)
        try:
            validated_role = Role(role)
        except ValueError:
            raise ValueError(f"invalid role: {role!r}") from None
        with transaction(self.session_factory) as session:
            if self.user_repo.get_by_username(session, username) is not None:
                raise ValueError(f"username already exists: {username!r}")
            user = User(
                id=uuid.uuid4().hex,
                username=username,
                display_name=display_name,
                role=validated_role.value,
                disabled=disabled,
                credential_refs=dict(credential_refs or {}),
            )
            self.user_repo.create(session, user)
        return user

    def get_user(self, user_id: str) -> User | None:
        with transaction(self.session_factory) as session:
            return self.user_repo.get(session, user_id)

    def get_user_by_username(self, username: str) -> User | None:
        with transaction(self.session_factory) as session:
            return self.user_repo.get_by_username(session, username)

    def list_users(self) -> list[User]:
        with transaction(self.session_factory) as session:
            return self.user_repo.list(session)

    def set_user_disabled(self, user_id: str, disabled: bool) -> User | None:
        with transaction(self.session_factory) as session:
            user = self.user_repo.get(session, user_id)
            if user is None:
                return None
            user.disabled = disabled
            self.user_repo.update(session, user)
        return user

    # -- API-key management --------------------------------------------------
    def create_api_key(self, user_id: str, name: str) -> tuple[ApiKey, str]:
        """Create a key for ``user_id``; return (row, raw_key). Raw key is shown
        once and never stored. Raises ``ValueError`` if the user does not exist.
        """
        name = validate_name(name)
        with transaction(self.session_factory) as session:
            if self.user_repo.get(session, user_id) is None:
                raise ValueError(f"no such user: {user_id!r}")
            raw, key_hash, prefix = generate_api_key()
            key = ApiKey(
                id=uuid.uuid4().hex,
                user_id=user_id,
                name=name,
                key_hash=key_hash,
                prefix=prefix,
            )
            self.api_key_repo.create(session, key)
        return key, raw

    def list_keys(self, user_id: str | None = None) -> list[ApiKey]:
        with transaction(self.session_factory) as session:
            if user_id is not None:
                return self.api_key_repo.list_by_user(session, user_id)
            return self.api_key_repo.list(session)

    def revoke_key(self, key_id: str) -> ApiKey | None:
        with transaction(self.session_factory) as session:
            key = self.api_key_repo.get(session, key_id)
            if key is None:
                return None
            if key.revoked_at is None:
                key.revoked_at = utcnow_iso()
                self.api_key_repo.update(session, key)
        return key
