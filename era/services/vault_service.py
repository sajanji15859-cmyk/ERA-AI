"""Credential vault service (Phase 3C).

Manages provider secrets end-to-end:

* **store_or_rotate_secret** — encrypt (AES-256-GCM) and persist a secret, or
  rotate an existing one (bumps ``revision``, re-activates a revoked row).
* **resolve_ref** — the ONLY value-returning API. Providers (the owners of a
  credential) call it with an opaque ``vault:<domain>/<name>`` reference at
  execution time. The agent / LLM / permission / audit core never call it —
  they only ever see the reference string, which is what keeps the secret
  boundary intact.
* **revoke_secret / list_secrets** — metadata-only management.

Every mutation **and every resolution** (success or failure) is appended to
the tamper-evident audit log with metadata only (domain / name / ref —
*never* the value). Fail-closed: a disabled vault (no master key), an
unknown / revoked reference, or a tampered ciphertext all raise
:class:`~era.security.vault.VaultError` — there is no degraded mode.
"""

from __future__ import annotations

import uuid

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.enums import Decision, Outcome, RiskLevel
from era.core.util import utcnow_iso
from era.db import transaction
from era.models import VaultSecret
from era.security.redaction import redact
from era.security.vault import (
    MAX_VAULT_VALUE_LENGTH,
    VaultError,
    is_vault_ref,
    parse_vault_ref,
    validate_vault_part,
    vault_decrypt,
    vault_encrypt,
)

#: Actor id used for vault ops that carry no user context (e.g. provider
#: resolutions happening inside a dispatch).
SYSTEM_ACTOR = "vault-system"


class VaultService:
    def __init__(self, session_factory, vault_repo, audit_service, policy_service,
                 settings, master_key: bytes | None = None):
        self.session_factory = session_factory
        self.vault_repo = vault_repo
        self.audit_service = audit_service
        self.policy_service = policy_service
        self.settings = settings
        self.master_key = master_key

    # -- state -----------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        """True iff a valid master key is configured (fail-closed default)."""
        return self.master_key is not None

    def _require_enabled(self) -> None:
        if self.master_key is None:
            raise VaultError(
                "credential vault disabled: set ERA_VAULT_MASTER_KEY "
                "(32 bytes, hex or base64)",
                code="disabled",
            )

    def _policy_version(self) -> int:
        policy = self.policy_service.get_current()
        return policy.version if policy else 0

    def _audit(self, *, op: str, domain: str, name: str, actor_id: str,
               outcome: Outcome, error_code: str | None = None) -> None:
        """Append a vault op to the audit log (its own durable transaction).

        Params carry only domain/name — secret values must never appear in an
        audit row, so redaction is applied on top as a belt-and-braces lock.
        """
        risk = RiskLevel.SENSITIVE if op == "vault.resolve" else RiskLevel.MUTATING
        with transaction(self.session_factory) as session:
            self.audit_service.record(
                session,
                action=Action(action_type=op,
                              params=redact({"domain": domain, "name": name})),
                ctx=ExecutionContext(actor_id=actor_id),
                risk_level=risk,
                decision=Decision.ALLOW,
                outcome=outcome,
                policy_version=self._policy_version(),
                error_code=error_code,
                capability_domain=domain,
            )

    # -- management ----------------------------------------------------------
    def store_or_rotate_secret(self, *, domain: str, name: str, value: str,
                               actor_id: str,
                               owner_user_id: str | None = None) -> VaultSecret:
        """Create a new secret, or rotate an existing (active or revoked) one.

        Returns the metadata row — the plaintext ``value`` is not returned,
        stored in plaintext, or logged anywhere.
        """
        domain = validate_vault_part(domain, "domain")
        name = validate_vault_part(name, "name")
        owner_was_explicit = owner_user_id is not None
        owner_user_id = owner_user_id or actor_id
        if not isinstance(owner_user_id, str) or not owner_user_id:
            raise VaultError("owner_user_id must be non-empty", code="validation")
        if not isinstance(value, str) or not value:
            raise VaultError("value must be a non-empty string", code="validation")
        if len(value) > MAX_VAULT_VALUE_LENGTH:
            raise VaultError(f"value too long (max {MAX_VAULT_VALUE_LENGTH} chars)",
                             code="validation")
        self._require_enabled()

        ciphertext, nonce = vault_encrypt(value, self.master_key, domain, name)
        with transaction(self.session_factory) as session:
            existing = self.vault_repo.get(session, domain, name)
            if existing is None:
                secret = VaultSecret(
                    id=uuid.uuid4().hex,
                    domain=domain,
                    name=name,
                    owner_user_id=owner_user_id,
                    ciphertext=ciphertext,
                    nonce=nonce,
                    value_length=len(value),
                    revision=1,
                )
                self.vault_repo.create(session, secret)
                op = "vault.store"
            else:
                existing.ciphertext = ciphertext
                existing.nonce = nonce
                if owner_was_explicit:
                    existing.owner_user_id = owner_user_id
                existing.value_length = len(value)
                existing.revision = (existing.revision or 1) + 1
                existing.revoked_at = None  # re-store revives a revoked row
                existing.updated_at = utcnow_iso()
                self.vault_repo.update(session, existing)
                secret = existing
                op = "vault.rotate"
        self._audit(op=op, domain=domain, name=name, actor_id=actor_id,
                    outcome=Outcome.EXECUTED)
        return secret

    def revoke_secret(self, *, domain: str, name: str, actor_id: str) -> VaultSecret:
        """Soft-revoke a secret: it can no longer be resolved. Returns the row."""
        domain = validate_vault_part(domain, "domain")
        name = validate_vault_part(name, "name")
        self._require_enabled()
        with transaction(self.session_factory) as session:
            secret = self.vault_repo.get(session, domain, name)
            if secret is None:
                raise VaultError(f"no such vault secret: {domain}/{name}",
                                 code="not_found")
            if secret.revoked_at is None:
                secret.revoked_at = utcnow_iso()
                self.vault_repo.update(session, secret)
        self._audit(op="vault.revoke", domain=domain, name=name, actor_id=actor_id,
                    outcome=Outcome.EXECUTED)
        return secret

    def get_secret(self, *, domain: str, name: str) -> VaultSecret | None:
        """Metadata lookup (no value). ``None`` if absent."""
        domain = validate_vault_part(domain, "domain")
        name = validate_vault_part(name, "name")
        with transaction(self.session_factory) as session:
            return self.vault_repo.get(session, domain, name)

    def list_secrets(self, domain: str | None = None) -> list[VaultSecret]:
        """Metadata for all (optionally domain-filtered) secrets. No values."""
        if domain is not None:
            domain = validate_vault_part(domain, "domain")
        with transaction(self.session_factory) as session:
            return self.vault_repo.list(session, domain)

    # -- resolution (providers only) -------------------------------------------
    def resolve_ref(self, ref: str, *, actor_id: str = SYSTEM_ACTOR,
                    require_owner: bool = False) -> str:
        """Resolve a ``vault:<domain>/<name>`` reference to its plaintext.

        Intended for providers at execution time. Every call — success or
        failure — is audited. Fail-closed on: non-reference input, disabled
        vault, unknown secret, revoked secret, tampered ciphertext.
        """
        if not is_vault_ref(ref):
            raise VaultError("not a vault reference (expected 'vault:<domain>/<name>')",
                             code="validation")
        parsed = parse_vault_ref(ref)
        if parsed is None:
            raise VaultError("malformed vault reference", code="validation")
        domain, name = parsed
        self._require_enabled()

        with transaction(self.session_factory) as session:
            secret = self.vault_repo.get(session, domain, name)
            if secret is None:
                self._audit(op="vault.resolve", domain=domain, name=name,
                            actor_id=actor_id, outcome=Outcome.FAILED,
                            error_code="UNKNOWN")
                raise VaultError(f"unknown vault secret: {domain}/{name}",
                                 code="unknown")
            if require_owner and secret.owner_user_id != actor_id:
                self._audit(op="vault.resolve", domain=domain, name=name,
                            actor_id=actor_id, outcome=Outcome.FAILED,
                            error_code="AUTH")
                raise VaultError("vault secret belongs to another actor", code="auth")
            if secret.revoked_at is not None:
                self._audit(op="vault.resolve", domain=domain, name=name,
                            actor_id=actor_id, outcome=Outcome.FAILED,
                            error_code="REVOKED")
                raise VaultError(f"vault secret revoked: {domain}/{name}",
                                 code="revoked")
            try:
                value = vault_decrypt(bytes(secret.ciphertext), bytes(secret.nonce),
                                      self.master_key, domain, name)
            except VaultError:
                self._audit(op="vault.resolve", domain=domain, name=name,
                            actor_id=actor_id, outcome=Outcome.FAILED,
                            error_code="TAMPERED")
                raise
        self._audit(op="vault.resolve", domain=domain, name=name, actor_id=actor_id,
                    outcome=Outcome.EXECUTED)
        return value


class VaultRefResolver:
    """Lazy adapter letting providers resolve vault refs.

    Providers are constructed *before* the container (and thus before the
    :class:`VaultService` they need) exists, so they are wired with this
    adapter and :meth:`attach` is called once the container is built. Before
    attach (or with a disabled vault) every resolution fails closed — no
    secret can ever be resolved through an unwired adapter.
    """

    def __init__(self, vault_service=None):
        self._vault_service = vault_service

    def attach(self, vault_service) -> None:
        self._vault_service = vault_service

    def resolve_ref(self, ref: str, *, actor_id: str = SYSTEM_ACTOR,
                    require_owner: bool = False) -> str:
        if self._vault_service is None:
            raise VaultError("vault resolver is not attached", code="disabled")
        return self._vault_service.resolve_ref(
            ref, actor_id=actor_id, require_owner=require_owner,
        )
