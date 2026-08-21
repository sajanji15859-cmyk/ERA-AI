"""Credential vault crypto core (Phase 3C).

The vault is the ONLY place provider secrets are stored. Plaintext secrets
are encrypted at rest with **AES-256-GCM** (authenticated encryption) under an
operator-supplied 32-byte master key that is env-only and never committed.

The secret boundary is preserved exactly as the audit requires it:

* The core (agent / LLM / permission / audit layers) never sees plaintext
  values — only opaque *references* of the form ``vault:<domain>/<name>``.
* Providers (the owners of the credential) resolve a reference against the
  vault at execution time. The plaintext exists only for the duration of that
  single resolution.

Fail-closed invariants:

* No valid master key -> the vault is **disabled**: nothing can be stored and
  nothing can be resolved (every operation raises :class:`VaultError`).
* GCM authentication: a tampered ciphertext or a nonce/row mismatch is
  rejected, never "best-effort" decrypted.
* Ciphertext is bound to ``(domain, name)`` via AAD, so a ciphertext can
  never be swapped between two vault rows.
* Malformed master keys (wrong length / alphabet) are treated as *absent*,
  i.e. the vault stays disabled — a broken key must not become a working
  (wrong) key.
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: Algorithm identifier persisted with every vault row.
ALGORITHM = "AES-256-GCM"

#: ``vault:`` is the only reference prefix the resolver understands.
VAULT_REF_PREFIX = "vault:"

#: Master key length in bytes (AES-256).
MASTER_KEY_LENGTH = 32

#: GCM nonce length in bytes (96-bit — the standard for AES-GCM).
_NONCE_LENGTH = 12

#: Max length of a secret value (chars). Keeps the encrypted store bounded.
MAX_VAULT_VALUE_LENGTH = 16384

#: Domain / name must look like a conservative identifier.
_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")


class VaultError(Exception):
    """Vault operation failed (fail closed).

    ``code`` is a stable machine-readable reason (``"disabled"``,
    ``"validation"``, ``"unknown"``, ``"revoked"``, ``"tampered"``,
    ``"not_found"``) so the API layer can map it onto deterministic HTTP
    statuses without string matching.
    """

    def __init__(self, message: str, *, code: str = "error"):
        super().__init__(message)
        self.code = code


# -- reference parsing -------------------------------------------------------
def is_vault_ref(value: object) -> bool:
    """True iff ``value`` looks like a ``vault:<domain>/<name>`` reference."""
    return isinstance(value, str) and value.startswith(VAULT_REF_PREFIX)


def parse_vault_ref(ref: str) -> tuple[str, str] | None:
    """Parse ``vault:<domain>/<name>`` -> ``(domain, name)``.

    Returns ``None`` (never raises) for anything malformed: missing slash,
    empty parts, bad characters, or over-long parts.
    """
    if not is_vault_ref(ref):
        return None
    rest = ref[len(VAULT_REF_PREFIX):]
    domain, sep, name = rest.partition("/")
    if not sep or not domain or not name:
        return None
    if not _PART_RE.match(domain) or not _PART_RE.match(name):
        return None
    return domain, name


def make_vault_ref(domain: str, name: str) -> str:
    """Build a canonical reference from validated parts."""
    return f"{VAULT_REF_PREFIX}{domain}/{name}"


def validate_vault_part(part: str, what: str) -> str:
    """Validate one reference part (domain / name); raise :class:`VaultError`."""
    if not isinstance(part, str) or not _PART_RE.match(part):
        raise VaultError(
            f"{what} must be 1-64 chars of [A-Za-z0-9_-] starting alphanumeric",
            code="validation",
        )
    return part


# -- master key ---------------------------------------------------------------
def parse_master_key(raw: str | None) -> bytes | None:
    """Parse an operator-supplied master key into 32 raw bytes.

    Accepts 64 hex characters or 44 base64 characters (both encoding 32
    bytes). Anything else — including a *near-miss* like a 31-byte key —
    returns ``None``: the vault must stay disabled rather than run under a
    broken key.
    """
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if len(text) == 2 * MASTER_KEY_LENGTH:
        try:
            key = bytes.fromhex(text)
        except ValueError:
            return None
        if len(key) == MASTER_KEY_LENGTH:
            return key
        return None
    if len(text) == 44:  # base64 of 32 bytes (with padding)
        try:
            key = base64.b64decode(text.encode("ascii"), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError):
            return None
        if len(key) == MASTER_KEY_LENGTH:
            return key
    return None


# -- AES-256-GCM ----------------------------------------------------------------
def _aad(domain: str, name: str) -> bytes:
    """Authentication data binding ciphertext to exactly one (domain, name)."""
    return f"era-vault/v1/{domain}/{name}".encode()


def vault_encrypt(plaintext: str, master_key: bytes, domain: str, name: str) -> tuple[bytes, bytes]:
    """Encrypt ``plaintext`` -> ``(ciphertext, nonce)``.

    A fresh random 96-bit nonce is generated per value (AES-GCM: never reuse
    a nonce under the same key). ``domain``/``name`` are bound into the
    ciphertext via AAD so the blob is only decryptable for the row it was
    created for.
    """
    nonce = secrets.token_bytes(_NONCE_LENGTH)
    ct = AESGCM(master_key).encrypt(nonce, plaintext.encode("utf-8"), _aad(domain, name))
    return ct, nonce


def vault_decrypt(ciphertext: bytes, nonce: bytes, master_key: bytes,
                  domain: str, name: str) -> str:
    """Decrypt and authenticate a vault value.

    Raises :class:`VaultError` (code ``"tampered"``) on any authentication
    failure — wrong key, flipped ciphertext byte, or AAD (domain/name)
    mismatch. There is no non-raising mode.
    """
    try:
        plaintext = AESGCM(master_key).decrypt(nonce, ciphertext, _aad(domain, name))
    except (InvalidTag, ValueError, TypeError) as exc:
        raise VaultError("vault value failed authentication (tampered or wrong key)",
                         code="tampered") from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VaultError("vault value is not valid UTF-8", code="tampered") from exc
