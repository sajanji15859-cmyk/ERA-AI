"""Keyed audit-chain signing (Phase 3F).

A plain SHA-256 chain is only tamper-*evident* while its trusted head remains
outside the database: an attacker able to rewrite the table can recompute every
hash.  These signers authenticate each chain head with either HMAC-SHA-256 or
Ed25519, making such a rewrite unverifiable without the configured key.

Keys are operational secrets and are never persisted by ERA.  They must be
provided through environment-backed settings (or an external secret manager).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from era.security.hashing import canonical_json

SIGNING_DOMAIN = b"ERA-AUDIT-SIGNATURE-V1\x00"


@runtime_checkable
class AuditSigner(Protocol):
    """Small algorithm-neutral signing boundary used by audit repositories."""

    algorithm: str
    key_id: str

    def sign(self, entry_hash: str) -> str: ...

    def verify(self, entry_hash: str, signature: str) -> bool: ...


def signing_payload(entry_hash: str, algorithm: str, key_id: str) -> bytes:
    """Domain-separated canonical bytes bound to both algorithm and key id."""
    document = canonical_json({
        "algorithm": algorithm,
        "entry_hash": entry_hash,
        "key_id": key_id,
    }).encode("utf-8")
    return SIGNING_DOMAIN + document


def _encode_signature(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_signature(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("missing signature")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid signature encoding") from exc


class HMACAuditSigner:
    """HMAC-SHA-256 audit signer and verifier."""

    algorithm = "hmac-sha256"

    def __init__(self, key: bytes, *, key_id: str = "default"):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("audit HMAC key must contain at least 32 bytes")
        if not key_id or not isinstance(key_id, str):
            raise ValueError("audit signing key id must be a non-empty string")
        self._key = key
        self.key_id = key_id

    def sign(self, entry_hash: str) -> str:
        digest = hmac.new(
            self._key,
            signing_payload(entry_hash, self.algorithm, self.key_id),
            hashlib.sha256,
        ).digest()
        return _encode_signature(digest)

    def verify(self, entry_hash: str, signature: str) -> bool:
        try:
            supplied = _decode_signature(signature)
        except ValueError:
            return False
        expected = hmac.new(
            self._key,
            signing_payload(entry_hash, self.algorithm, self.key_id),
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(supplied, expected)


class Ed25519AuditSigner:
    """Ed25519 signer; it may also be constructed as a public-key verifier."""

    algorithm = "ed25519"

    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey | None = None,
        public_key: Ed25519PublicKey | None = None,
        key_id: str = "default",
    ):
        if private_key is None and public_key is None:
            raise ValueError("an Ed25519 private or public key is required")
        if not key_id or not isinstance(key_id, str):
            raise ValueError("audit signing key id must be a non-empty string")
        if private_key is not None and public_key is not None:
            derived = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            supplied = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            if not hmac.compare_digest(derived, supplied):
                raise ValueError("Ed25519 public key does not match private key")
        self._private_key = private_key
        self._public_key = public_key or private_key.public_key()  # type: ignore[union-attr]
        self.key_id = key_id

    def sign(self, entry_hash: str) -> str:
        if self._private_key is None:
            raise ValueError("Ed25519 verifier has no private signing key")
        value = self._private_key.sign(
            signing_payload(entry_hash, self.algorithm, self.key_id)
        )
        return _encode_signature(value)

    def verify(self, entry_hash: str, signature: str) -> bool:
        try:
            value = _decode_signature(signature)
            self._public_key.verify(
                value,
                signing_payload(entry_hash, self.algorithm, self.key_id),
            )
        except (InvalidSignature, ValueError):
            return False
        return True

    @classmethod
    def from_encoded(
        cls,
        *,
        private_key: str = "",
        public_key: str = "",
        key_id: str = "default",
    ) -> Ed25519AuditSigner:
        """Load PEM or raw 32-byte hex/base64 Ed25519 key material."""
        private = _load_ed25519_private(private_key) if private_key else None
        public = _load_ed25519_public(public_key) if public_key else None
        return cls(private_key=private, public_key=public, key_id=key_id)


def decode_secret(value: str) -> bytes:
    """Decode ``hex:``, ``base64:`` or a literal UTF-8 operational secret."""
    if not isinstance(value, str) or not value:
        raise ValueError("audit signing key is required")
    if value.startswith("hex:"):
        try:
            return bytes.fromhex(value[4:])
        except ValueError as exc:
            raise ValueError("invalid hex audit signing key") from exc
    if value.startswith("base64:"):
        try:
            return base64.b64decode(value[7:], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("invalid base64 audit signing key") from exc
    return value.encode("utf-8")


def build_audit_signer(
    algorithm: str,
    *,
    key: str = "",
    public_key: str = "",
    key_id: str = "default",
) -> AuditSigner | None:
    """Build the configured signer; ``none`` is explicit legacy mode."""
    algorithm = (algorithm or "none").strip().lower()
    if algorithm in {"none", "off", "disabled"}:
        return None
    if algorithm == HMACAuditSigner.algorithm:
        return HMACAuditSigner(decode_secret(key), key_id=key_id)
    if algorithm == Ed25519AuditSigner.algorithm:
        return Ed25519AuditSigner.from_encoded(
            private_key=key,
            public_key=public_key,
            key_id=key_id,
        )
    raise ValueError(f"unsupported audit signing algorithm: {algorithm!r}")


def _decode_raw_key(value: str) -> bytes:
    stripped = value.strip()
    if stripped.startswith(("hex:", "base64:")):
        return decode_secret(stripped)
    try:
        return bytes.fromhex(stripped)
    except ValueError:
        try:
            return base64.b64decode(stripped, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("key must be PEM, 32-byte hex, or base64") from exc


def _load_ed25519_private(value: str) -> Ed25519PrivateKey:
    pem = value.replace("\\n", "\n").encode("utf-8")
    if pem.lstrip().startswith(b"-----BEGIN"):
        loaded = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("audit private key is not Ed25519")
        return loaded
    raw = _decode_raw_key(value)
    if len(raw) != 32:
        raise ValueError("raw Ed25519 private key must contain 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _load_ed25519_public(value: str) -> Ed25519PublicKey:
    pem = value.replace("\\n", "\n").encode("utf-8")
    if pem.lstrip().startswith(b"-----BEGIN"):
        loaded = serialization.load_pem_public_key(pem)
        if not isinstance(loaded, Ed25519PublicKey):
            raise ValueError("audit public key is not Ed25519")
        return loaded
    raw = _decode_raw_key(value)
    if len(raw) != 32:
        raise ValueError("raw Ed25519 public key must contain 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)
