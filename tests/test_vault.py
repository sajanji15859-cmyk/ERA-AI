"""Credential vault crypto + service tests (Phase 3C)."""

from __future__ import annotations

import pytest

from era.config import Settings
from era.container import build_container
from era.db import transaction
from era.security.vault import (
    MAX_VAULT_VALUE_LENGTH,
    VaultError,
    is_vault_ref,
    make_vault_ref,
    parse_master_key,
    parse_vault_ref,
    vault_decrypt,
    vault_encrypt,
)

KEY = bytes(range(32))  # fixed 32-byte master key for unit tests


# -- master key parsing -------------------------------------------------------
def test_parse_master_key_hex():
    raw = "ab" * 32
    assert parse_master_key(raw) == bytes.fromhex(raw)
    assert parse_master_key(raw.upper()) == bytes.fromhex(raw.upper())


def test_parse_master_key_base64():
    import base64
    raw = base64.b64encode(KEY).decode()
    assert len(raw) == 44
    assert parse_master_key(raw) == KEY


def test_parse_master_key_rejects_malformed():
    assert parse_master_key("") is None
    assert parse_master_key(None) is None
    assert parse_master_key("tooshort") is None
    assert parse_master_key("ab" * 16) is None            # 16 bytes, not 32
    assert parse_master_key("zz" * 32) is None            # not hex
    assert parse_master_key("ab" * 32 + "cd") is None     # 66 chars: neither
    assert parse_master_key("a" * 44) is None             # 44 chars but not valid b64 payload
    # a 31-byte "near-miss" key must NOT become a working key
    assert parse_master_key("ab" * 31 + "c") is None


# -- reference parsing --------------------------------------------------------
def test_vault_ref_parse_roundtrip():
    ref = make_vault_ref("email", "smtp_password")
    assert ref == "vault:email/smtp_password"
    assert is_vault_ref(ref)
    assert parse_vault_ref(ref) == ("email", "smtp_password")


def test_vault_ref_rejects_malformed():
    for bad in ("", "vault:", "vault/email/x", "vault://a/b", "vault:/x",
                "vault:a/b/c", "vault:A//b", "vault:-a/x",
                "vault:a/x" + "y" * 65, "vault:a/" + "b" * 65,
                "env:EMAIL_PASS", "VAULT:a/b", None, 42):
        assert parse_vault_ref(bad) is None, bad
    # 64 chars is the max (valid); leading digits are valid (alphanumeric):
    assert parse_vault_ref("vault:a/" + "b" * 64)[1] == "b" * 64
    assert parse_vault_ref("vault:9ok/x") == ("9ok", "x")


# -- AES-256-GCM roundtrip / tamper -------------------------------------------
def test_encrypt_decrypt_roundtrip():
    ct, nonce = vault_encrypt("hunter2", KEY, "email", "smtp_password")
    assert vault_decrypt(ct, nonce, KEY, "email", "smtp_password") == "hunter2"


def test_nonce_is_fresh_per_encryption():
    ct1, n1 = vault_encrypt("same", KEY, "d", "n")
    ct2, n2 = vault_encrypt("same", KEY, "d", "n")
    assert n1 != n2 and ct1 != ct2
    assert vault_decrypt(ct2, n2, KEY, "d", "n") == "same"


def test_tampered_ciphertext_rejected():
    ct, nonce = vault_encrypt("hunter2", KEY, "email", "p")
    flipped = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(VaultError) as ei:
        vault_decrypt(flipped, nonce, KEY, "email", "p")
    assert ei.value.code == "tampered"


def test_tampered_nonce_rejected():
    ct, nonce = vault_encrypt("hunter2", KEY, "email", "p")
    bad_nonce = bytes([nonce[0] ^ 1]) + nonce[1:]
    with pytest.raises(VaultError) as ei:
        vault_decrypt(ct, bad_nonce, KEY, "email", "p")
    assert ei.value.code == "tampered"


def test_wrong_key_rejected():
    ct, nonce = vault_encrypt("hunter2", KEY, "email", "p")
    with pytest.raises(VaultError) as ei:
        vault_decrypt(ct, nonce, bytes(32), "email", "p")
    assert ei.value.code == "tampered"


def test_aad_binds_ciphertext_to_domain_name():
    ct, nonce = vault_encrypt("hunter2", KEY, "email", "p")
    # Same ciphertext must NOT decrypt under a different (domain, name).
    with pytest.raises(VaultError) as ei:
        vault_decrypt(ct, nonce, KEY, "email", "other_name")
    assert ei.value.code == "tampered"
    with pytest.raises(VaultError):
        vault_decrypt(ct, nonce, KEY, "github", "p")


# -- service: fail-closed disabled --------------------------------------------
def make_vaulted_container(tmp_path, *, master_key: str | None = None,
                           providers=None):
    kwargs = {"database_url": f"sqlite:///{tmp_path}/vault_test.db"}
    if master_key is not None:
        kwargs["vault_master_key"] = master_key
    return build_container(Settings(**kwargs), providers=providers)


def test_disabled_vault_stores_and_resolves_fail_closed(tmp_path):
    c = make_vaulted_container(tmp_path)  # no master key
    v = c.vault_service
    assert v.enabled is False
    with pytest.raises(VaultError) as ei:
        v.store_or_rotate_secret(domain="email", name="p", value="x", actor_id="u")
    assert ei.value.code == "disabled"
    with pytest.raises(VaultError) as ei:
        v.resolve_ref("vault:email/p")
    assert ei.value.code == "disabled"


def test_enabled_vault_roundtrip_and_audit(tmp_path):
    c = make_vaulted_container(tmp_path, master_key="ab" * 32)
    v = c.vault_service
    secret = v.store_or_rotate_secret(domain="email", name="smtp_password",
                                      value="S3cret!", actor_id="u1")
    assert secret.revision == 1 and secret.value_length == 7
    assert v.resolve_ref("vault:email/smtp_password") == "S3cret!"

    with transaction(c.session_factory) as session:
        entries = v.audit_service.list(session, limit=500)
    ops = [(e.action_type, e.outcome) for e in entries
           if e.action_type in ("vault.store", "vault.rotate", "vault.revoke",
                                "vault.resolve")]
    assert ("vault.store", "EXECUTED") in ops
    assert ("vault.resolve", "EXECUTED") in ops
    # The plaintext must not appear anywhere in the audit log.
    for e in entries:
        assert "S3cret!" not in str(e.action_params)
        assert "S3cret!" not in str(e.result)


# -- service: validation -------------------------------------------------------
def test_store_validates_inputs(tmp_path):
    c = make_vaulted_container(tmp_path, master_key="ab" * 32)
    v = c.vault_service
    for kwargs in (
        {"domain": "bad domain", "name": "p", "value": "x", "actor_id": "u"},
        {"domain": "email", "name": "has/slash", "value": "x", "actor_id": "u"},
        {"domain": "email", "name": "x" * 65, "value": "x", "actor_id": "u"},
        {"domain": "email", "name": "p", "value": "", "actor_id": "u"},
        {"domain": "email", "name": "p", "value": "x" * (MAX_VAULT_VALUE_LENGTH + 1),
         "actor_id": "u"},
        {"domain": "email", "name": "p", "value": 123, "actor_id": "u"},
    ):
        with pytest.raises(VaultError) as ei:
            v.store_or_rotate_secret(**kwargs)
        assert ei.value.code == "validation"
    assert v.list_secrets() == []


def test_resolve_rejects_non_ref_and_malformed(tmp_path):
    c = make_vaulted_container(tmp_path, master_key="ab" * 32)
    v = c.vault_service
    for ref in ("plain-value", "vault:", "vault:email/", "env:EMAIL_PASS",
                "vault:email/nosuch"):
        with pytest.raises(VaultError):
            v.resolve_ref(ref)
    # unknown-but-well-formed ref:
    with pytest.raises(VaultError) as ei:
        v.resolve_ref("vault:email/ghost")
    assert ei.value.code == "unknown"


def test_unknown_resolve_is_audited_as_failure(tmp_path):
    c = make_vaulted_container(tmp_path, master_key="ab" * 32)
    with pytest.raises(VaultError):
        c.vault_service.resolve_ref("vault:email/ghost")
    with transaction(c.session_factory) as session:
        entries = c.audit_service.list(session, limit=500)
    fails = [e for e in entries if e.action_type == "vault.resolve"
             and e.outcome == "FAILED"]
    assert len(fails) == 1
    assert fails[0].error_code == "UNKNOWN"


# -- service: rotate / revoke ---------------------------------------------------
def test_rotate_bumps_revision(tmp_path):
    c = make_vaulted_container(tmp_path, master_key="ab" * 32)
    v = c.vault_service
    v.store_or_rotate_secret(domain="email", name="p", value="one", actor_id="u1")
    v.store_or_rotate_secret(domain="email", name="p", value="two", actor_id="u1")
    assert v.resolve_ref("vault:email/p") == "two"
    row = v.get_secret(domain="email", name="p")
    assert row.revision == 2
    assert v.list_secrets("email")[0].id == row.id


def test_revoke_blocks_resolve_until_restore(tmp_path):
    c = make_vaulted_container(tmp_path, master_key="ab" * 32)
    v = c.vault_service
    v.store_or_rotate_secret(domain="email", name="p", value="one", actor_id="u1")
    v.revoke_secret(domain="email", name="p", actor_id="u1")
    with pytest.raises(VaultError) as ei:
        v.resolve_ref("vault:email/p")
    assert ei.value.code == "revoked"
    # failure audited
    with transaction(c.session_factory) as session:
        fails = [e for e in v.audit_service.list(session)
                 if e.action_type == "vault.resolve" and e.outcome == "FAILED"]
    assert [f.error_code for f in fails] == ["REVOKED"]
    # re-store revives it
    row = v.store_or_rotate_secret(domain="email", name="p", value="two", actor_id="u1")
    assert row.revoked_at is None and row.revision == 2
    assert v.resolve_ref("vault:email/p") == "two"


def test_revoke_missing_raises_not_found(tmp_path):
    c = make_vaulted_container(tmp_path, master_key="ab" * 32)
    with pytest.raises(VaultError) as ei:
        c.vault_service.revoke_secret(domain="email", name="ghost", actor_id="u1")
    assert ei.value.code == "not_found"


def test_list_never_exposes_secret_material(tmp_path):
    c = make_vaulted_container(tmp_path, master_key="ab" * 32)
    v = c.vault_service
    v.store_or_rotate_secret(domain="email", name="smtp_password",
                             value="TOP-SECRET-VALUE", actor_id="u1")
    rows = v.list_secrets()
    assert len(rows) == 1
    dumped = rows[0].__dict__
    # ciphertext exists on the row but the *plaintext* must be nowhere:
    assert "TOP-SECRET-VALUE" not in str(dumped)
    # and the metadata shape has no value field:
    assert not hasattr(rows[0], "value")


def test_ciphertext_at_rest_is_not_plaintext(tmp_path):
    """The database (incl. WAL) must not contain the secret in plaintext."""
    c = make_vaulted_container(tmp_path, master_key="ab" * 32)
    needle = "SUPER-UNIQUE-SECRET-VALUE-12345"
    c.vault_service.store_or_rotate_secret(domain="email", name="p",
                                           value=needle, actor_id="u1")
    c.engine.dispose()
    raw = b""
    for suffix in ("", "-wal", "-shm"):
        path = f"{tmp_path}/vault_test.db{suffix}"
        try:
            with open(path, "rb") as f:
                raw += f.read()
        except FileNotFoundError:
            pass
    assert needle.encode() not in raw
