"""LLM API key via the credential vault (Phase 3C)."""

from __future__ import annotations

import pytest

from era.agent_runtime import build_llm_provider
from era.config import Settings
from era.container import build_container
from era.security.vault import VaultError

HEX_KEY = "ef" * 32


def _settings(tmp_path, *, api_key: str, **overrides):
    kwargs = {
        "database_url": f"sqlite:///{tmp_path}/llm_vault.db",
        "vault_master_key": HEX_KEY,
        "agent_llm_provider": "openai",
        "agent_llm_api_key": api_key,
    }
    kwargs.update(overrides)
    return Settings(**kwargs)


def _vaulted_container(tmp_path):
    c = build_container(Settings(database_url=f"sqlite:///{tmp_path}/llm_vc.db",
                                 vault_master_key=HEX_KEY))
    return c


def test_llm_key_from_vault_resolves_at_build_time(tmp_path):
    c = _vaulted_container(tmp_path)
    c.vault_service.store_or_rotate_secret(domain="llm", name="openai",
                                           value="sk-vault-stored-123",
                                           actor_id="admin")
    s = _settings(tmp_path, api_key="vault:llm/openai")
    provider = build_llm_provider(s, c.vault_service)
    assert provider is not None
    assert provider._api_key == "sk-vault-stored-123"


def test_llm_plain_env_key_still_works(tmp_path):
    s = _settings(tmp_path, api_key="sk-plain-env-key")
    provider = build_llm_provider(s, None)
    assert provider is not None and provider._api_key == "sk-plain-env-key"


def test_llm_no_key_still_offline(tmp_path):
    assert build_llm_provider(_settings(tmp_path, api_key=""), None) is None
    assert build_llm_provider(Settings(agent_llm_provider=""), None) is None


def test_llm_vault_ref_with_disabled_vault_fails_closed(tmp_path):
    s = _settings(tmp_path, api_key="vault:llm/openai", vault_master_key="")
    with pytest.raises(VaultError) as ei:
        build_llm_provider(s, None)
    assert ei.value.code == "disabled"
    c = build_container(Settings(database_url=f"sqlite:///{tmp_path}/off.db"))
    with pytest.raises(VaultError) as ei:
        build_llm_provider(s, c.vault_service)
    assert ei.value.code == "disabled"


def test_llm_unresolvable_vault_ref_fails_closed(tmp_path):
    c = _vaulted_container(tmp_path)  # enabled, but nothing stored
    s = _settings(tmp_path, api_key="vault:llm/openai")
    with pytest.raises(VaultError) as ei:
        build_llm_provider(s, c.vault_service)
    assert ei.value.code == "unknown"


def test_agent_container_builds_llm_from_vault(tmp_path, monkeypatch):
    """Full runtime wiring: ERA_AGENT_LLM_API_KEY=vault:llm/openai."""
    from era.agent_runtime import build_agent_container

    c = build_container(Settings(database_url=f"sqlite:///{tmp_path}/ac.db",
                                 vault_master_key=HEX_KEY))
    c.vault_service.store_or_rotate_secret(domain="llm", name="openai",
                                           value="sk-agent-vault", actor_id="admin")
    s = Settings(database_url=f"sqlite:///{tmp_path}/ac.db",
                 vault_master_key=HEX_KEY,
                 agent_llm_provider="openai",
                 agent_llm_api_key="vault:llm/openai")
    # Reuse the same DB file so the secret is visible to the new container:
    c2 = build_agent_container(s)
    assert c2.llm_provider is not None
    assert c2.llm_provider._api_key == "sk-agent-vault"
