"""Tests for the LLM client factory (era.llm.factory)."""

from __future__ import annotations

import pytest
from era.config import Config, ConfigError, LLMSettings, load_config
from era.llm.base import LLMClient
from era.llm.factory import API_KEY_ENV_VAR, create_client
from era.llm.mock import MockLLMClient
from era.llm.openai_compat import OpenAICompatClient


def config_with(provider: str, **llm_kwargs: object) -> Config:
    return Config(llm=LLMSettings(provider=provider, **llm_kwargs))  # type: ignore[arg-type]


class TestProviderRouting:
    def test_mock_provider_returns_mock_client(self) -> None:
        client = create_client(config_with("mock"), env={})
        assert isinstance(client, MockLLMClient)
        assert isinstance(client, LLMClient)  # satisfies the protocol

    def test_openai_provider_returns_openai_client(self) -> None:
        client = create_client(config_with("openai", model="m-1"), env={})
        assert isinstance(client, OpenAICompatClient)
        assert client.model == "m-1"
        assert client.timeout_s == 60.0

    def test_none_provider_raises_helpful_error(self) -> None:
        with pytest.raises(ConfigError, match="no LLM provider configured"):
            create_client(config_with("none"), env={})

    def test_unknown_provider_raises(self) -> None:
        bogus = config_with("mock")
        object.__setattr__(bogus.llm, "provider", "skynet")  # bypass frozen dataclass
        with pytest.raises(ConfigError, match="unknown LLM provider"):
            create_client(bogus, env={})

    def test_openai_without_model_raises(self) -> None:
        with pytest.raises(ConfigError, match="requires a model"):
            create_client(config_with("openai"), env={})


class TestEnvIntegration:
    def test_key_read_from_env_not_config(self, monkeypatch) -> None:
        monkeypatch.setenv(API_KEY_ENV_VAR, "sk-factory-test")
        client = create_client(config_with("openai", model="m"), env=None)  # reads os.environ
        # Key is stored privately; verify via a fake transport round-trip.
        assert client._api_key == "sk-factory-test"

    def test_missing_key_is_allowed_for_local_endpoints(self) -> None:
        # No ERA_LLM_API_KEY in env -> empty key, still constructible (Ollama etc.)
        client = create_client(config_with("openai", model="m"), env={})
        assert client._api_key == ""

    def test_base_url_from_settings(self) -> None:
        client = create_client(
            config_with("openai", model="m", base_url="http://localhost:11434/v1"), env={}
        )
        assert client.base_url == "http://localhost:11434/v1"

    def test_timeout_from_settings(self) -> None:
        client = create_client(config_with("openai", model="m", timeout_s=7.0), env={})
        assert client.timeout_s == 7.0


class TestEndToEndConfig:
    def test_load_config_to_client_via_env(self) -> None:
        config = load_config(
            env={
                "ERA_HOME": "/tmp/x",
                "ERA_LLM_PROVIDER": "mock",
            }
        )
        assert isinstance(create_client(config, env={}), MockLLMClient)

    def test_load_config_to_client_openai(self) -> None:
        config = load_config(
            env={"ERA_HOME": "/tmp/x", "ERA_LLM_PROVIDER": "openai", "ERA_LLM_MODEL": "gpt-x"}
        )
        client = create_client(config, env={API_KEY_ENV_VAR: "k"})
        assert isinstance(client, OpenAICompatClient)
        assert client.model == "gpt-x"


class TestProtocolConformance:
    def test_mock_and_openai_both_satisfy_protocol(self) -> None:
        for client in (
            MockLLMClient(["x"]),
            OpenAICompatClient(model="m"),
        ):
            assert isinstance(client, LLMClient)
            assert callable(client.complete)

    def test_factory_docstates_env_only_key(self) -> None:
        # The Config dataclass must never carry an API-key field.
        import dataclasses

        field_names = {f.name for f in dataclasses.fields(LLMSettings)}
        assert not any("key" in n or "secret" in n or "token" in n for n in field_names)
