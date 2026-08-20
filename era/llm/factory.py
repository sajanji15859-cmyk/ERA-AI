"""Build the configured LLM client from config + environment.

Providers:
    ``mock``    — offline scripted client (tests, demos)
    ``openai``  — any OpenAI-compatible chat-completions endpoint
    ``none``    — LLM disabled (default); requesting a client raises a
                  helpful ConfigError

The API key is read from ``$ERA_LLM_API_KEY`` (environment only — it is never
stored in the Config object, the config file, or logs).
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from era.config import VALID_LLM_PROVIDERS, Config, ConfigError
from era.llm.base import LLMClient
from era.llm.mock import MockLLMClient
from era.llm.openai_compat import DEFAULT_BASE_URL, OpenAICompatClient

API_KEY_ENV_VAR = "ERA_LLM_API_KEY"


def create_client(config: Config, env: Mapping[str, str] | None = None) -> LLMClient:
    """Return an LLM client for the configured provider.

    Raises:
        ConfigError: if the provider is unknown/disabled, or required settings
            (e.g. ``model`` for ``openai``) are missing.
    """
    env = os.environ if env is None else env
    settings = config.llm
    provider = settings.provider

    if provider == "mock":
        return MockLLMClient()
    if provider == "openai":
        if not settings.model:
            msg = "LLM provider 'openai' requires a model — set [llm] model or ERA_LLM_MODEL"
            raise ConfigError(msg)
        return OpenAICompatClient(
            model=settings.model,
            base_url=settings.base_url or DEFAULT_BASE_URL,
            api_key=env.get(API_KEY_ENV_VAR, ""),
            timeout_s=settings.timeout_s,
        )
    if provider == "none":
        msg = (
            "no LLM provider configured — set [llm] provider or ERA_LLM_PROVIDER "
            f"to one of: {', '.join(sorted(VALID_LLM_PROVIDERS - {'none'}))}"
        )
        raise ConfigError(msg)
    msg = f"unknown LLM provider {provider!r} (valid: {', '.join(sorted(VALID_LLM_PROVIDERS))})"
    raise ConfigError(msg)
