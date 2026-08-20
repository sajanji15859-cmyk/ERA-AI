"""Provider-agnostic LLM adapter layer (Phase 1A).

Public API:

- :class:`ChatMessage` / :class:`LLMResponse` — the transport-neutral message types
- :class:`LLMClient` — the protocol every provider implements
- Error taxonomy rooted at :class:`LLMError`
- :func:`~era.llm.factory.create_client` — build a client from config + environment

Design notes:
    The interface is deliberately text-in/text-out. Tool selection is handled by
    the agent loop's JSON-action prompt protocol (Phase 1E), not provider-native
    tool-calling, so every provider — and the mock used in tests — behaves
    identically. Streaming, caching and native tool APIs can be added later
    without breaking this contract.
"""

from __future__ import annotations

from era.llm.base import (
    ChatMessage,
    LLMAuthError,
    LLMClient,
    LLMConnectionError,
    LLMError,
    LLMResponse,
    LLMResponseError,
    LLMTimeoutError,
    TokenUsage,
)
from era.llm.factory import create_client
from era.llm.mock import MockLLMClient

__all__ = [
    "ChatMessage",
    "LLMAuthError",
    "LLMClient",
    "LLMConnectionError",
    "LLMError",
    "LLMResponse",
    "LLMResponseError",
    "LLMTimeoutError",
    "MockLLMClient",
    "TokenUsage",
    "create_client",
]
