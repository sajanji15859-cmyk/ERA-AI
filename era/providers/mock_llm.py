"""MockLLMProvider — a fixed-response model for testing the agent loop.

Implements the abstract :class:`~era.core.llm.LLMProvider` interface so the
tool-calling loop can be exercised in Phase 1C without a real model. Carries no
credentials (its ``id`` is an opaque reference, not an API key).
"""

from __future__ import annotations

from collections.abc import Iterator

from era.core.llm import LLMRequest, LLMResponse, ToolCall
from era.core.provider_info import ProviderInfo


class MockLLMProvider:
    id = "mock"

    def __init__(self, tool_calls: list[ToolCall] | None = None):
        self._tool_calls = tool_calls or []

    def complete(self, req: LLMRequest) -> LLMResponse:
        return LLMResponse(text="mock", tool_calls=list(self._tool_calls))

    def stream(self, req: LLMRequest) -> Iterator[LLMResponse]:
        yield self.complete(req)

    def describe(self) -> ProviderInfo:
        # An LLM provider is not a ToolProvider, but it exposes the same
        # introspection shape so diagnostics/registry listings stay uniform.
        return ProviderInfo(
            id=self.id,
            action_types=frozenset(),
            version="0.1.0",
            display_name="Mock LLM (offline)",
            is_stub=True,
            capabilities=("complete", "stream"),
        )
