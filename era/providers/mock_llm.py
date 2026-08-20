"""MockLLMProvider — a fixed-response model for testing the agent loop.

Implements the abstract :class:`~era.core.llm.LLMProvider` interface so the
tool-calling loop can be exercised in Phase 1C without a real model. Carries no
credentials (its ``id`` is an opaque reference, not an API key).
"""

from __future__ import annotations

from collections.abc import Iterator

from era.core.llm import LLMRequest, LLMResponse, ToolCall


class MockLLMProvider:
    id = "mock"

    def __init__(self, tool_calls: list[ToolCall] | None = None):
        self._tool_calls = tool_calls or []

    def complete(self, req: LLMRequest) -> LLMResponse:
        return LLMResponse(text="mock", tool_calls=list(self._tool_calls))

    def stream(self, req: LLMRequest) -> Iterator[LLMResponse]:
        yield self.complete(req)
