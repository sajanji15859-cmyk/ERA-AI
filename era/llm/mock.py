"""Offline mock LLM client for tests and demos — zero network access.

``MockLLMClient`` replays a queue of scripted responses and records every
prompt it receives, so tests can assert on the exact conversation the agent
built. When the queue runs dry it raises instead of improvising, keeping test
behaviour deterministic.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence

from era.llm.base import ChatMessage, LLMError, LLMResponse

MOCK_MODEL_NAME = "mock-1"


class MockLLMClient:
    """Scripted, recording stand-in for a real provider client."""

    def __init__(self, responses: Sequence[str] = ()) -> None:
        self._responses: deque[str] = deque(responses)
        #: Every prompt received, in order (each entry is the full message list).
        self.calls: list[list[ChatMessage]] = []

    @property
    def call_count(self) -> int:
        """How many ``complete()`` calls were made."""
        return len(self.calls)

    @property
    def last_messages(self) -> list[ChatMessage]:
        """The most recent prompt (raises if never called)."""
        if not self.calls:
            msg = "MockLLMClient has not been called yet"
            raise LLMError(msg)
        return self.calls[-1]

    def queue_response(self, text: str) -> None:
        """Append one more scripted response."""
        self._responses.append(text)

    def complete(
        self, messages: Sequence[ChatMessage], *, timeout_s: float | None = None
    ) -> LLMResponse:
        """Return the next scripted response; record the prompt."""
        self.calls.append(list(messages))
        if not self._responses:
            msg = "MockLLMClient ran out of scripted responses"
            raise LLMError(msg)
        return LLMResponse(text=self._responses.popleft(), model=MOCK_MODEL_NAME)
