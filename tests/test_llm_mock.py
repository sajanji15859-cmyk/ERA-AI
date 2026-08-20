"""Tests for the offline mock LLM client (era.llm.mock)."""

from __future__ import annotations

import pytest
from era.llm.base import ChatMessage, LLMError
from era.llm.mock import MOCK_MODEL_NAME, MockLLMClient

MSGS = [ChatMessage(role="user", content="hello")]


class TestMockClient:
    def test_replays_scripted_responses_in_order(self) -> None:
        client = MockLLMClient(["first", "second"])
        assert client.complete(MSGS).text == "first"
        assert client.complete(MSGS).text == "second"

    def test_records_every_call(self) -> None:
        client = MockLLMClient(["a", "b"])
        client.complete([ChatMessage(role="system", content="s"), *MSGS])
        client.complete(MSGS)
        assert client.call_count == 2
        assert client.calls[0][0].role == "system"
        assert client.last_messages == MSGS

    def test_empty_queue_raises_deterministic_error(self) -> None:
        client = MockLLMClient()
        with pytest.raises(LLMError, match="ran out of scripted responses"):
            client.complete(MSGS)

    def test_queue_response_appends(self) -> None:
        client = MockLLMClient()
        client.queue_response("late")
        assert client.complete(MSGS).text == "late"

    def test_response_metadata(self) -> None:
        response = MockLLMClient(["hi"]).complete(MSGS, timeout_s=1.0)
        assert response.model == MOCK_MODEL_NAME
        assert response.usage is None

    def test_last_messages_before_any_call_raises(self) -> None:
        with pytest.raises(LLMError, match="has not been called"):
            _ = MockLLMClient().last_messages
