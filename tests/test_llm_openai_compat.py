"""Tests for the OpenAI-compatible client (era.llm.openai_compat).

All tests run offline against a fake transport injected in place of
``urllib.request.urlopen`` — no real API calls, no real credentials.
"""

from __future__ import annotations

import io
import json
import socket
import urllib.error
from typing import Any

import pytest
from era.llm.base import (
    ChatMessage,
    LLMAuthError,
    LLMConnectionError,
    LLMResponseError,
    LLMTimeoutError,
)
from era.llm.openai_compat import DEFAULT_BASE_URL, OpenAICompatClient

MSGS = [ChatMessage(role="user", content="hello")]
SECRET = "sk-test-DO-NOT-LEAK-000"


class FakeResponse:
    """Minimal stand-in for urllib's HTTPResponse (context manager + read)."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self, *args: Any) -> bytes:
        return self._body


class TransportRecorder:
    """Fake urlopen capturing requests and returning/replaying scripted results."""

    def __init__(self, result: Any = None) -> None:
        self.result = result  # bytes/FakeResponse, or an exception to raise
        self.requests: list[tuple[urllib.request.Request, float | None]] = []

    def __call__(self, request: urllib.request.Request, timeout: float | None = None) -> Any:
        self.requests.append((request, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        if isinstance(self.result, bytes):
            return FakeResponse(self.result)
        return self.result


def ok_body(text: str = "model says hi", model: str = "gpt-test") -> bytes:
    return json.dumps(
        {
            "model": model,
            "choices": [{"message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
    ).encode()


def make_client(transport: TransportRecorder, **kwargs: Any) -> OpenAICompatClient:
    kwargs.setdefault("model", "gpt-test")
    kwargs.setdefault("api_key", SECRET)
    kwargs.setdefault("transport", transport)
    return OpenAICompatClient(**kwargs)


class TestRequestBuilding:
    def test_url_payload_and_headers(self) -> None:
        transport = TransportRecorder(ok_body())
        client = make_client(transport, base_url="http://localhost:9999/v1")
        client.complete(MSGS)
        request, timeout = transport.requests[0]
        assert request.full_url == "http://localhost:9999/v1/chat/completions"
        assert request.get_method() == "POST"
        assert request.get_header("Content-type") == "application/json"
        assert request.get_header("Authorization") == f"Bearer {SECRET}"
        payload = json.loads(request.data.decode())
        assert payload["model"] == "gpt-test"
        assert payload["messages"] == [{"role": "user", "content": "hello"}]
        assert timeout == 60.0

    def test_no_auth_header_without_key(self) -> None:
        transport = TransportRecorder(ok_body())
        client = make_client(transport, api_key="")
        client.complete(MSGS)
        assert transport.requests[0][0].get_header("Authorization") is None

    def test_default_base_url(self) -> None:
        transport = TransportRecorder(ok_body())
        client = make_client(transport)
        assert client.base_url == DEFAULT_BASE_URL
        client.complete(MSGS)
        assert transport.requests[0][0].full_url == f"{DEFAULT_BASE_URL}/chat/completions"

    def test_timeout_override_per_call(self) -> None:
        transport = TransportRecorder(ok_body())
        client = make_client(transport, timeout_s=30.0)
        client.complete(MSGS, timeout_s=2.5)
        assert transport.requests[0][1] == 2.5

    def test_empty_messages_rejected(self) -> None:
        client = make_client(TransportRecorder(ok_body()))
        with pytest.raises(ValueError, match="must not be empty"):
            client.complete([])


class TestResponseParsing:
    def test_success_text_model_usage(self) -> None:
        transport = TransportRecorder(ok_body(text="answer", model="m-echo"))
        response = make_client(transport).complete(MSGS)
        assert response.text == "answer"
        assert response.model == "m-echo"
        assert response.usage is not None
        assert response.usage.input_tokens == 10
        assert response.usage.output_tokens == 5

    def test_missing_usage_is_none(self) -> None:
        body = json.dumps({"choices": [{"message": {"content": "x"}}]}).encode()
        response = make_client(TransportRecorder(body)).complete(MSGS)
        assert response.usage is None

    def test_bad_json_raises_response_error(self) -> None:
        client = make_client(TransportRecorder(b"<html>not json</html>"))
        with pytest.raises(LLMResponseError, match="non-JSON"):
            client.complete(MSGS)

    def test_missing_choices_raises(self) -> None:
        client = make_client(TransportRecorder(json.dumps({"model": "m"}).encode()))
        with pytest.raises(LLMResponseError, match="no choices"):
            client.complete(MSGS)

    def test_none_content_raises(self) -> None:
        body = json.dumps({"choices": [{"message": {"content": None}}]}).encode()
        client = make_client(TransportRecorder(body))
        with pytest.raises(LLMResponseError, match="no text content"):
            client.complete(MSGS)


class TestErrorMapping:
    def http_error(self, code: int, body: bytes = b"{}") -> urllib.error.HTTPError:
        return urllib.error.HTTPError(
            "http://x/chat/completions",
            code,
            "err",
            None,
            io.BytesIO(body),  # type: ignore[arg-type]
        )

    def test_401_maps_to_auth_error_without_leaking_key(self) -> None:
        client = make_client(TransportRecorder(self.http_error(401)))
        with pytest.raises(LLMAuthError, match="ERA_LLM_API_KEY") as excinfo:
            client.complete(MSGS)
        assert SECRET not in str(excinfo.value)

    def test_403_maps_to_auth_error(self) -> None:
        client = make_client(TransportRecorder(self.http_error(403)))
        with pytest.raises(LLMAuthError):
            client.complete(MSGS)

    def test_500_maps_to_response_error_with_body_excerpt(self) -> None:
        client = make_client(TransportRecorder(self.http_error(500, b'{"error": "upstream died"}')))
        with pytest.raises(LLMResponseError, match="HTTP 500") as excinfo:
            client.complete(MSGS)
        assert "upstream died" in str(excinfo.value)
        assert SECRET not in str(excinfo.value)

    def test_urlerror_timeout_reason_maps_to_timeout(self) -> None:
        client = make_client(TransportRecorder(urllib.error.URLError(TimeoutError("timed out"))))
        with pytest.raises(LLMTimeoutError, match="timed out after"):
            client.complete(MSGS)

    def test_plaintext_timeout_maps_to_timeout(self) -> None:
        client = make_client(TransportRecorder(TimeoutError("timed out")))
        with pytest.raises(LLMTimeoutError):
            client.complete(MSGS)

    def test_urlerror_connection_reason_maps_to_connection(self) -> None:
        client = make_client(
            TransportRecorder(urllib.error.URLError(socket.gaierror("name resolution failed")))
        )
        with pytest.raises(LLMConnectionError, match="cannot reach"):
            client.complete(MSGS)

    def test_connection_reset_maps_to_connection(self) -> None:
        client = make_client(
            TransportRecorder(urllib.error.URLError(ConnectionResetError("reset")))
        )
        with pytest.raises(LLMConnectionError):
            client.complete(MSGS)


class TestSecretHygiene:
    def test_repr_never_contains_key(self) -> None:
        client = OpenAICompatClient(model="m", api_key=SECRET)
        assert SECRET not in repr(client)
        assert "api_key" not in repr(client)

    def test_error_messages_never_contain_key(self) -> None:
        for failure in (
            self.http_error_of(401),
            self.http_error_of(500),
            urllib.error.URLError(ConnectionRefusedError("refused")),
        ):
            client = make_client(TransportRecorder(failure))
            try:
                client.complete(MSGS)
            except Exception as exc:
                assert SECRET not in str(exc), type(exc)
            else:  # pragma: no cover
                pytest.fail("expected an exception")

    @staticmethod
    def http_error_of(code: int) -> urllib.error.HTTPError:
        return urllib.error.HTTPError(
            "http://x",
            code,
            "err",
            None,
            io.BytesIO(b"{}"),  # type: ignore[arg-type]
        )


class TestConstruction:
    def test_requires_model(self) -> None:
        with pytest.raises(ValueError, match="non-empty model"):
            OpenAICompatClient(model="")

    def test_requires_positive_timeout(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            OpenAICompatClient(model="m", timeout_s=0)
