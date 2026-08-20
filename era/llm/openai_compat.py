"""OpenAI-compatible chat-completions client (stdlib ``urllib`` only).

Works with any endpoint that speaks the OpenAI chat-completions protocol:
OpenAI itself, Groq, OpenRouter, Together, and local servers such as Ollama or
llama.cpp's server. Configure via::

    [llm]                      # or environment
    provider = "openai"
    model   = "..."            # required
    base_url = "..."           # optional; default https://api.openai.com/v1

    $ERA_LLM_API_KEY           # env var ONLY — never the config file, never logs

The API key is read from the environment, kept in a private attribute, and never
appears in exception messages, ``repr()``, or logs. The HTTP transport is
injectable so tests run offline against a fake ``urlopen``.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any

from era.llm.base import (
    ChatMessage,
    LLMAuthError,
    LLMConnectionError,
    LLMResponse,
    LLMResponseError,
    LLMTimeoutError,
    TokenUsage,
)

DEFAULT_BASE_URL = "https://api.openai.com/v1"
_CHAT_COMPLETIONS_PATH = "/chat/completions"
_MAX_ERROR_BODY_CHARS = 300

#: Injectable transport matching ``urllib.request.urlopen(req, timeout=t)``.
Transport = Callable[..., Any]


class OpenAICompatClient:
    """Minimal, dependency-free client for OpenAI-compatible endpoints."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str = "",
        timeout_s: float = 60.0,
        transport: Transport | None = None,
    ) -> None:
        if not model:
            msg = "OpenAICompatClient requires a non-empty model"
            raise ValueError(msg)
        if timeout_s <= 0:
            msg = f"timeout_s must be positive, got {timeout_s}"
            raise ValueError(msg)
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self._api_key = api_key  # private: never logged, never in repr/errors
        self._urlopen: Transport = transport or urllib.request.urlopen

    def __repr__(self) -> str:  # deliberately excludes the API key
        return (
            f"<OpenAICompatClient model={self.model!r} "
            f"base_url={self.base_url!r} timeout_s={self.timeout_s}>"
        )

    def complete(
        self, messages: Sequence[ChatMessage], *, timeout_s: float | None = None
    ) -> LLMResponse:
        """Send the conversation; return the model's text response."""
        if not messages:
            msg = "messages must not be empty"
            raise ValueError(msg)
        effective_timeout = self.timeout_s if timeout_s is None else timeout_s
        if effective_timeout <= 0:
            msg = f"timeout must be positive, got {effective_timeout}"
            raise ValueError(msg)

        url = f"{self.base_url}{_CHAT_COMPLETIONS_PATH}"
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        body = self._send(request, effective_timeout)
        return self._parse(body)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _send(self, request: urllib.request.Request, timeout: float) -> bytes:
        """Execute the request with sanitized error mapping."""
        try:
            with self._urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            body_excerpt = self._safe_body_excerpt(exc)
            if exc.code in (401, 403):
                msg = (
                    f"authentication failed (HTTP {exc.code}) from {self.base_url} — "
                    "check ERA_LLM_API_KEY"
                )
                raise LLMAuthError(msg) from exc
            msg = f"provider returned HTTP {exc.code} from {self.base_url}{body_excerpt}"
            raise LLMResponseError(msg) from exc
        except TimeoutError as exc:
            msg = f"request timed out after {timeout:.1f}s calling {self.base_url}"
            raise LLMTimeoutError(msg) from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, (TimeoutError, socket.timeout)):
                msg = f"request timed out after {timeout:.1f}s calling {self.base_url}"
                raise LLMTimeoutError(msg) from exc
            msg = f"cannot reach {self.base_url} ({reason})"
            raise LLMConnectionError(msg) from exc

    @staticmethod
    def _safe_body_excerpt(exc: urllib.error.HTTPError) -> str:
        """Read a short error-body excerpt; never raises, never leaks headers."""
        try:
            body = exc.read(1024).decode("utf-8", errors="replace").strip()
        except Exception:  # pragma: no cover - body already consumed/unavailable
            return ""
        body = body.replace("\n", " ")
        if not body:
            return ""
        return f": {body[:_MAX_ERROR_BODY_CHARS]}"

    def _parse(self, body: bytes) -> LLMResponse:
        """Parse a chat-completions response body into an LLMResponse."""
        try:
            data = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            msg = f"provider returned a non-JSON body ({len(body)} bytes) from {self.base_url}"
            raise LLMResponseError(msg) from exc

        choices = data.get("choices") or []
        if not isinstance(choices, list) or not choices:
            msg = f"provider response has no choices from {self.base_url}"
            raise LLMResponseError(msg)
        message = choices[0].get("message") or {}
        content = message.get("content")
        if not isinstance(content, str):
            msg = f"provider response has no text content from {self.base_url}"
            raise LLMResponseError(msg)

        usage_raw = data.get("usage") or {}
        usage = None
        if "prompt_tokens" in usage_raw or "completion_tokens" in usage_raw:
            usage = TokenUsage(
                input_tokens=usage_raw.get("prompt_tokens"),
                output_tokens=usage_raw.get("completion_tokens"),
            )
        return LLMResponse(
            text=content,
            model=data.get("model", self.model),
            usage=usage,
            raw=data,
        )
