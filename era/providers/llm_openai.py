"""OpenAI-compatible LLM provider (Phase 3A, SSE streaming in 3B).

Talks to any OpenAI-compatible ``chat/completions`` endpoint — OpenAI free
tier, Groq, OpenRouter, Together, a local Ollama gateway, etc. Configure via:

    ERA_AGENT_LLM_PROVIDER=openai
    ERA_AGENT_LLM_BASE_URL=https://api.openai.com/v1   (or another base URL)
    ERA_AGENT_LLM_MODEL=gpt-4o-mini
    ERA_AGENT_LLM_API_KEY=...   (env only — NEVER committed or logged)

The provider owns its API key: the key never appears in requests, results,
audit summaries or error messages. HTTP errors are mapped onto the stable
``ProviderErrorCode`` taxonomy so the retry/circuit-breaker layers react
deterministically (401 → AUTH never retried; 429/5xx → UNAVAILABLE retried
boundedly; timeout → TIMEOUT never retried).

With no key configured the agent runs in offline deterministic mode (the
provider is simply not built) — see AGENT_AUDIT_AND_PLAN.md §E.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

from era.core.llm import LLMRequest, LLMResponse, ToolCall
from era.core.provider_info import ProviderInfo
from era.core.result import ProviderErrorCode, ToolError

DEFAULT_TIMEOUT_SECONDS = 60.0


class OpenAICompatLLMProvider:
    """A real, key-owning LLM provider. Implements the ``LLMProvider`` protocol."""

    id = "openai"

    def __init__(self, *, base_url: str, api_key: str, model: str,
                 timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
                 temperature: float = 0.2):
        if not api_key or not isinstance(api_key, str):
            raise ValueError("OpenAICompatLLMProvider requires an API key")
        self.base_url = str(base_url).rstrip("/")
        self._api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.temperature = temperature

    # -- LLMProvider -------------------------------------------------------------
    def complete(self, req: LLMRequest) -> LLMResponse:
        payload = self._payload(req, stream=False)
        body = json.dumps(payload).encode("utf-8")
        request = self._request(body, accept="application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as resp:
                raw = resp.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            self._raise_http(exc)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ToolError("LLM provider unreachable", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc
        try:
            doc = json.loads(raw.decode("utf-8"))
            message = doc["choices"][0]["message"]
            if not isinstance(message, dict):
                raise TypeError("message is not an object")
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ToolError("LLM provider returned an unparseable response",
                            provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc

        tool_calls: list[ToolCall] = []
        for i, raw_call in enumerate(message.get("tool_calls") or []):
            function = raw_call.get("function") or {}
            name = str(function.get("name") or "")
            try:
                arguments = json.loads(function.get("arguments") or "{}")
            except (TypeError, ValueError):
                arguments = {}
            tool_calls.append(ToolCall(id=str(raw_call.get("id") or i),
                                       action_type=name, params=arguments))

        usage = doc.get("usage") or {}
        return LLMResponse(text=str(message.get("content") or ""),
                           tool_calls=tool_calls, usage=usage)

    def stream(self, req: LLMRequest) -> Iterator[LLMResponse]:
        """Real SSE token streaming (Phase 3B).

        Parses ``text/event-stream`` chunks from the provider, yielding one
        :class:`LLMResponse` per content delta; the final chunk carries the
        provider's usage block (requested via ``stream_options``).
        """
        payload = self._payload(req, stream=True)
        body = json.dumps(payload).encode("utf-8")
        request = self._request(body, accept="text/event-stream")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as resp:
                for line in resp:
                    parsed = _parse_sse_line(line)
                    if parsed is None:
                        continue
                    content, usage = parsed
                    if content is None:
                        continue
                    yield LLMResponse(text=content, usage=usage)
        except urllib.error.HTTPError as exc:
            self._raise_http(exc)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ToolError("LLM provider unreachable", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=frozenset(),
            version="0.3.0",
            display_name=f"OpenAI-compatible LLM ({self.model})",
            is_stub=False,
            capabilities=("chat", "tool_calls", "stream"),
        )

    # -- internals ---------------------------------------------------------------
    def _payload(self, req: LLMRequest, *, stream: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": req.messages,
            "temperature": self.temperature,
            "stream": stream,
        }
        if stream:
            payload["stream_options"] = {"include_usage": True}
        if req.max_tokens is not None and req.max_tokens > 0:
            payload["max_tokens"] = int(req.max_tokens)
        tools = (req.metadata or {}).get("tools")
        if isinstance(tools, list) and tools and not stream:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        return payload

    def _request(self, body: bytes, *, accept: str) -> urllib.request.Request:
        return urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
                "User-Agent": "ERA-Agent/0.3",
                "Accept": accept,
            },
        )

    def _raise_http(self, exc: urllib.error.HTTPError) -> None:
        code = exc.code if isinstance(exc.code, int) else 0
        if code in (401, 403):
            raise ToolError("LLM provider rejected authentication (401/403)",
                            provider_id=self.id, code=ProviderErrorCode.AUTH) from exc
        if code == 429 or code >= 500:
            raise ToolError(f"LLM provider unavailable (HTTP {code})",
                            provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc
        raise ToolError(f"LLM provider rejected the request (HTTP {code})",
                        provider_id=self.id,
                        code=ProviderErrorCode.VALIDATION) from exc


def _parse_sse_line(line: Any) -> tuple[str | None, dict[str, Any] | None] | None:
    """Parse one SSE line. Returns (content_delta, usage) or None to skip."""
    if isinstance(line, bytes):
        try:
            line = line.decode("utf-8")
        except UnicodeDecodeError:
            return None
    line = (line or "").strip()
    if not line.startswith("data:"):
        return None
    data = line[len("data:"):].strip()
    if data == "[DONE]":
        return None
    try:
        chunk = json.loads(data)
    except (TypeError, ValueError):
        return None  # tolerate malformed keep-alive frames
    if not isinstance(chunk, dict):
        return None
    choices = chunk.get("choices") or []
    if not choices:
        usage = chunk.get("usage")
        return ("", usage) if isinstance(usage, dict) else None
    first = choices[0]
    if not isinstance(first, dict):
        return None
    delta = first.get("delta") or {}
    if not isinstance(delta, dict):
        return None
    content = delta.get("content")
    if content is None:
        return None
    return str(content), chunk.get("usage") if isinstance(chunk.get("usage"), dict) else None
