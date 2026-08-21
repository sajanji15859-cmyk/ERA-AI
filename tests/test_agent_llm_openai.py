"""OpenAICompatLLMProvider tests — request shape, parsing, error mapping (no network)."""

from __future__ import annotations

import json

import pytest

from era.core.llm import LLMRequest
from era.core.result import ProviderErrorCode, ToolError
from era.providers.llm_openai import OpenAICompatLLMProvider


def _provider(**kw):
    return OpenAICompatLLMProvider(base_url="https://api.example.com/v1",
                                   api_key="test-key-not-a-secret", model="m", **kw)


class _FakeResponse:
    def __init__(self, payload: dict, status=200):
        self.payload = payload
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n):
        return json.dumps(self.payload).encode("utf-8")


def test_requires_api_key():
    with pytest.raises(ValueError):
        OpenAICompatLLMProvider(base_url="https://x/v1", api_key="", model="m")


def test_complete_parses_content_and_usage(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["data"] = json.loads(request.data.decode("utf-8"))
        assert request.get_header("Authorization") == "Bearer test-key-not-a-secret"
        return _FakeResponse({
            "choices": [{"message": {"content": "hello", "tool_calls": None}}],
            "usage": {"total_tokens": 17},
        })

    monkeypatch.setattr("era.providers.llm_openai.urllib.request.urlopen", fake_urlopen)
    resp = _provider().complete(LLMRequest(
        messages=[{"role": "user", "content": "hi"}], max_tokens=64))
    assert resp.text == "hello"
    assert resp.usage == {"total_tokens": 17}
    assert captured["data"]["model"] == "m"
    assert captured["data"]["max_tokens"] == 64


def test_complete_parses_native_tool_calls(monkeypatch):
    def fake_urlopen(request, timeout=None):
        return _FakeResponse({
            "choices": [{"message": {"content": "",
                                     "tool_calls": [
                                         {"id": "c1", "type": "function",
                                          "function": {"name": "fs.write",
                                                       "arguments": '{"path": "a.txt"}'}}]}}],
            "usage": {"total_tokens": 5},
        })

    monkeypatch.setattr("era.providers.llm_openai.urllib.request.urlopen", fake_urlopen)
    resp = _provider().complete(LLMRequest(messages=[], metadata={"tools": [{"type": "function"}]}))
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].action_type == "fs.write"
    assert resp.tool_calls[0].params == {"path": "a.txt"}


@pytest.mark.parametrize("status,expected_code", [
    (401, ProviderErrorCode.AUTH),
    (403, ProviderErrorCode.AUTH),
    (429, ProviderErrorCode.UNAVAILABLE),
    (500, ProviderErrorCode.UNAVAILABLE),
    (400, ProviderErrorCode.VALIDATION),
])
def test_http_error_mapping(monkeypatch, status, expected_code):
    import urllib.error

    def fake_urlopen(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, status, "err", {}, None)

    monkeypatch.setattr("era.providers.llm_openai.urllib.request.urlopen", fake_urlopen)
    with pytest.raises(ToolError) as err:
        _provider().complete(LLMRequest(messages=[]))
    assert err.value.code is expected_code


def test_network_error_maps_to_unavailable(monkeypatch):
    import urllib.error

    def fake_urlopen(request, timeout=None):
        raise urllib.error.URLError("down")

    monkeypatch.setattr("era.providers.llm_openai.urllib.request.urlopen", fake_urlopen)
    with pytest.raises(ToolError) as err:
        _provider().complete(LLMRequest(messages=[]))
    assert err.value.code is ProviderErrorCode.UNAVAILABLE


def test_garbage_response_maps_to_provider_error(monkeypatch):
    def fake_urlopen(request, timeout=None):
        return _FakeResponse({"choices": [{"message": None}]})

    monkeypatch.setattr("era.providers.llm_openai.urllib.request.urlopen", fake_urlopen)
    with pytest.raises(ToolError) as err:
        _provider().complete(LLMRequest(messages=[]))
    assert err.value.code is ProviderErrorCode.PROVIDER_ERROR


def test_stream_falls_back_to_complete(monkeypatch):
    def fake_urlopen(request, timeout=None):
        return _FakeResponse({"choices": [{"message": {"content": "one"}}]})

    monkeypatch.setattr("era.providers.llm_openai.urllib.request.urlopen", fake_urlopen)
    chunks = list(_provider().stream(LLMRequest(messages=[])))
    assert [c.text for c in chunks] == ["one"]


def test_describe_has_no_secrets():
    info = _provider().describe()
    assert "test-key-not-a-secret" not in info.to_dict().__repr__()
    assert info.is_stub is False
