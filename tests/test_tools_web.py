"""Tests for the read-only web tools (era.tools.web).

All tests run offline against a fake transport — no real network access.
"""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest
from era.config import WebToolSettings
from era.tools.web import WebFetchTool, WebSearchTool, html_to_text, is_private_host, validate_url


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, content_type: str = "text/html") -> None:
        self._body = body
        self.status = status
        self.headers = {"Content-Type": content_type}

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self, *args: Any) -> bytes:
        return self._body


class TransportRecorder:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.requests: list[tuple[Any, float | None]] = []

    def __call__(self, request: Any, timeout: float | None = None) -> Any:
        self.requests.append((request, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def settings(**overrides: Any) -> WebToolSettings:
    return WebToolSettings(**overrides)


def page(body: str | bytes, content_type: str = "text/html") -> FakeResponse:
    payload = body.encode() if isinstance(body, str) else body
    return FakeResponse(payload, content_type=content_type)


class TestValidateUrl:
    @pytest.mark.parametrize(
        "url",
        ["file:///etc/passwd", "ftp://example.com/x", "gopher://x", "javascript:alert(1)"],
    )
    def test_non_http_schemes_rejected(self, url: str) -> None:
        with pytest.raises(Exception, match="http/https"):
            validate_url(url, allow_private=False)

    def test_userinfo_rejected(self) -> None:
        with pytest.raises(Exception, match="credentials"):
            validate_url("https://user:pass@example.com/", allow_private=False)

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://192.168.1.1/router",
            "http://10.0.0.5/",
            "http://172.16.0.1/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data",
            "http://myhost.local/",
            "http://service.internal/",
        ],
    )
    def test_private_targets_rejected(self, url: str) -> None:
        with pytest.raises(Exception, match="private"):
            validate_url(url, allow_private=False)

    def test_private_allowed_when_opted_in(self) -> None:
        url = validate_url("http://127.0.0.1:8080/", allow_private=True)
        assert url == "http://127.0.0.1:8080/"

    def test_public_url_ok(self) -> None:
        assert validate_url("https://example.com/page", allow_private=False)

    def test_is_private_host_literals(self) -> None:
        assert is_private_host("localhost")
        assert is_private_host("10.1.2.3")
        assert is_private_host("127.0.0.1")
        assert not is_private_host("example.com")
        assert not is_private_host("8.8.8.8")


class TestHtmlToText:
    def test_strips_script_and_style(self) -> None:
        html = (
            "<html><head><style>.x{color:red}</style><script>alert(1)</script></head>"
            "<body><h1>Title</h1><p>Hello   world</p></body></html>"
        )
        text = html_to_text(html)
        assert "Title" in text and "Hello world" in text
        assert "alert" not in text and "color" not in text

    def test_block_tags_break_lines(self) -> None:
        assert "one\ntwo" in html_to_text("<p>one</p><p>two</p>")


class TestWebFetch:
    def test_success(self) -> None:
        recorder = TransportRecorder(page("<html><body><p>hello web</p></body></html>"))
        result = WebFetchTool(settings(), transport=recorder).execute(
            {"url": "https://example.com/"}
        )
        assert result.ok and "hello web" in result.output
        assert result.data["content_type"] == "text/html"

    def test_request_headers_and_timeout(self) -> None:
        recorder = TransportRecorder(page("x"))
        WebFetchTool(settings(timeout_s=7.0), transport=recorder).execute(
            {"url": "https://example.com/"}
        )
        request, timeout = recorder.requests[0]
        assert request.get_header("User-agent") == settings().user_agent
        assert timeout == 7.0

    def test_plain_text_content_type(self) -> None:
        recorder = TransportRecorder(page("just text", content_type="text/plain"))
        result = WebFetchTool(settings(), transport=recorder).execute(
            {"url": "https://example.com/"}
        )
        assert result.ok and result.output == "just text"

    def test_unsupported_content_type(self) -> None:
        recorder = TransportRecorder(page(b"\x89PNG", content_type="image/png"))
        result = WebFetchTool(settings(), transport=recorder).execute(
            {"url": "https://example.com/"}
        )
        assert not result.ok and "image/png" in result.error

    def test_http_error(self) -> None:
        error = urllib.error.HTTPError(
            "https://example.com/",
            404,
            "Not Found",
            None,
            None,  # type: ignore[arg-type]
        )
        result = WebFetchTool(settings(), transport=TransportRecorder(error)).execute(
            {"url": "https://example.com/"}
        )
        assert not result.ok and "404" in result.error

    def test_redirected_to_file_scheme_refused(self) -> None:
        error = urllib.error.HTTPError(
            "https://example.com/x",
            302,
            "Found",
            None,
            None,  # type: ignore[arg-type]
        )
        result = WebFetchTool(settings(), transport=TransportRecorder(error)).execute(
            {"url": "https://example.com/x"}
        )
        assert not result.ok and "redirect" in result.error

    def test_network_error(self) -> None:
        error = urllib.error.URLError(ConnectionRefusedError("refused"))
        result = WebFetchTool(settings(), transport=TransportRecorder(error)).execute(
            {"url": "https://example.com/"}
        )
        assert not result.ok and "cannot fetch" in result.error

    def test_private_url_rejected_before_any_request(self) -> None:
        recorder = TransportRecorder(page("x"))
        result = WebFetchTool(settings(), transport=recorder).execute(
            {"url": "http://169.254.169.254/meta"}
        )
        assert not result.ok and "private" in result.error
        assert recorder.requests == []  # never touched the network

    def test_output_char_cap(self) -> None:
        recorder = TransportRecorder(page("<p>" + "z" * 100 + "</p>"))
        result = WebFetchTool(settings(output_char_limit=50), transport=recorder).execute(
            {"url": "https://example.com/"}
        )
        assert result.ok and len(result.output.split("[...")[0].strip()) <= 50
        assert "truncated" in result.output

    def test_byte_cap(self) -> None:
        recorder = TransportRecorder(page("b" * 5000))
        result = WebFetchTool(settings(max_bytes=100), transport=recorder).execute(
            {"url": "https://example.com/"}
        )
        assert result.ok and "byte cap" in result.output


DDG_LITE = """
<html><body><table>
<tr><td><a class="result-link" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa">
Result A</a></td></tr>
<tr><td class="result-snippet">Snippet about A</td></tr>
<tr><td><a class="result-link" href="https://example.org/b">Result B</a>
</td></tr>
<tr><td class="result-snippet">Snippet about B</td></tr>
</table></body></html>
"""


class TestWebSearch:
    def test_duckduckgo_parsing(self) -> None:
        recorder = TransportRecorder(page(DDG_LITE))
        result = WebSearchTool(settings(), transport=recorder).execute({"query": "test query"})
        assert result.ok
        results = result.data["results"]
        assert len(results) == 2
        assert results[0]["url"] == "https://example.com/a"  # unwrapped from DDG redirect
        assert results[0]["title"] == "Result A"
        assert results[0]["snippet"] == "Snippet about A"
        assert "1. Result A" in result.output

    def test_max_results(self) -> None:
        recorder = TransportRecorder(page(DDG_LITE))
        result = WebSearchTool(settings(), transport=recorder).execute(
            {"query": "q", "max_results": 1}
        )
        assert len(result.data["results"]) == 1

    def test_no_results(self) -> None:
        recorder = TransportRecorder(page("<html><body><table></table></body></html>"))
        result = WebSearchTool(settings(), transport=recorder).execute({"query": "void"})
        assert result.ok and "No results" in result.output

    def test_searxng_provider(self) -> None:
        payload = json.dumps(
            {
                "results": [
                    {"title": "S1", "url": "https://s.example/1", "content": "cs1"},
                    {"title": "S2", "url": "https://s.example/2", "content": "cs2"},
                ]
            }
        ).encode()
        recorder = TransportRecorder(FakeResponse(payload, content_type="application/json"))
        result = WebSearchTool(
            settings(search="searxng", searxng_url="http://searx.example"),
            transport=recorder,
        ).execute({"query": "q"})
        assert result.ok and result.data["provider"] == "searxng"
        assert result.data["results"][0]["url"] == "https://s.example/1"

    def test_query_validation(self) -> None:
        from era.tools.base import ToolValidationError

        recorder = TransportRecorder(page("x"))
        tool = WebSearchTool(settings(), transport=recorder)
        with pytest.raises(ToolValidationError):
            tool.validate({"query": ""})
        with pytest.raises(ToolValidationError):
            tool.validate({"query": "x" * 401})
        with pytest.raises(ToolValidationError):
            tool.validate({"query": "q", "max_results": 99})
