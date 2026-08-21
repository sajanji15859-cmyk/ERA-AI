"""WebProvider + SSRF guard tests (Phase 3A) — all offline (no real network)."""

from __future__ import annotations

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError
from era.providers.web import WebProvider
from era.security.url_safety import validate_public_url

CTX = ExecutionContext(actor_id="t")


@pytest.fixture
def provider(tmp_path):
    return WebProvider(workspace_root=tmp_path / "ws", timeout_seconds=2.0,
                       max_fetch_bytes=100_000)


# -- URL safety ---------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "ftp://example.com/x",          # scheme
    "file:///etc/passwd",           # scheme
    "http://127.0.0.1/x",           # loopback literal
    "http://10.0.0.1/x",            # private literal
    "http://169.254.169.254/latest/meta-data",  # link-local (cloud metadata!)
    "http://192.168.1.1/x",         # private literal
    "http://[::1]/x",               # IPv6 loopback
    "http://0.0.0.0/x",             # unspecified
    "http://user:pass@example.com/x",  # creds in URL
    "http://example.com:8080/x",    # non-80/443 port
])
def test_ssrf_guards_reject(bad):
    with pytest.raises(ToolError) as err:
        validate_public_url(bad)
    assert err.value.code in (ProviderErrorCode.FORBIDDEN, ProviderErrorCode.VALIDATION)


def test_public_url_accepted():
    scheme, host, port = validate_public_url("https://example.com/a?b=c")
    assert (scheme, host, port) == ("https", "example.com", 443)


def test_localhost_resolution_blocked(monkeypatch):
    # A hostname resolving to a loopback address must be blocked (DNS-rebinding
    # guard at pre-connect time).
    import socket

    # getaddrinfo returns 5-tuples: (family, type, proto, canonname, sockaddr).
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(0, 0, 0, "", ("127.0.0.1", 80))])
    with pytest.raises(ToolError) as err:
        validate_public_url("http://evil.example.com/")
    assert err.value.code is ProviderErrorCode.FORBIDDEN


# -- provider validation --------------------------------------------------------

def test_search_validation(provider):
    provider.validate(Action(action_type="web.search", params={"q": "welding"}))
    with pytest.raises(ToolError):
        provider.validate(Action(action_type="web.search", params={}))
    with pytest.raises(ToolError):
        provider.validate(Action(action_type="web.search", params={"q": "x" * 600}))


def test_fetch_validation_applies_ssrf(provider):
    with pytest.raises(ToolError) as err:
        provider.validate(Action(action_type="web.fetch",
                                params={"url": "http://169.254.169.254/x"}))
    assert err.value.code is ProviderErrorCode.FORBIDDEN


def test_download_validation_requires_path(provider):
    with pytest.raises(ToolError):
        provider.validate(Action(action_type="web.download",
                                params={"url": "https://example.com/f.txt"}))
    provider.validate(Action(action_type="web.download",
                             params={"url": "https://example.com/f.txt",
                                     "path": "dl/f.txt"}))


# -- result parsing (no network) ------------------------------------------------

def test_search_result_parser(monkeypatch, provider):
    from era.providers.web import _DDGResultParser
    html = """
    <div class="result">
      <a href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fwelding">Welding guide</a>
      <a class="snippet">Learn welding safely.</a>
    </div>
    <div class="result">
      <a href="https://other.org/x">Other</a>
      <a class="snippet">Other thing.</a>
    </div>
    """
    parser = _DDGResultParser()
    parser.feed(html)
    assert len(parser.results) == 2
    assert parser.results[0]["url"] == "https://example.com/welding"
    assert parser.results[0]["title"] == "Welding guide"
    assert parser.results[0]["snippet"] == "Learn welding safely."


def test_search_network_failure_maps_to_unavailable(monkeypatch, provider):
    import urllib.error

    class BoomOpen:
        def open(self, *a, **k):
            raise urllib.error.URLError("offline")

    monkeypatch.setattr("era.providers.web.urllib.request.build_opener",
                        lambda handler: BoomOpen())
    with pytest.raises(ToolError) as err:
        provider.execute(Action(action_type="web.search", params={"q": "x"}), CTX)
    assert err.value.code is ProviderErrorCode.UNAVAILABLE


def test_fetch_extracts_title_and_text(monkeypatch, provider):
    html = b"<html><head><title>Hello</title></head><body><p>Some body text.</p></body></html>"

    class FakeResp:
        def __init__(self):
            self.headers: dict = {}

        def read(self, n):
            return html[:n]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeOpen:
        def open(self, *a, **k):
            return FakeResp()

    monkeypatch.setattr("era.providers.web.urllib.request.build_opener",
                        lambda handler: FakeOpen())
    result = provider.execute(Action(action_type="web.fetch",
                                     params={"url": "https://example.com/"}), CTX)
    assert result.success
    assert result.data["title"] == "Hello"
    assert "body text" in result.data["text"]


def test_redirect_handler_revalidates(monkeypatch):
    import urllib.request

    from era.providers.web import SafeRedirectHandler
    handler = SafeRedirectHandler()
    with pytest.raises(ToolError):
        handler.redirect_request(urllib.request.Request("https://example.com/"),
                                 None, 302, "Found", {},
                                 "http://127.0.0.1/steal")


def test_download_writes_into_workspace(monkeypatch, provider):
    class FakeResp:
        def __init__(self):
            self.headers: dict = {}

        def read(self, n):
            return b"data"[:n]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeOpen:
        def open(self, *a, **k):
            return FakeResp()

    monkeypatch.setattr("era.providers.web.urllib.request.build_opener",
                        lambda handler: FakeOpen())
    result = provider.execute(Action(action_type="web.download",
                                     params={"url": "https://example.com/f.txt",
                                             "path": "dl/f.txt"}), CTX)
    assert result.success
    assert (provider.workspace.root / "dl" / "f.txt").read_bytes() == b"data"


def test_provider_contract_suite(provider):
    # SPI shape + catalog membership + validate semantics (no network):
    # validation of the first claimed action rejects (missing params) with a
    # ToolError, which the contract accepts — no socket is ever opened.
    from tests.provider_contract import assert_provider_contract
    assert_provider_contract(provider)
