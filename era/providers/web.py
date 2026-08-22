"""Real web provider: bounded search, SSRF-safe fetch, and safe downloads.

``WebProvider`` is intentionally narrow:

* ``web.search`` uses DuckDuckGo's keyless Instant Answer API by default, with
  opt-in Bing / Google Custom Search adapters when an operator configures a
  credential.
* ``web.fetch`` accepts public HTTPS text documents only.  Every DNS answer is
  checked before a connection, and the HTTPS transport pins its TCP connection
  to that checked address so a second resolver lookup cannot turn into a DNS
  rebinding request.
* ``web.download`` is the only binary-capable operation.  It writes atomically
  under a configured workspace and returns a size + SHA-256 artifact receipt.

All network work remains behind ``ExecutionService``; this module never makes
permission, confirmation, or audit decisions itself.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.providers._rate_limit import ActorRateLimiter
from era.registry.actions import ActionType
from era.security.path_safety import WorkspaceRoot
from era.security.url_safety import ResolvedPublicURL, resolve_public_url, validate_public_url
from era.security.vault import VaultError, is_vault_ref

DEFAULT_MAX_FETCH_BYTES = 2_097_152  # 2 MiB
DEFAULT_MAX_DOWNLOAD_BYTES = 209_715_200  # 200 MiB
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_USER_AGENT = "ERA-Agent/0.9.0 (+https://github.com/sajanji15859-cmyk/ERA-AI)"
DDG_INSTANT_ANSWER_URL = "https://api.duckduckgo.com/"
BING_SEARCH_URL = "https://api.bing.microsoft.com/v7.0/search"
GOOGLE_SEARCH_URL = "https://www.googleapis.com/customsearch/v1"
# Compatibility alias retained for callers/tests that used the prior HTML URL.
SEARCH_URL = DDG_INSTANT_ANSWER_URL
MAX_SEARCH_RESULTS = 10
MAX_SEARCH_TITLE_CHARS = 200
MAX_SEARCH_SNIPPET_CHARS = 500
MAX_FETCH_TEXT_CHARS = 100_000
MAX_REDIRECTS = 5

_ACTION_TYPES = frozenset({
    ActionType.WEB_SEARCH.value,
    ActionType.WEB_FETCH.value,
    ActionType.WEB_DOWNLOAD.value,
})


@dataclass(frozen=True)
class _HttpResponse:
    body: bytes
    content_type: str
    final_url: str
    truncated: bool
    status_code: int | None = None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that uses a previously checked DNS address.

    ``http.client.HTTPSConnection`` normally resolves ``host`` during
    ``connect()``.  This replacement preserves the original hostname for Host
    and TLS SNI/certificate verification but dials the vetted literal address.
    It is the connection half of the DNS-rebinding defense in
    :mod:`era.security.url_safety`.
    """

    def __init__(self, target: ResolvedPublicURL, *, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 **kwargs):
        self._target = target
        super().__init__(target.host, target.port, timeout=timeout, **kwargs)

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._target.connect_address, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler, urllib.request.HTTPSHandler):
    """HTTPS-only redirect handler with URL validation and pinned connections.

    It intentionally combines redirect handling and HTTPS opening so callers
    can pass *one* handler to ``urllib.request.build_opener``.  That preserves
    the lightweight injection point used by offline tests while ensuring the
    production opener cannot fall back to a DNS-resolving default handler.
    """

    handler_order = 400  # win before urllib's default HTTPSHandler (500)
    max_redirections = MAX_REDIRECTS

    def __init__(self, initial: ResolvedPublicURL | None = None):
        urllib.request.HTTPRedirectHandler.__init__(self)
        urllib.request.HTTPSHandler.__init__(self, context=ssl.create_default_context())
        self._targets: dict[str, ResolvedPublicURL] = {}
        if initial is not None:
            self._targets[initial.url] = initial

    def _target_for(self, url: str) -> ResolvedPublicURL:
        target = self._targets.get(url)
        if target is None:
            target = resolve_public_url(url)
            self._targets[url] = target
        return target

    def https_open(self, req):  # urllib handler protocol
        target = self._target_for(req.full_url)

        def factory(_host, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, **kwargs):
            return _PinnedHTTPSConnection(target, timeout=timeout, **kwargs)

        return self.do_open(factory, req)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        candidate = newurl.replace(" ", "%20")
        # Resolve now and retain the exact safe addresses for the next hop.
        self._targets[candidate] = resolve_public_url(candidate)
        return super().redirect_request(req, fp, code, msg, headers, candidate)


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title: str = ""
        self._in_title = False
        self._skip = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        lowered = tag.lower()
        if lowered == "title":
            self._in_title = True
        if lowered in ("script", "style", "noscript", "template"):
            self._skip += 1

    def handle_endtag(self, tag):
        lowered = tag.lower()
        if lowered == "title":
            self._in_title = False
        if lowered in ("script", "style", "noscript", "template") and self._skip > 0:
            self._skip -= 1

    def handle_data(self, data):
        if self._skip > 0:
            return
        if self._in_title:
            self.title += data
        else:
            self.parts.append(data)


class _DDGResultParser(HTMLParser):
    """Compatibility parser for an HTML-formatted DuckDuckGo response."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.results: list[dict[str, str]] = []
        self._in_result = False
        self._in_link = False
        self._link_href = ""
        self._link_text: list[str] = []
        self._snippet: list[str] = []
        self._depth = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        classes = attrs_dict.get("class", "").split()
        if tag == "div" and "result" in classes and not self._in_result:
            self._in_result = True
            self._depth = 1
            self._link_href = ""
            self._link_text = []
            self._snippet = []
            return
        if self._in_result:
            self._depth += 1
            if tag == "a" and self._link_href == "":
                href = attrs_dict.get("href", "")
                if href.startswith("//duckduckgo.com/l/"):
                    parsed = urllib.parse.urlparse("https:" + href)
                    real = urllib.parse.parse_qs(parsed.query).get("uddg", [""])[0]
                    if real:
                        href = urllib.parse.unquote(real)
                self._in_link = True
                self._link_href = href
            if tag == "a" and "snippet" in classes:
                self._snippet.append("[snip]")

    def handle_endtag(self, tag):
        if self._in_result:
            self._depth -= 1
            if tag == "a":
                self._in_link = False
            if self._depth <= 0:
                self._finish_result()
                self._in_result = False

    def handle_data(self, data):
        if self._in_link:
            self._link_text.append(data)
        elif self._in_result:
            self._snippet.append(data)

    def _finish_result(self):
        if not self._link_href or not self._link_text:
            return
        title = _collapse("".join(self._link_text))
        snippet = _collapse("".join(self._snippet))
        if snippet.startswith("[snip]"):
            snippet = snippet[len("[snip]"):].strip()
        if title:
            self.results.append(_result(title, self._link_href, snippet))


class WebProvider:
    """Keyless web search and HTTPS-only public fetch/download provider."""

    id = "web"
    action_types = _ACTION_TYPES

    def __init__(
        self,
        *,
        max_fetch_bytes: int = DEFAULT_MAX_FETCH_BYTES,
        max_download_bytes: int | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        user_agent: str = DEFAULT_USER_AGENT,
        workspace_root: str | Path | None = None,
        search_api_key: str = "",
        search_provider: str = "",
        search_engine_id: str = "",
        secret_resolver=None,
        max_fetches_per_minute: int = 30,
        rate_limit_window_seconds: float = 60.0,
    ):
        self.max_fetch_bytes = max(1, int(max_fetch_bytes))
        self.max_download_bytes = max(
            1,
            int(max_download_bytes if max_download_bytes is not None else self.max_fetch_bytes),
        )
        self.timeout_seconds = max(0.1, float(timeout_seconds))
        self.user_agent = str(user_agent or DEFAULT_USER_AGENT)
        self.workspace = WorkspaceRoot(workspace_root) if workspace_root is not None else None
        self._search_api_key_ref = str(search_api_key or "").strip()
        self._search_provider = str(search_provider or "").strip().lower()
        self._search_engine_id = str(search_engine_id or "").strip()
        self._resolver = secret_resolver
        self._rate_limiter = ActorRateLimiter(
            limit=max_fetches_per_minute,
            window_seconds=rate_limit_window_seconds,
        )

    # -- SPI -----------------------------------------------------------------
    def validate(self, action: Action) -> None:
        action_type = action.action_type
        params = action.params or {}
        if action_type not in self.action_types:
            raise ToolError(
                f"web cannot handle {action_type}",
                provider_id=self.id,
                code=ProviderErrorCode.NOT_IMPLEMENTED,
            )
        if action_type == ActionType.WEB_SEARCH.value:
            query = params.get("q", params.get("query"))
            if not isinstance(query, str) or not query.strip():
                raise ToolError("'q' is required for web.search", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if len(query) > 500:
                raise ToolError("search query too long", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            return

        url = params.get("url")
        if not isinstance(url, str) or not url:
            raise ToolError("'url' is required", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        validate_public_url(url)
        if action_type == ActionType.WEB_DOWNLOAD.value:
            path = params.get("path")
            if self.workspace is None:
                raise ToolError("web.download needs a workspace root", provider_id=self.id,
                                code=ProviderErrorCode.NOT_IMPLEMENTED)
            if not isinstance(path, str) or not path:
                raise ToolError("'path' is required for web.download", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            self.workspace.resolve(path)

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        self.validate(action)
        if not self._rate_limiter.allow(ctx.actor_id):
            raise ToolError(
                "web provider rate limit exceeded for actor",
                provider_id=self.id,
                code=ProviderErrorCode.FORBIDDEN,
            )

        action_type = action.action_type
        params = action.params or {}
        if action_type == ActionType.WEB_SEARCH.value:
            query = params.get("q", params.get("query"))
            if not isinstance(query, str) or not query.strip():
                raise ToolError("'q' is required for web.search", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            return self._search(query.strip())

        url = params.get("url")
        if not isinstance(url, str) or not url:
            raise ToolError("'url' is required", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        if action_type == ActionType.WEB_FETCH.value:
            return self._fetch(url)
        if action_type == ActionType.WEB_DOWNLOAD.value:
            path = params.get("path")
            if not isinstance(path, str) or not path:
                raise ToolError("'path' is required for web.download", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            return self._download(url, path)
        raise ToolError(f"web cannot handle {action_type}", provider_id=self.id,
                        code=ProviderErrorCode.NOT_IMPLEMENTED)

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.9.0",
            display_name="Web (DuckDuckGo search + pinned HTTPS fetch)",
            is_stub=False,
            capabilities=("search", "fetch", "download", "https-only", "ssrf-pinned"),
        )

    # -- operations ----------------------------------------------------------
    def _search(self, query: str) -> ActionResult:
        provider = self._search_provider or "duckduckgo"
        if provider == "bing":
            results = self._search_bing(query)
        elif provider in ("google", "google_cse", "google-custom-search"):
            results = self._search_google(query)
        elif provider in ("", "duckduckgo", "ddg"):
            results = self._search_duckduckgo(query)
        else:
            raise ToolError(
                "configured web search provider is not supported",
                provider_id=self.id,
                code=ProviderErrorCode.NOT_IMPLEMENTED,
            )
        return ActionResult(
            success=True,
            summary=f"web search returned {len(results)} result(s)",
            data={"query": query, "results": results[:MAX_SEARCH_RESULTS], "provider": provider},
        )

    def _search_duckduckgo(self, query: str) -> list[dict[str, str]]:
        query_string = urllib.parse.urlencode({
            "q": query, "format": "json", "no_html": "1", "skip_disambig": "1",
        })
        url = f"{DDG_INSTANT_ANSWER_URL}?{query_string}"
        response = self._request(url, max_bytes=1_048_576, allow_truncate=True)
        text = self._decode(response.body, response.content_type)
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            # Some test doubles / mirrors return the legacy DDG HTML shape.
            parser = _DDGResultParser()
            parser.feed(text)
            return parser.results[:MAX_SEARCH_RESULTS]
        return _ddg_results(payload)

    def _search_bing(self, query: str) -> list[dict[str, str]]:
        key = self._resolve_secret(self._search_api_key_ref, "web search API key")
        if not key:
            raise ToolError("Bing search API key is not configured", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)
        url = f"{BING_SEARCH_URL}?{urllib.parse.urlencode({'q': query, 'count': MAX_SEARCH_RESULTS})}"
        response = self._request(
            url,
            max_bytes=1_048_576,
            headers={"Ocp-Apim-Subscription-Key": key},
        )
        try:
            items = json.loads(self._decode(response.body, response.content_type)).get("webPages", {}).get("value", [])
        except (json.JSONDecodeError, AttributeError) as exc:
            raise ToolError("Bing search returned an invalid response", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        return [_result(item.get("name", ""), item.get("url", ""), item.get("snippet", ""))
                for item in items if isinstance(item, dict) and item.get("url")][:MAX_SEARCH_RESULTS]

    def _search_google(self, query: str) -> list[dict[str, str]]:
        key = self._resolve_secret(self._search_api_key_ref, "web search API key")
        if not key or not self._search_engine_id:
            raise ToolError("Google Custom Search credentials are not configured", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)
        # Google APIs accept an API-key header. Keeping it out of the URL means
        # it cannot leak through action params, redirect diagnostics, or logs.
        query_string = urllib.parse.urlencode({
            "q": query, "cx": self._search_engine_id, "num": MAX_SEARCH_RESULTS,
        })
        url = f"{GOOGLE_SEARCH_URL}?{query_string}"
        response = self._request(
            url,
            max_bytes=1_048_576,
            headers={"X-Goog-Api-Key": key},
        )
        try:
            items = json.loads(self._decode(response.body, response.content_type)).get("items", [])
        except (json.JSONDecodeError, AttributeError) as exc:
            raise ToolError("Google search returned an invalid response", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        return [_result(item.get("title", ""), item.get("link", ""), item.get("snippet", ""))
                for item in items if isinstance(item, dict) and item.get("link")][:MAX_SEARCH_RESULTS]

    def _fetch(self, url: str) -> ActionResult:
        response = self._request(url, max_bytes=self.max_fetch_bytes, allow_truncate=True)
        if response.content_type and not _is_textual_content_type(response.content_type):
            raise ToolError(
                f"web.fetch rejects non-text content type {response.content_type!r}; use web.download",
                provider_id=self.id,
                code=ProviderErrorCode.FORBIDDEN,
            )
        text = self._decode(response.body, response.content_type)
        extractor = _TextExtractor()
        try:
            extractor.feed(text)
        except Exception:  # noqa: BLE001,S110 -- malformed HTML is still fetchable text
            pass
        body_text = _collapse(" ".join(extractor.parts))
        return ActionResult(
            success=True,
            summary=f"fetched {len(response.body)} bytes from {response.final_url}",
            data={
                "url": response.final_url,
                "title": _collapse(extractor.title)[:300],
                "text": body_text[:MAX_FETCH_TEXT_CHARS],
                "bytes": len(response.body),
                "content_type": response.content_type or "unknown",
                "truncated": response.truncated,
            },
        )

    def _download(self, url: str, path: str) -> ActionResult:
        if self.workspace is None:
            raise ToolError("web.download needs a workspace root", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)
        response = self._request(url, max_bytes=self.max_download_bytes, allow_truncate=False)
        resolved = self.workspace.resolve(path)
        _atomic_write(resolved, response.body, provider_id=self.id)
        digest = hashlib.sha256(response.body).hexdigest()
        return ActionResult(
            success=True,
            summary=f"downloaded {len(response.body)} bytes",
            data={
                "path": self.workspace.path_of(resolved),
                "bytes": len(response.body),
                "size": len(response.body),
                "sha256": digest,
                "url": response.final_url,
                "content_type": response.content_type or "application/octet-stream",
            },
        )

    def max_file_bytes(self) -> int:
        """Compatibility helper: the configured download artifact cap."""

        return self.max_download_bytes

    # -- transport -----------------------------------------------------------
    def _http_get(self, url: str, max_bytes: int) -> bytes:
        """Legacy helper retained for provider extensions and old tests."""

        return self._request(url, max_bytes=max_bytes, allow_truncate=True).body

    def _request(self, url: str, *, max_bytes: int, allow_truncate: bool = True,
                 headers: dict[str, str] | None = None) -> _HttpResponse:
        if max_bytes < 1:
            raise ToolError("response byte limit must be positive", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        # Resolve before constructing the opener.  SafeRedirectHandler passes
        # this exact resolved target to its first TCP connection, not merely a
        # hostname that urllib would resolve again.
        target = resolve_public_url(url)
        request_headers = {
            "User-Agent": self.user_agent,
            "Accept-Encoding": "identity",
            "Accept": "text/html,application/xhtml+xml,text/plain,application/json,application/xml;q=0.9,*/*;q=0.1",
        }
        request_headers.update(headers or {})
        request = urllib.request.Request(url, headers=request_headers)
        opener = urllib.request.build_opener(SafeRedirectHandler(target))
        try:
            with opener.open(request, timeout=self.timeout_seconds) as response:
                declared = _content_length(getattr(response, "headers", None))
                if declared is not None and declared > max_bytes and not allow_truncate:
                    raise ToolError(
                        f"response exceeds configured download cap ({declared} > {max_bytes} bytes)",
                        provider_id=self.id,
                        code=ProviderErrorCode.PROVIDER_ERROR,
                    )
                raw = response.read(max_bytes + 1)
                truncated = len(raw) > max_bytes
                if truncated:
                    raw = raw[:max_bytes]
                if truncated and not allow_truncate:
                    raise ToolError(
                        f"response exceeds configured download cap ({max_bytes} bytes)",
                        provider_id=self.id,
                        code=ProviderErrorCode.PROVIDER_ERROR,
                    )
                response_headers = getattr(response, "headers", None)
                content_type = _header(response_headers, "Content-Type")
                final_url = getattr(response, "geturl", lambda: url)() or url
                # The redirect handler already checked every hop.  Validate the
                # final URL once more defensively in case a custom opener is
                # injected by a test/embedding integration.
                validate_public_url(final_url)
                return _HttpResponse(
                    body=raw,
                    content_type=content_type,
                    final_url=final_url,
                    truncated=truncated,
                    status_code=getattr(response, "status", None),
                )
        except ToolError:
            raise
        except urllib.error.HTTPError as exc:
            code = int(exc.code) if isinstance(exc.code, int) else 0
            if code == 403:
                raise ToolError("target forbids access (HTTP 403)", provider_id=self.id,
                                code=ProviderErrorCode.FORBIDDEN) from exc
            if code in (404, 410):
                raise ToolError(f"resource not found (HTTP {code})", provider_id=self.id,
                                code=ProviderErrorCode.NOT_FOUND) from exc
            if code in (408, 429) or code >= 500:
                raise ToolError(f"target temporarily unavailable (HTTP {code})", provider_id=self.id,
                                code=ProviderErrorCode.UNAVAILABLE) from exc
            raise ToolError(f"fetch failed (HTTP {code})", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        except TimeoutError as exc:
            raise ToolError("web request timed out", provider_id=self.id,
                            code=ProviderErrorCode.TIMEOUT) from exc
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            raise ToolError("network unavailable", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc

    def _resolve_secret(self, ref_or_plain: str, label: str) -> str:
        if not ref_or_plain:
            return ""
        if not is_vault_ref(ref_or_plain):
            return ref_or_plain
        if self._resolver is None:
            raise ToolError(f"{label} is a vault reference but no resolver is attached",
                            provider_id=self.id, code=ProviderErrorCode.AUTH)
        try:
            return self._resolver.resolve_ref(ref_or_plain, actor_id="web-provider")
        except (VaultError, ValueError, TypeError) as exc:
            raise ToolError(f"{label} could not be resolved from the vault",
                            provider_id=self.id, code=ProviderErrorCode.AUTH) from exc

    @staticmethod
    def _decode(raw: bytes, content_type: str) -> str:
        for charset in _charsets(content_type):
            try:
                return raw.decode(charset)
            except (LookupError, UnicodeDecodeError):
                continue
        return raw.decode("utf-8", errors="replace")


def _ddg_results(payload: Any) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    results: list[dict[str, str]] = []
    abstract_url = payload.get("AbstractURL")
    abstract_text = payload.get("AbstractText")
    heading = payload.get("Heading") or payload.get("AbstractSource")
    if isinstance(abstract_url, str) and abstract_url and isinstance(abstract_text, str):
        results.append(_result(str(heading or abstract_url), abstract_url, abstract_text))

    def visit(items: Any) -> None:
        if len(results) >= MAX_SEARCH_RESULTS:
            return
        if isinstance(items, list):
            for item in items:
                visit(item)
                if len(results) >= MAX_SEARCH_RESULTS:
                    return
        elif isinstance(items, dict):
            nested = items.get("Topics")
            if nested is not None:
                visit(nested)
            url = items.get("FirstURL")
            text = items.get("Text")
            if isinstance(url, str) and url and isinstance(text, str):
                results.append(_result(text.split(" - ", 1)[0], url, text))

    visit(payload.get("RelatedTopics", []))
    return results[:MAX_SEARCH_RESULTS]


def _result(title: Any, url: Any, snippet: Any) -> dict[str, str]:
    return {
        "title": _collapse(str(title))[:MAX_SEARCH_TITLE_CHARS],
        "url": str(url)[:2048],
        "snippet": _collapse(str(snippet))[:MAX_SEARCH_SNIPPET_CHARS],
    }


def _collapse(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _is_textual_content_type(content_type: str) -> bool:
    mime = content_type.split(";", 1)[0].strip().lower()
    return (
        mime.startswith("text/")
        or mime in {
            "application/json", "application/ld+json", "application/xml",
            "application/xhtml+xml", "application/rss+xml", "application/atom+xml",
        }
        or mime.endswith(("+json", "+xml"))
    )


def _header(headers: Any, name: str) -> str:
    if headers is None:
        return ""
    get = getattr(headers, "get", None)
    if callable(get):
        value = get(name, "")
        return str(value or "")
    return ""


def _content_length(headers: Any) -> int | None:
    raw = _header(headers, "Content-Length")
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value >= 0 else None


def _atomic_write(path: Path, content: bytes, *, provider_id: str) -> None:
    temporary_path: str | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_path = tempfile.mkstemp(prefix=".era-download-", dir=path.parent)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    except OSError as exc:
        raise ToolError("download write failed", provider_id=provider_id,
                        code=ProviderErrorCode.PROVIDER_ERROR) from exc
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


def _charsets(content_type: str):
    match = re.search(r"charset=[\"']?([\w\-]+)", content_type or "", re.IGNORECASE)
    if match:
        yield match.group(1)
    yield "utf-8"
    yield "latin-1"
