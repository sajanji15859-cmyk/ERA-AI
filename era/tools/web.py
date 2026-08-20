"""Read-only web tools: ``web.fetch`` and ``web.search``.

Security model (hard boundaries):

* ``http``/``https`` only; URLs containing userinfo (``user:pass@``) rejected.
* Private/loopback/link-local targets are blocked by default (best-effort
  SSRF guard against literal IPs, ``localhost``, ``*.local``); DNS-rebinding
  races are out of scope for Phase 1. Opt-in via ``allow_private_networks``.
* Redirects are re-validated (non-http(s) and private targets are refused).
* Response size and output character caps; text content types only.
* No credentials, cookies, or auth headers of any kind are ever attached.
"""

from __future__ import annotations

import html as html_module
import html.parser
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

from era.tools.base import RiskLevel, Tool, ToolResult, ToolValidationError

Transport = Callable[..., Any]

_ALLOWED_CONTENT_TYPES = frozenset({"text/html", "text/plain", "application/json"})
_PRIVATE_SUFFIXES = (".local", ".internal", ".localhost")
_MAX_QUERY_LENGTH = 400
_MAX_RESULTS_CAP = 10


# ---------------------------------------------------------------------------
# URL / host safety
# ---------------------------------------------------------------------------


def validate_url(url: str, *, allow_private: bool) -> str:
    """Validate a URL for fetching; raise ToolValidationError on policy violation."""
    if not isinstance(url, str) or not url.strip():
        msg = "url must be a non-empty string"
        raise ToolValidationError(msg)
    url = url.strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        msg = f"only http/https URLs are allowed (got scheme {parts.scheme!r})"
        raise ToolValidationError(msg)
    if parts.username or parts.password:
        msg = "URLs containing credentials (user:pass@host) are not allowed"
        raise ToolValidationError(msg)
    host = parts.hostname
    if not host:
        msg = "URL has no hostname"
        raise ToolValidationError(msg)
    if not allow_private and is_private_host(host):
        msg = (
            f"refusing to fetch private/loopback host {host!r} "
            "(set [tools.web] allow_private_networks = true to override for local testing)"
        )
        raise ToolValidationError(msg)
    return url


def is_private_host(host: str) -> bool:
    """Best-effort check: is ``host`` a private/loopback/link-local target?

    Checks literal IPs and obvious local names; does NOT resolve DNS.
    """
    host = host.lower().rstrip(".")
    if host == "localhost" or host.endswith(_PRIVATE_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses non-http(s) and (optionally) private targets."""

    def __init__(self, allow_private: bool = False) -> None:
        self.allow_private = allow_private

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        parts = urlsplit(newurl)
        if parts.scheme not in ("http", "https"):
            return None
        host = parts.hostname or ""
        if not self.allow_private and is_private_host(host):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def default_transport(allow_private: bool) -> Transport:
    """Build the production transport: an opener with the safe redirect handler."""
    return urllib.request.build_opener(_SafeRedirectHandler(allow_private)).open


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

_SKIP_TAGS = frozenset({"script", "style", "noscript", "template", "svg"})
_BLOCK_TAGS = frozenset(
    {
        "p",
        "div",
        "br",
        "li",
        "ul",
        "ol",
        "tr",
        "table",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "section",
        "article",
    }
)


class _TextExtractor(html.parser.HTMLParser):
    """Extract readable text from HTML, dropping script/style content."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        elif tag in _BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
        elif tag in _BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._chunks.append(data)

    def text(self) -> str:
        lines = [" ".join(line.split()) for line in "".join(self._chunks).splitlines()]
        return "\n".join(line for line in lines if line)


def html_to_text(html_source: str) -> str:
    """Convert HTML to plain text (scripts/styles removed, whitespace collapsed)."""
    extractor = _TextExtractor()
    try:
        extractor.feed(html_source)
        extractor.close()
    except html.parser.HTMLParseError:  # pragma: no cover - parser is lenient
        return " ".join(html_source.split())
    return extractor.text()


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


class _WebTool(Tool):
    """Shared plumbing for web tools."""

    risk_level = RiskLevel.READ_ONLY

    def __init__(self, settings: Any, *, transport: Transport | None = None) -> None:
        self._settings = settings
        self._transport = transport or default_transport(settings.allow_private_networks)

    def _get(self, url: str, *, accept: str) -> tuple[int, str, bytes]:
        """GET ``url`` through the transport; return (status, content_type, body).

        Raises ToolValidationError for URL policy violations and returns
        failure info via exceptions the caller maps to clean results.
        """
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": self._settings.user_agent,
                "Accept": accept,
            },
            method="GET",
        )
        try:
            with self._transport(request, timeout=self._settings.timeout_s) as response:
                status = getattr(response, "status", 200)
                content_type = response.headers.get("Content-Type", "")
                body = response.read(self._settings.max_bytes + 1)
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                msg = f"redirect from {url} was refused (non-http(s) or private target)"
                raise ToolValidationError(msg) from exc
            raise
        except urllib.error.URLError as exc:
            reason = exc.reason
            msg = f"cannot fetch {url}: {reason}"
            raise ToolValidationError(msg) from exc
        except TimeoutError as exc:
            msg = f"fetching {url} timed out after {self._settings.timeout_s:.0f}s"
            raise ToolValidationError(msg) from exc
        return int(status), content_type, body


class WebFetchTool(_WebTool):
    name = "web.fetch"
    description = (
        "Fetch a public http(s) URL and return readable text (HTML is stripped; "
        "output truncated to the configured character limit). "
        "Input: {url: string}"
    )
    input_schema: Mapping[str, Any] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "minLength": 8, "maxLength": 2000},
        },
        "required": ["url"],
        "additionalProperties": False,
    }

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        url = args["url"]
        try:
            url = validate_url(url, allow_private=self._settings.allow_private_networks)
        except ToolValidationError as exc:
            return ToolResult.failure(str(exc), tool=self.name)
        try:
            status, content_type, body = self._get(
                url, accept="text/html, text/plain, application/json"
            )
        except ToolValidationError as exc:
            return ToolResult.failure(str(exc), tool=self.name)
        except urllib.error.HTTPError as exc:
            return ToolResult.failure(f"HTTP {exc.code} fetching {url}", tool=self.name)

        byte_truncated = len(body) > self._settings.max_bytes
        body = body[: self._settings.max_bytes]
        base_type = content_type.split(";")[0].strip().lower()
        if base_type not in _ALLOWED_CONTENT_TYPES:
            allowed = ", ".join(sorted(_ALLOWED_CONTENT_TYPES))
            return ToolResult.failure(
                f"unsupported content type {base_type!r} (allowed: {allowed})",
                tool=self.name,
            )
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - decode with replace does not raise
            text = ""
        if base_type == "text/html":
            text = html_to_text(text)
        char_truncated = False
        if len(text) > self._settings.output_char_limit:
            text = text[: self._settings.output_char_limit]
            char_truncated = True
        notes = []
        if byte_truncated:
            notes.append("response truncated at the byte cap")
        if char_truncated:
            notes.append(f"text truncated at {self._settings.output_char_limit} characters")
        if notes:
            text += "\n[... " + "; ".join(notes) + "]"
        return ToolResult.success(
            text,
            data={
                "url": url,
                "status": status,
                "content_type": base_type,
                "truncated": byte_truncated or char_truncated,
            },
            tool=self.name,
        )


class _DuckDuckGoLiteParser(html.parser.HTMLParser):
    """Parse DuckDuckGo Lite result tables into (title, url, snippet) triples."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: list[dict[str, str]] = []
        self._link: dict[str, str] | None = None
        self._capture: str | None = None
        self._snippet_target: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attr_map = dict(attrs)
        classes = attr_map.get("class", "").split()
        if tag == "a" and "result-link" in classes:
            self._link = {"url": attr_map.get("href", ""), "title": "", "snippet": ""}
            self._capture = "title"
        elif tag == "td" and "result-snippet" in classes and self.results:
            self._snippet_target = self.results[-1]
            self._capture = "snippet"

    def handle_data(self, data: str) -> None:
        if self._capture == "title" and self._link is not None:
            self._link["title"] += data
        elif self._capture == "snippet" and self._snippet_target is not None:
            self._snippet_target["snippet"] += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._link is not None:
            self._link["url"] = _unwrap_duckduckgo_url(self._link["url"])
            self._link["title"] = " ".join(self._link["title"].split())
            self.results.append(self._link)
            self._link = None
            self._capture = None
        elif tag == "td" and self._capture == "snippet":
            if self._snippet_target is not None:
                self._snippet_target["snippet"] = " ".join(self._snippet_target["snippet"].split())
            self._snippet_target = None
            self._capture = None


def _unwrap_duckduckgo_url(href: str) -> str:
    """DuckDuckGo Lite links go through /l/?uddg=<urlencoded target>."""
    if href.startswith("//"):
        href = "https:" + href
    parts = urlsplit(href)
    if "duckduckgo.com" in (parts.netloc or "") and parts.path.startswith("/l/"):
        target = parse_qs(parts.query).get("uddg", [""])[0]
        if target:
            return target
    return href


class WebSearchTool(_WebTool):
    name = "web.search"
    description = (
        "Search the web and return {title, url, snippet} results. "
        "Input: {query: string, max_results?: integer (1-10)}"
    )
    input_schema: Mapping[str, Any] = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": _MAX_QUERY_LENGTH},
            "max_results": {"type": "integer", "minimum": 1, "maximum": _MAX_RESULTS_CAP},
        },
        "required": ["query"],
        "additionalProperties": False,
    }

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        query = " ".join(str(args["query"]).split())
        max_results = min(int(args.get("max_results", 5)), _MAX_RESULTS_CAP)
        try:
            if self._settings.search == "searxng":
                return self._search_searxng(query, max_results)
            return self._search_duckduckgo(query, max_results)
        except ToolValidationError as exc:
            return ToolResult.failure(str(exc), tool=self.name)
        except urllib.error.HTTPError as exc:
            return ToolResult.failure(f"HTTP {exc.code} while searching", tool=self.name)

    def _search_duckduckgo(self, query: str, max_results: int) -> ToolResult:
        url = "https://lite.duckduckgo.com/lite/?" + urllib.parse.urlencode({"q": query})
        _, content_type, body = self._get(url, accept="text/html")
        base_type = content_type.split(";")[0].strip().lower()
        if base_type not in _ALLOWED_CONTENT_TYPES:
            return ToolResult.failure(
                f"unexpected search content type {base_type!r}", tool=self.name
            )
        parser = _DuckDuckGoLiteParser()
        parser.feed(body.decode("utf-8", errors="replace"))
        parser.close()
        results = [r for r in parser.results if r["url"].startswith(("http://", "https://"))]
        results = results[:max_results]
        return self._format_results(query, results, provider="duckduckgo")

    def _search_searxng(self, query: str, max_results: int) -> ToolResult:
        base = self._settings.searxng_url.rstrip("/")
        url = base + "/search?" + urllib.parse.urlencode({"q": query, "format": "json"})
        _, _, body = self._get(url, accept="application/json")
        try:
            payload = json.loads(body.decode("utf-8"))
        except ValueError:
            return ToolResult.failure("searxng returned invalid JSON", tool=self.name)
        results = [
            {
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "snippet": item.get("content", ""),
            }
            for item in payload.get("results", [])
            if item.get("url", "").startswith(("http://", "https://"))
        ]
        return self._format_results(query, results[:max_results], provider="searxng")

    def _format_results(
        self, query: str, results: list[dict[str, str]], *, provider: str
    ) -> ToolResult:
        if not results:
            return ToolResult.success(
                f"No results for {query!r}.",
                data={"query": query, "provider": provider, "results": []},
                tool=self.name,
            )
        lines = [f"Web search results for {query!r} ({provider}):"]
        for index, result in enumerate(results, start=1):
            lines.append(f"{index}. {result['title']}")
            lines.append(f"   {result['url']}")
            if result["snippet"]:
                lines.append(f"   {html_module.unescape(result['snippet'])}")
        return ToolResult.success(
            "\n".join(lines),
            data={"query": query, "provider": provider, "results": results},
            tool=self.name,
        )
