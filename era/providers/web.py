"""WebProvider — keyless web search + SSRF-safe fetch/download (Phase 3A).

The first *networked* ToolProvider in ERA:

* ``web.search`` — DuckDuckGo HTML endpoint (no API key, free). Parse the
  results page; on any network failure raise ``ToolError(UNAVAILABLE)`` so the
  agent observes the outage instead of crashing.
* ``web.fetch`` — fetch a public URL with the SSRF guards from
  :class:`era.security.url_safety.validate_public_url` applied to the request
  AND to every redirect hop; extract ``<title>`` and body text; cap size.
* ``web.download`` — same guarded fetch, saved into the sandboxed workspace
  (``path`` confined by :class:`era.security.path_safety.WorkspaceRoot`).

No credentials, no API keys, no cookies. The agent loop treats failures as
observations and adapts (offline knowledge packs etc.).
"""

from __future__ import annotations

import gzip
import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.registry.actions import ActionType
from era.security.path_safety import WorkspaceRoot
from era.security.url_safety import validate_public_url

DEFAULT_MAX_FETCH_BYTES = 2_097_152  # 2 MiB
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_USER_AGENT = "ERA-Agent/0.3 (+https://github.com/sajanji15859-cmyk/ERA-AI)"
SEARCH_URL = "https://html.duckduckgo.com/html/"
MAX_SEARCH_RESULTS = 10
MAX_FETCH_TEXT_CHARS = 100_000

_ACTION_TYPES = frozenset({
    ActionType.WEB_SEARCH.value,
    ActionType.WEB_FETCH.value,
    ActionType.WEB_DOWNLOAD.value,
})


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate every redirect hop through the SSRF guards."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newurl = newurl.replace(" ", "%20")
        validate_public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title: str = ""
        self._in_title = False
        self._skip = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self._in_title = True
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag in ("script", "style") and self._skip > 0:
            self._skip -= 1

    def handle_data(self, data):
        if self._skip > 0:
            return
        if self._in_title:
            self.title += data
        else:
            self.parts.append(data)


class _DDGResultParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.results: list[dict] = []
        self._in_result = False
        self._in_link = False
        self._link_href = ""
        self._link_text: list[str] = []
        self._snippet: list[str] = []
        self._depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = attrs.get("class", "").split()
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
                href = attrs.get("href", "")
                if href.startswith("//duckduckgo.com/l/"):
                    parsed = urllib.parse.urlparse("https:" + href)
                    qs = urllib.parse.parse_qs(parsed.query)
                    real = qs.get("uddg", [""])[0]
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
        title = re.sub(r"\s+", " ", "".join(self._link_text)).strip()
        snippet = re.sub(r"\s+", " ", "".join(self._snippet)).strip()
        if snippet.startswith("[snip]"):
            snippet = snippet[len("[snip]"):].strip()
        if not title:
            return
        self.results.append({"title": title[:200], "url": self._link_href[:2048],
                             "snippet": snippet[:500]})
        if len(self.results) >= MAX_SEARCH_RESULTS:
            self._in_result = False
            self._depth = 0


class WebProvider:
    id = "web"

    def __init__(self, *, max_fetch_bytes: int = DEFAULT_MAX_FETCH_BYTES,
                 timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
                 user_agent: str = DEFAULT_USER_AGENT,
                 workspace_root: str | Path | None = None):
        self.max_fetch_bytes = max(1, int(max_fetch_bytes))
        self.timeout_seconds = float(timeout_seconds)
        self.user_agent = user_agent
        self.workspace = WorkspaceRoot(workspace_root) if workspace_root is not None else None

    action_types = _ACTION_TYPES

    # -- SPI ---------------------------------------------------------------------
    def validate(self, action: Action) -> None:
        action_type = action.action_type
        params = action.params or {}
        if action_type == ActionType.WEB_SEARCH.value:
            query = params.get("q")
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
        validate_public_url(url)  # SSRF guards (raises ToolError)
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
        action_type = action.action_type
        params = action.params or {}
        if action_type == ActionType.WEB_SEARCH.value:
            query = params.get("q")
            if not isinstance(query, str) or not query:
                raise ToolError("'q' is required for web.search", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            return self._search(query)
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
            version="0.3.0",
            display_name="Web (keyless search + SSRF-safe fetch)",
            is_stub=False,
            capabilities=("search", "fetch", "download", "ssrf-guarded"),
        )

    # -- operations ---------------------------------------------------------------
    def _search(self, query: str) -> ActionResult:
        url = f"{SEARCH_URL}?{urllib.parse.urlencode({'q': query})}"
        html_text = self._http_get(url, max_bytes=1_048_576)
        parser = _DDGResultParser()
        parser.feed(html_text)
        return ActionResult(
            success=True,
            summary=f"web search returned {len(parser.results)} result(s)",
            data={"query": query, "results": parser.results[:MAX_SEARCH_RESULTS]},
        )

    def _fetch(self, url: str) -> ActionResult:
        raw = self._http_get(url, max_bytes=self.max_fetch_bytes)
        content_type = ""
        text = self._decode(raw, content_type)
        extractor = _TextExtractor()
        try:
            extractor.feed(text)
        except Exception:  # noqa: BLE001,S110 — HTML parser quirks must not fail a fetch
            pass
        body_text = re.sub(r"\s+", " ", " ".join(extractor.parts)).strip()
        return ActionResult(
            success=True,
            summary=f"fetched {len(raw)} bytes from {url}",
            data={"url": url, "title": extractor.title.strip()[:300],
                  "text": body_text[:MAX_FETCH_TEXT_CHARS], "bytes": len(raw)},
        )

    def _download(self, url: str, path: str) -> ActionResult:
        raw = self._http_get(url, max_bytes=self.max_file_bytes())
        resolved = self.workspace.resolve(path)
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_bytes(raw)
        except OSError as exc:
            raise ToolError(f"download write failed: {exc}", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        return ActionResult(success=True, summary=f"downloaded {len(raw)} bytes",
                            data={"path": path, "bytes": len(raw), "url": url})

    def max_file_bytes(self) -> int:
        # Downloads also respect the workspace cap (bounded by fetch cap too).
        return self.max_fetch_bytes

    # -- transport ---------------------------------------------------------------
    def _http_get(self, url: str, max_bytes: int) -> bytes:
        validate_public_url(url)
        request = urllib.request.Request(url, headers={
            "User-Agent": self.user_agent,
            "Accept-Encoding": "gzip",
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
        })
        opener = urllib.request.build_opener(SafeRedirectHandler())
        try:
            with opener.open(request, timeout=self.timeout_seconds) as resp:
                raw = resp.read(max_bytes + 1)
                if resp.headers.get("Content-Encoding") == "gzip":
                    try:
                        raw = gzip.decompress(raw)
                    except OSError:
                        pass
                if len(raw) > max_bytes:
                    raw = raw[:max_bytes]
                return raw
        except urllib.error.HTTPError as exc:
            code = exc.code if isinstance(exc.code, int) else 0
            if code in (403,):
                raise ToolError(f"target forbids access (HTTP 403): {url}",
                                provider_id=self.id,
                                code=ProviderErrorCode.FORBIDDEN) from exc
            if code in (404, 410):
                raise ToolError(f"resource not found (HTTP {code}): {url}",
                                provider_id=self.id,
                                code=ProviderErrorCode.NOT_FOUND) from exc
            raise ToolError(f"fetch failed (HTTP {code}): {url}", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ToolError(f"network unavailable: {url}", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc

    @staticmethod
    def _decode(raw: bytes, content_type: str) -> str:
        for charset in _charsets(content_type):
            try:
                return raw.decode(charset)
            except (LookupError, UnicodeDecodeError):
                continue
        return raw.decode("utf-8", errors="replace")


def _charsets(content_type: str):
    match = re.search(r"charset=([\w\-]+)", content_type or "", re.IGNORECASE)
    if match:
        yield match.group(1)
    yield "utf-8"
    yield "latin-1"
