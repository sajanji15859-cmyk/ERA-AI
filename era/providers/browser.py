"""Self-hosted browser automation with Playwright and an offline simulator.

The provider owns the ``browser.*`` action family while the existing execution
service remains the only dispatch boundary.  Consequently every navigation,
DOM read and interaction still passes through permission evaluation,
confirmation, audit-before-execute, timeout/retry and circuit-breaker gates.

Security properties implemented here:

* every top-level navigation is checked with :func:`validate_public_url` both
  during validation and immediately before dispatch;
* the Playwright transport intercepts subresource/redirect requests and blocks
  non-public HTTP(S), non-network schemes and WebSockets;
* each ``(actor_id, session_id)`` gets a separate non-persistent browser
  context (no shared cookies, local storage or cache);
* screenshots and optional HTML dumps are written by this provider only after
  :class:`WorkspaceRoot` containment checks;
* configured viewport and per-operation timeout bounds are applied inside
  Playwright as well as at ERA's provider dispatch boundary;
* Playwright is imported lazily.  Offline CI can inject
  :class:`SimulatedBrowserTransport` without installing Chromium or opening a
  socket.

Phase 4B — reliable browser workflows — adds:

* ``browser.inspect``: a bounded snapshot of the rendered accessibility state
  (role, accessible name, tag, input type, frame/tab/origin identity) with
  opaque, provider-issued ``element_ref`` tokens.  No CSS selectors or
  visible-text matching are needed and none can be invented: refs are
  unpredictable, actor/run-scoped, tab/frame-scoped, snapshot-generation
  scoped and TTL-bound, and resolution fails closed on any drift;
* element-reference security (:class:`ElementReferenceRegistry`): refs become
  invalid after navigation, tab close, frame replacement, context close,
  snapshot invalidation, TTL expiry; resolution requires *exactly one*
  fingerprint match or a deterministic NOT_FOUND/CONFLICT error;
* tabs/popups (``browser.tabs`` / ``browser.activate_tab``) with opaque tab
  identities and deterministic popup handling;
* iframe/frame handling with explicit frame identity and stale-frame
  invalidation (cross-origin frames expose only bounded accessibility
  metadata, never secrets);
* Shadow DOM support where Chromium permits it (open shadow roots are walked
  and scoped exactly like normal elements);
* ``browser.download`` (workspace-confined, size-bound, atomic) and
  ``browser.upload`` (workspace-confined, validated file inputs);
* deterministic post-condition verification and sanitized interaction
  receipts; every mutating action stays non-retryable and ambiguous outcomes
  remain ``SIDE_EFFECT_UNKNOWN`` with context quarantine.
"""

from __future__ import annotations

import hashlib
import os
import queue
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, ClassVar, Protocol
from urllib.parse import urljoin, urlsplit

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.registry.actions import ActionType
from era.security.path_safety import WorkspaceRoot
from era.security.url_safety import validate_public_url
from era.security.vault import VaultError, is_vault_ref, parse_vault_ref

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_VIEWPORT_WIDTH = 1280
DEFAULT_VIEWPORT_HEIGHT = 800
DEFAULT_USER_AGENT = "ERA-Agent/0.8.1 (+https://github.com/sajanji15859-cmyk/ERA-AI)"
MAX_DOM_CHARS = 100_000
DEFAULT_DOM_CHARS = 50_000
MAX_DOM_SOURCE_CHARS = 2_000_000
MAX_SCREENSHOT_BYTES = 20 * 1024 * 1024
MAX_LINKS = 200
DEFAULT_MAX_CONTEXTS = 32
DEFAULT_CONTEXT_IDLE_SECONDS = 300.0
DEFAULT_COMMAND_QUEUE_SIZE = 128
_DISPATCH_SAFETY_MARGIN_SECONDS = 0.25

# --- Phase 4B element references / inspection bounds --------------------------
ELEMENT_REF_PREFIX = "er_"
DEFAULT_ELEMENT_REF_TTL_SECONDS = 120.0
DEFAULT_MAX_INSPECT_ELEMENTS = 200
MAX_INSPECT_ELEMENTS_CAP = 500
DEFAULT_MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024   # 200 MiB
DEFAULT_MAX_UPLOAD_BYTES = 100 * 1024 * 1024     # 100 MiB
MAX_TRANSFER_BYTES_CAP = 1024 ** 3               # 1 GiB hard cap for both
MAX_NAME_CHARS = 300
MAX_HREF_CHARS = 2048
MAX_ATTR_CHARS = 200
MAX_ELEMENT_REFS_PER_SNAPSHOT = MAX_INSPECT_ELEMENTS_CAP
_POPUP_DETECTION_WINDOW_SECONDS = 1.0

_NON_RETRYABLE_ACTION_TYPES = frozenset({
    ActionType.BROWSER_CLICK.value,
    ActionType.BROWSER_FILL.value,
    ActionType.BROWSER_SUBMIT.value,
    ActionType.BROWSER_DOWNLOAD.value,
    ActionType.BROWSER_UPLOAD.value,
})
_NON_RETRYABLE_OPERATIONS = frozenset({
    "click", "fill", "submit", "download", "upload",
})

_ACTION_TYPES = frozenset({
    ActionType.BROWSER_NAVIGATE.value,
    ActionType.BROWSER_SCREENSHOT.value,
    ActionType.BROWSER_EXTRACT_DOM.value,
    ActionType.BROWSER_CLICK.value,
    ActionType.BROWSER_FILL.value,
    ActionType.BROWSER_SUBMIT.value,
    ActionType.BROWSER_INSPECT.value,
    ActionType.BROWSER_TABS.value,
    ActionType.BROWSER_ACTIVATE_TAB.value,
    ActionType.BROWSER_DOWNLOAD.value,
    ActionType.BROWSER_UPLOAD.value,
})

# A valid deterministic one-pixel PNG used only by the explicit offline
# simulator.  Production screenshots always come from Chromium.
_SIMULATED_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDAT\x08\xd7c\xf8"
    b"\xcf\xc0\xf0\x1f\x00\x05\x00\x01\xff\x89\x99=\x1d\x00\x00\x00\x00IEND"
    b"\xaeB`\x82"
)


class BrowserTransport(Protocol):
    """Modular browser engine interface used by production and offline tests.

    Phase 4B extends the protocol with accessibility inspection, tabs and
    element-reference-driven mutations.  Existing methods keep their original
    keyword signature; ``element_ref``/``expect`` are additive keyword-only
    parameters so Phase 4A callers and transports remain compatible.
    """

    def navigate(self, session_key: str, url: str, *, wait_until: str,
                 timeout_ms: int) -> dict[str, Any]: ...

    def screenshot(self, session_key: str, *, selector: str | None,
                   full_page: bool, image_type: str, timeout_ms: int) -> bytes: ...

    def extract(self, session_key: str, *, selector: str | None,
                timeout_ms: int) -> dict[str, Any]: ...

    def inspect(self, session_key: str, *, max_elements: int,
                timeout_ms: int) -> dict[str, Any]: ...

    def list_tabs(self, session_key: str) -> dict[str, Any]: ...

    def activate_tab(self, session_key: str, tab_id: str,
                     timeout_ms: int) -> dict[str, Any]: ...

    def click(self, session_key: str, *, selector: str | None, text: str | None,
              exact: bool, element_ref: str | None = None,
              timeout_ms: int) -> dict[str, Any]: ...

    def fill(self, session_key: str, *, selector: str | None,
             element_ref: str | None, text: str,
             timeout_ms: int) -> dict[str, Any]: ...

    def submit(self, session_key: str, *, selector: str | None,
               element_ref: str | None = None,
               timeout_ms: int) -> dict[str, Any]: ...

    def download(self, session_key: str, *, element_ref: str | None,
                 selector: str | None, text: str | None, exact: bool,
                 dest: str, max_bytes: int, timeout_ms: int) -> dict[str, Any]: ...

    def upload(self, session_key: str, *, element_ref: str | None,
               selector: str | None, path: str,
               timeout_ms: int) -> dict[str, Any]: ...

    def close_context(self, session_key: str) -> None: ...

    def close(self) -> None: ...


# -- element reference security -------------------------------------------------

def _ref_error(message: str, code: ProviderErrorCode) -> ToolError:
    return ToolError(message, provider_id="browser", code=code)


@dataclass
class ElementRefRecord:
    """One issued element reference and the scope it is bound to."""

    ref: str
    tab_id: str
    frame_id: str
    generation: int
    url: str            # tab URL at snapshot time (drift sentinel)
    origin: str         # frame origin at snapshot time
    fingerprint: dict[str, Any]   # tag, role, name, input_type (identity core)
    path: tuple[int, ...]         # structural path inside the frame
    created: float
    ttl_seconds: float


class ElementReferenceRegistry:
    """Scope/TTL/generation bookkeeping for provider-issued element references.

    References are opaque, unpredictable tokens (``er_<random>``) minted only
    by a transport during :meth:`SimulatedBrowserTransport.inspect` /
    Playwright inspection.  They are bound to one browser run (the transport's
    ``session_key``), one tab, one frame and one snapshot generation, and
    expire after a TTL.

    Resolution is fail-closed: any scope mismatch raises a deterministic
    :class:`ToolError` (NOT_FOUND for unknown refs, CONFLICT for stale/wrong
    tab/wrong frame/drift/expired).  The registry deliberately stores no DOM
    handles or page objects — the owning transport performs the actual element
    lookup using the recorded fingerprint/path.
    """

    def __init__(self, ttl_seconds: float = DEFAULT_ELEMENT_REF_TTL_SECONDS):
        if float(ttl_seconds) <= 0:
            raise ValueError("browser element_ref_ttl_seconds must be positive")
        self.ttl_seconds = float(ttl_seconds)
        self._lock = threading.RLock()
        self._refs: dict[str, dict[str, ElementRefRecord]] = {}
        self._generations: dict[str, dict[str, int]] = {}

    def generation(self, session_key: str, tab_id: str) -> int:
        with self._lock:
            return self._generations.get(session_key, {}).get(tab_id, 0)

    def begin_snapshot(self, session_key: str, tab_id: str) -> int:
        """Bump the tab's snapshot generation.

        Older refs are *kept* so they resolve deterministically to CONFLICT
        ("stale — run browser.inspect again") instead of pretending they never
        existed.  Expired refs are dropped opportunistically.
        """
        with self._lock:
            gens = self._generations.setdefault(session_key, {})
            generation = gens.get(tab_id, 0) + 1
            gens[tab_id] = generation
            now = time.monotonic()
            refs = self._refs.get(session_key)
            if refs:
                for ref in [r for r, rec in refs.items()
                            if rec.tab_id == tab_id
                            and now - rec.created > rec.ttl_seconds]:
                    del refs[ref]
            return generation

    def register(self, session_key: str, *, tab_id: str, frame_id: str,
                 generation: int, url: str, origin: str,
                 fingerprint: dict[str, Any], path: tuple[int, ...]) -> str:
        token = secrets.token_urlsafe(32)
        ref = f"{ELEMENT_REF_PREFIX}{token}"
        record = ElementRefRecord(
            ref=ref, tab_id=tab_id, frame_id=frame_id, generation=generation,
            url=url, origin=origin, fingerprint=dict(fingerprint),
            path=tuple(path), created=time.monotonic(), ttl_seconds=self.ttl_seconds,
        )
        with self._lock:
            self._refs.setdefault(session_key, {})[ref] = record
        return ref

    def get(self, session_key: str, ref: str) -> ElementRefRecord | None:
        with self._lock:
            return self._refs.get(session_key, {}).get(ref)

    def check_scope(self, record: ElementRefRecord, *, session_key: str,
                    active_tab_id: str, active_url: str, generation: int,
                    frame_origin: str) -> None:
        """Validate every scope dimension; raise ToolError on any mismatch."""
        if time.monotonic() - record.created > record.ttl_seconds:
            raise _ref_error("element reference expired (TTL)", ProviderErrorCode.CONFLICT)
        if record.tab_id != active_tab_id:
            raise _ref_error(
                "element reference belongs to another tab", ProviderErrorCode.CONFLICT,
            )
        if record.generation != generation:
            raise _ref_error(
                "element reference is stale — run browser.inspect again",
                ProviderErrorCode.CONFLICT,
            )
        if record.url != active_url:
            raise _ref_error(
                "page changed since the element was inspected",
                ProviderErrorCode.CONFLICT,
            )
        if record.origin != frame_origin:
            raise _ref_error(
                "element's frame origin changed", ProviderErrorCode.CONFLICT,
            )

    def invalidate_tab(self, session_key: str, tab_id: str) -> None:
        """Drop a tab's refs and bump its generation (e.g. after navigation)."""
        with self._lock:
            refs = self._refs.get(session_key)
            if refs:
                for ref in [r for r, rec in refs.items() if rec.tab_id == tab_id]:
                    del refs[ref]
            gens = self._generations.setdefault(session_key, {})
            gens[tab_id] = gens.get(tab_id, 0) + 1

    def invalidate_session(self, session_key: str) -> None:
        with self._lock:
            self._refs.pop(session_key, None)
            self._generations.pop(session_key, None)


def _fingerprint_core(desc: dict[str, Any]) -> dict[str, Any]:
    """Identity core used to resolve an element reference."""
    return {
        "tag": desc.get("tag"),
        "role": desc.get("role"),
        "name": desc.get("name"),
        "input_type": desc.get("input_type"),
    }


def _origin_of(url: str) -> str:
    try:
        parts = urlsplit(url)
        if parts.scheme in ("http", "https"):
            return f"{parts.scheme}://{parts.netloc}"
    except ValueError:
        pass
    return "opaque"


def _bounded(value: str | None, limit: int) -> str:
    if value is None:
        return ""
    return value[:limit]


# -- accessibility-style DOM walker (offline simulator) -------------------------

class _AccessibilityWalker(HTMLParser):
    """Extract a bounded accessibility-style view of one HTML document.

    Deterministic offline counterpart of the Playwright DOM walk.  It returns
    descriptors used to mint element references: ``tag``, ``role``,
    ``name``, ``input_type``, sensitivity flag, shadow-DOM flags, structural
    path and safe metadata (resolved href/alt/target).  It never extracts
    input values, hidden fields or non-visible text.
    """

    _SKIP = frozenset({"script", "style", "noscript", "head", "meta", "link",
                       "title"})
    _VOID = frozenset({
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr",
    })
    _ROLE_BY_TAG: ClassVar[dict[str, str]] = {
        "a": "link", "button": "button", "select": "combobox", "textarea": "textbox",
        "img": "img", "nav": "navigation", "form": "form", "main": "main",
        "iframe": "frame", "summary": "button", "dialog": "dialog",
    }
    _INPUT_ROLES: ClassVar[dict[str, str]] = {
        "button": "button", "submit": "button", "image": "button", "reset": "button",
        "checkbox": "checkbox", "radio": "radio", "range": "slider", "file": "file",
        "password": "textbox",
    }
    _USABLE_TAGS = frozenset({
        "a", "button", "input", "select", "textarea", "summary", "iframe",
        "nav", "form", "main", "dialog",
    })

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.root: list[_SimNode] = []
        self._stack: list[_SimNode] = []
        self._skip_depth = 0

    def reset_doc(self) -> None:
        self.root = []
        self._stack = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in self._SKIP or self._skip_depth:
            if tag in self._SKIP:
                self._skip_depth += 1
            return
        node = _SimNode(tag=tag, attrs=dict(attrs))
        parent = self._stack[-1] if self._stack else None
        if parent is not None:
            parent.children.append(node)
        else:
            self.root.append(node)
        if tag == "template" and (node.attrs.get("shadowrootmode") or
                                  node.attrs.get("shadowroot")) in ("open",):
            node.tag = "__shadow__"
            # The placeholder is not a real child: remove it from the host so
            # shadow children are indexed after the host's light children
            # (matching the Playwright walker).  Content is spliced on close.
            if parent is not None:
                parent.children.pop()
            self._stack.append(node)
            return
        if tag in self._VOID:
            return   # void elements never produce an end tag
        self._stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in ("template", "script", "style"):
            return
        self.handle_starttag(tag, attrs)
        if tag not in self._VOID and self._stack and self._stack[-1].tag == tag:
            self._stack.pop()

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self._SKIP:
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if self._skip_depth or not self._stack:
            return
        if self._stack[-1].tag == tag:
            self._stack.pop()
            return
        # Unbalanced/quirk HTML (e.g. void elements that never produce an end
        # tag): close implicitly until the matching tag.  A ``__shadow__``
        # marker IS the matching template — splice it into its host and stop.
        while self._stack:
            node = self._stack.pop()
            if node.tag == "__shadow__":
                self._splice_shadow(node)
                return
            if node.tag == tag:
                return

    def _splice_shadow(self, node: _SimNode) -> None:
        if not self._stack:
            return
        host = self._stack[-1]
        host.shadow_root = True
        for child in node.children:
            child.in_shadow = True
            host.children.append(child)

    def handle_data(self, data: str) -> None:
        if self._skip_depth or not self._stack:
            return
        self._stack[-1].text += data

    # -- descriptor production -------------------------------------------------
    def descriptors(self) -> list[dict[str, Any]]:
        nodes: list[tuple[_SimNode, tuple[int, ...], bool]] = []
        self._collect(self.root, (), False, nodes)
        id_text = self._visible_text_index(nodes)
        labels = self._label_index(nodes)
        out: list[dict[str, Any]] = []
        for node, path, in_shadow in nodes:
            if not self._usable(node):
                continue
            desc = self._describe(node, path, in_shadow, id_text, labels)
            if desc is not None:
                out.append(desc)
        return out

    @staticmethod
    def _collect(nodes: list[_SimNode], path: tuple[int, ...], in_shadow: bool,
                 out: list[tuple[_SimNode, tuple[int, ...], bool]]) -> None:
        for index, node in enumerate(nodes):
            if node.tag == "__shadow__":
                continue
            child_path = path + (index,)
            out.append((node, child_path, in_shadow or bool(node.in_shadow)))
            child_in_shadow = in_shadow or bool(node.in_shadow)
            _AccessibilityWalker._collect(
                node.children, child_path, child_in_shadow, out,
            )

    def _visible_text(self, node: _SimNode) -> str:
        if node.tag in ("script", "style", "noscript", "template"):
            return ""
        return _clean_inline(node.text + " ".join(
            self._visible_text(child) for child in node.children
        ))

    def _visible_text_index(self, nodes) -> dict[str, str]:
        index: dict[str, str] = {}
        for node, _, _ in nodes:
            node_id = node.attrs.get("id")
            if node_id:
                index[node_id] = self._visible_text(node)[:MAX_NAME_CHARS]
        return index

    def _label_index(self, nodes) -> dict[str, str]:
        index: dict[str, str] = {}
        for node, _, _ in nodes:
            if node.tag == "label":
                for_for = node.attrs.get("for")
                if for_for:
                    index[for_for] = self._visible_text(node)[:MAX_NAME_CHARS]
        return index

    def _usable(self, node: _SimNode) -> bool:
        if node.tag in ("__shadow__",):
            return False
        if node.attrs.get("hidden") is not None:
            return False
        if node.attrs.get("aria-hidden", "").lower() == "true":
            return False
        style = (node.attrs.get("style") or "").lower().replace(" ", "")
        if "display:none" in style or "visibility:hidden" in style:
            return False
        if node.tag == "input":
            input_type = (node.attrs.get("type") or "text").lower()
            if input_type == "hidden":
                return False
        if node.tag == "a" and not node.attrs.get("href"):
            return False
        return bool(node.attrs.get("role") or node.attrs.get("aria-label")
                    or node.attrs.get("aria-labelledby")
                    or node.tag in self._USABLE_TAGS
                    or node.tag.startswith("h") and len(node.tag) == 2
                    or node.attrs.get("contenteditable") is not None)

    def _describe(self, node: _SimNode, path: tuple[int, ...], in_shadow: bool,
                  id_text: dict[str, str], labels: dict[str, str]) -> dict[str, Any] | None:
        tag = node.tag
        attrs = node.attrs
        role = attrs.get("role") or self._role_for(node)
        if not role:
            return None
        name = self._name_for(node, id_text, labels)
        input_type = None
        sensitive = False
        disabled = attrs.get("disabled") is not None
        checked = None
        if tag == "input":
            input_type = (attrs.get("type") or "text").lower()
            sensitive = input_type == "password"
            if input_type in ("checkbox", "radio"):
                checked = attrs.get("checked") is not None
        desc: dict[str, Any] = {
            "tag": tag,
            "role": role,
            "name": name,
            "input_type": input_type,
            "sensitive": sensitive,
            "disabled": disabled,
            "checked": checked,
            "path": list(path),
            "in_shadow": in_shadow,
            "shadow_root": bool(node.shadow_root),
        }
        if tag == "a":
            href = str(attrs.get("href") or "").strip()
            if href:
                resolved = urljoin(self.base_url, href)
                if urlsplit(resolved).scheme in ("http", "https"):
                    desc["href"] = resolved[:MAX_HREF_CHARS]
            target = attrs.get("target")
            if target:
                desc["target"] = _bounded(target, MAX_ATTR_CHARS)
        elif tag == "img":
            alt = attrs.get("alt")
            if alt:
                desc["alt"] = _bounded(alt, MAX_NAME_CHARS)
        elif tag == "iframe":
            src = str(attrs.get("src") or "").strip()
            if src:
                desc["href"] = urljoin(self.base_url, src)[:MAX_HREF_CHARS]
        elif tag == "form" and attrs.get("action"):
            action = str(attrs.get("action") or "").strip()
            if action:
                desc["action"] = urljoin(self.base_url, action)[:MAX_HREF_CHARS]
        placeholder = attrs.get("placeholder")
        if placeholder:
            desc["placeholder"] = _bounded(placeholder, MAX_ATTR_CHARS)
        return desc

    def _role_for(self, node: _SimNode) -> str:
        tag = node.tag
        if tag == "input":
            input_type = (node.attrs.get("type") or "text").lower()
            return self._INPUT_ROLES.get(input_type, "textbox")
        if tag.startswith("h") and len(tag) == 2:
            return "heading"
        if node.attrs.get("contenteditable") is not None:
            return "textbox"
        return self._ROLE_BY_TAG.get(tag, "")

    def _name_for(self, node: _SimNode, id_text: dict[str, str],
                  labels: dict[str, str]) -> str:
        attrs = node.attrs
        label = (attrs.get("aria-label") or "").strip()
        if label:
            return _bounded(label, MAX_NAME_CHARS)
        labelledby = (attrs.get("aria-labelledby") or "").strip()
        if labelledby:
            parts = [id_text.get(ref_id, "") for ref_id in labelledby.split()]
            joined = " ".join(p for p in parts if p)
            if joined:
                return _bounded(joined, MAX_NAME_CHARS)
        tag = node.tag
        if tag == "img":
            return _bounded(attrs.get("alt") or "", MAX_NAME_CHARS)
        if tag == "input":
            placeholder = (attrs.get("placeholder") or "").strip()
            if placeholder:
                return _bounded(placeholder, MAX_NAME_CHARS)
            node_id = attrs.get("id")
            if node_id and node_id in labels:
                return labels[node_id]
            return ""
        if tag == "iframe":
            return _bounded(attrs.get("title") or attrs.get("name") or "",
                            MAX_NAME_CHARS)
        return self._visible_text(node)[:MAX_NAME_CHARS]


@dataclass
class _SimNode:
    tag: str
    attrs: dict[str, str]
    children: list[_SimNode] = field(default_factory=list)
    text: str = ""
    in_shadow: bool = False
    shadow_root: bool = False


def _walk_html(html: str, base_url: str) -> list[dict[str, Any]]:
    """Return bounded accessibility descriptors for ``html`` (offline)."""
    walker = _AccessibilityWalker(base_url)
    try:
        walker.feed(html)
    except Exception:  # noqa: BLE001,S110 — malformed live HTML is expected
        pass
    try:
        return walker.descriptors()
    except Exception:  # noqa: BLE001 — never fail inspection on parse quirks
        return []


def guard_browser_request(url: str) -> None:
    """Apply browser-network SSRF policy to one outgoing request.

    Chromium-internal, extension, file and WebSocket schemes are never allowed.
    ``data:``, ``blob:`` and ``about:blank`` may be generated by an already
    approved public document and do not create a network connection.
    """

    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError as exc:
        raise ToolError("invalid browser request URL", provider_id="browser",
                        code=ProviderErrorCode.FORBIDDEN) from exc
    if scheme in {"data", "blob"} or url == "about:blank":
        return
    if scheme not in {"http", "https"}:
        raise ToolError("browser request scheme is blocked", provider_id="browser",
                        code=ProviderErrorCode.FORBIDDEN)
    validate_public_url(url)


@dataclass
class _SimulatedTab:
    tab_id: str
    url: str
    html: str
    title: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    clicks: list[dict[str, Any]] = field(default_factory=list)
    submitted: bool = False
    uploads: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class _SimulatedSession:
    # Active-tab projection kept in sync with ``tabs[active_tab_id]`` so Phase
    # 4A tests that read session.fields/clicks/submitted keep working.
    url: str = ""
    html: str = ""
    title: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    clicks: list[dict[str, Any]] = field(default_factory=list)
    submitted: bool = False
    tabs: dict[str, _SimulatedTab] = field(default_factory=dict)
    active_tab_id: str = ""


class SimulatedBrowserTransport:
    """Deterministic in-memory browser transport for offline tests/CI.

    The simulator performs no DNS or network calls itself.  The provider's URL
    guard still runs before ``navigate``; tests normally use a public IP literal
    or monkeypatch DNS resolution.  Session state is isolated by the opaque key
    supplied by :class:`BrowserProvider`.

    Phase 4B additions: accessibility inspection with opaque element refs
    (``element_ref_ttl_seconds`` configurable), tabs/popups, frames, Shadow DOM
    (declarative ``<template shadowrootmode="open">``), downloads (a download is
    simulated for links whose resolved URL is in :attr:`downloads`) and
    workspace-confined uploads.  All element-ref resolution is fail-closed and
    deterministic.
    """

    def __init__(self, pages: dict[str, str] | None = None,
                 element_ref_ttl_seconds: float = DEFAULT_ELEMENT_REF_TTL_SECONDS):
        self.pages = dict(pages or {})
        self.downloads: dict[str, bytes] = {}
        self.sessions: dict[str, _SimulatedSession] = {}
        self.refs = ElementReferenceRegistry(element_ref_ttl_seconds)
        self._tab_counter = 0
        self.closed = False

    # -- Phase 4A core operations ----------------------------------------------
    def navigate(self, session_key: str, url: str, *, wait_until: str,
                 timeout_ms: int) -> dict[str, Any]:
        del wait_until, timeout_ms
        if url not in self.pages:
            raise ToolError("simulated page not found", provider_id="browser",
                            code=ProviderErrorCode.NOT_FOUND)
        html = self.pages[url]
        title = _title_from_html(html)
        session = self.sessions.get(session_key)
        if session is None:
            session = self._new_session(session_key)
            first = self._new_tab(session, url, html, title)
            session.tabs[first.tab_id] = first
            session.active_tab_id = first.tab_id
        else:
            tab = session.tabs[session.active_tab_id]
            self._navigate_tab(session_key, session, tab, url, html, title)
        self._sync(session)
        return {"url": url, "title": title, "status": 200}

    def screenshot(self, session_key: str, *, selector: str | None,
                   full_page: bool, image_type: str, timeout_ms: int) -> bytes:
        del selector, full_page, image_type, timeout_ms
        self._session(session_key)
        return _SIMULATED_PNG

    def extract(self, session_key: str, *, selector: str | None,
                timeout_ms: int) -> dict[str, Any]:
        del selector, timeout_ms
        session = self._session(session_key)
        text = _plain_text_from_html(session.html)
        return {
            "url": session.url,
            "title": session.title,
            "html": session.html,
            "text": text,
        }

    def click(self, session_key: str, *, selector: str | None, text: str | None,
              exact: bool, element_ref: str | None = None,
              timeout_ms: int) -> dict[str, Any]:
        del timeout_ms
        session = self._session(session_key)
        tab = session.tabs[session.active_tab_id]
        before_url = tab.url
        before_tabs = len(session.tabs)
        frame_id = ""
        path: list[int] = []
        tag = ""
        if element_ref is not None:
            desc, frame_id = self._resolve_ref(session_key, tab, element_ref)
            tab.clicks.append({
                "element_ref": element_ref, "path": desc["path"], "tag": desc["tag"],
            })
            path, tag = desc["path"], desc["tag"]
            self._simulate_click(session_key, session, tab, desc)
        else:
            tab.clicks.append({"selector": selector, "text": text, "exact": exact})
            self._simulate_click_legacy(session_key, session, tab, text)
        self._sync(session)
        return self._interaction_data(
            session_key, tab, before_url=before_url, before_tabs=before_tabs,
            frame_id=frame_id, path=path, tag=tag, element_ref=element_ref,
        )

    def fill(self, session_key: str, *, selector: str | None,
             element_ref: str | None, text: str,
             timeout_ms: int) -> dict[str, Any]:
        del timeout_ms
        session = self._session(session_key)
        tab = session.tabs[session.active_tab_id]
        frame_id = ""
        path: list[int] = []
        tag = ""
        if element_ref is not None:
            desc, frame_id = self._resolve_ref(session_key, tab, element_ref)
            if desc.get("input_type") == "file":
                raise _ref_error(
                    "browser.fill cannot target a file input — use browser.upload",
                    ProviderErrorCode.VALIDATION,
                )
            tab.fields[element_ref] = text
            path, tag = desc["path"], desc["tag"]
        else:
            if selector is None:
                raise _ref_error("browser.fill requires a selector or element_ref",
                                 ProviderErrorCode.VALIDATION)
            tab.fields[selector] = text
        self._sync(session)
        return self._interaction_data(
            session_key, tab, before_url=tab.url, before_tabs=len(session.tabs),
            frame_id=frame_id, path=path, tag=tag, element_ref=element_ref,
        )

    def submit(self, session_key: str, *, selector: str | None,
               element_ref: str | None = None,
               timeout_ms: int) -> dict[str, Any]:
        del timeout_ms
        session = self._session(session_key)
        tab = session.tabs[session.active_tab_id]
        before_url = tab.url
        before_tabs = len(session.tabs)
        frame_id = ""
        path: list[int] = []
        tag = ""
        if element_ref is not None:
            desc, frame_id = self._resolve_ref(session_key, tab, element_ref)
            tab.submitted = True
            path, tag = desc["path"], desc["tag"]
            action = desc.get("action")
            if action and action in self.pages:
                self._navigate_tab(
                    session_key, session, tab, action, self.pages[action],
                    _title_from_html(self.pages[action]),
                )
        else:
            tab.submitted = True
        self._sync(session)
        return self._interaction_data(
            session_key, tab, before_url=before_url, before_tabs=before_tabs,
            frame_id=frame_id, path=path, tag=tag, element_ref=element_ref,
        )

    # -- Phase 4B: inspection, tabs, downloads, uploads ------------------------
    def inspect(self, session_key: str, *, max_elements: int,
                timeout_ms: int) -> dict[str, Any]:
        del timeout_ms
        session = self._session(session_key)
        tab = session.tabs[session.active_tab_id]
        generation = self.refs.begin_snapshot(session_key, tab.tab_id)
        frames = self._frame_documents(session, tab)
        elements: list[dict[str, Any]] = []
        truncated = False
        for frame_id, frame_url, html in frames:
            for desc in _walk_html(html, base_url=frame_url):
                desc["frame_id"] = frame_id
                desc["tab_id"] = tab.tab_id
                desc["origin"] = _origin_of(frame_url)
                desc["snapshot_generation"] = generation
                desc["element_ref"] = self.refs.register(
                    session_key, tab_id=tab.tab_id, frame_id=frame_id,
                    generation=generation, url=tab.url, origin=_origin_of(frame_url),
                    fingerprint=_fingerprint_core(desc), path=tuple(desc["path"]),
                )
                elements.append(desc)
                if len(elements) >= max_elements:
                    truncated = True
                    break
            if truncated:
                break
        return {
            "url": tab.url,
            "title": tab.title,
            "tab_id": tab.tab_id,
            "tab_count": len(session.tabs),
            "snapshot_id": secrets.token_urlsafe(16),
            "generation": generation,
            "frames": [{"frame_id": f, "url": u} for f, u, _ in frames],
            "elements": elements,
            "elements_shown": len(elements),
            "truncated": truncated,
        }

    def list_tabs(self, session_key: str) -> dict[str, Any]:
        session = self._session(session_key)
        tabs = [
            {
                "tab_id": t.tab_id,
                "url": t.url,
                "title": t.title,
                "origin": _origin_of(t.url),
                "active": t.tab_id == session.active_tab_id,
            }
            for t in session.tabs.values()
        ]
        return {"tabs": tabs, "active_tab_id": session.active_tab_id}

    def activate_tab(self, session_key: str, tab_id: str,
                     timeout_ms: int) -> dict[str, Any]:
        del timeout_ms
        session = self._session(session_key)
        tab = session.tabs.get(tab_id)
        if tab is None:
            raise _ref_error("tab not found (closed or never existed)",
                             ProviderErrorCode.NOT_FOUND)
        session.active_tab_id = tab_id
        self._sync(session)
        return {"tab_id": tab_id, "url": tab.url, "title": tab.title,
                "origin": _origin_of(tab.url), "active": True}

    def download(self, session_key: str, *, element_ref: str | None,
                 selector: str | None, text: str | None, exact: bool,
                 dest: str, max_bytes: int, timeout_ms: int) -> dict[str, Any]:
        del exact, timeout_ms
        session = self._session(session_key)
        tab = session.tabs[session.active_tab_id]
        desc, frame_id = self._download_target(session_key, tab, element_ref,
                                               selector, text)
        href = desc.get("href", "")
        payload = self.downloads.get(href)
        if payload is None:
            raise _ref_error("element does not provide a simulated download",
                             ProviderErrorCode.NOT_FOUND)
        if len(payload) > max_bytes:
            raise _ref_error("download exceeds the configured size limit",
                             ProviderErrorCode.VALIDATION)
        path = Path(dest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        filename = Path(urlsplit(href).path).name or "download.bin"
        return {
            "path": dest,
            "suggested_filename": _bounded(filename, MAX_NAME_CHARS),
            "bytes": len(payload),
            "url": href,
            "tab_id": tab.tab_id,
            "frame_id": frame_id,
        }

    def upload(self, session_key: str, *, element_ref: str | None,
               selector: str | None, path: str,
               timeout_ms: int) -> dict[str, Any]:
        del timeout_ms
        session = self._session(session_key)
        tab = session.tabs[session.active_tab_id]
        if element_ref is None:
            raise _ref_error(
                "simulator requires an element_ref for browser.upload",
                ProviderErrorCode.NOT_IMPLEMENTED,
            )
        desc, frame_id = self._resolve_ref(session_key, tab, element_ref)
        if desc.get("input_type") != "file":
            raise _ref_error("element is not a file input", ProviderErrorCode.VALIDATION)
        tab.uploads.append({"element_ref": element_ref, "path": path,
                            "frame_id": frame_id})
        self._sync(session)
        return {"uploaded": True, "path": path, "tab_id": tab.tab_id,
                "frame_id": frame_id}

    def close_context(self, session_key: str) -> None:
        self.sessions.pop(session_key, None)
        self.refs.invalidate_session(session_key)

    def close(self) -> None:
        self.sessions.clear()
        self.refs.invalidate_session("")
        self.refs._refs.clear()
        self.refs._generations.clear()
        self.closed = True

    # -- internals -------------------------------------------------------------
    def _new_session(self, session_key: str) -> _SimulatedSession:
        session = _SimulatedSession()
        self.sessions[session_key] = session
        return session

    def _new_tab(self, session: _SimulatedSession, url: str, html: str,
                 title: str) -> _SimulatedTab:
        self._tab_counter += 1
        tab = _SimulatedTab(
            tab_id=f"tab_{secrets.token_urlsafe(8)}_{self._tab_counter}",
            url=url, html=html, title=title,
        )
        session.tabs[tab.tab_id] = tab
        return tab

    def _navigate_tab(self, session_key: str, session: _SimulatedSession,
                      tab: _SimulatedTab, url: str, html: str, title: str) -> None:
        self.refs.invalidate_tab(session_key, tab.tab_id)
        tab.url, tab.html, tab.title = url, html, title
        tab.fields.clear()
        tab.clicks.clear()
        tab.submitted = False
        tab.uploads.clear()

    def _sync(self, session: _SimulatedSession) -> None:
        tab = session.tabs.get(session.active_tab_id)
        if tab is None:
            return
        session.url = tab.url
        session.html = tab.html
        session.title = tab.title
        session.fields = tab.fields
        session.clicks = tab.clicks
        session.submitted = tab.submitted

    def _session(self, session_key: str) -> _SimulatedSession:
        session = self.sessions.get(session_key)
        if session is None or session.active_tab_id not in session.tabs:
            raise ToolError("browser context has no open page", provider_id="browser",
                            code=ProviderErrorCode.NOT_FOUND)
        return session

    def _frame_documents(self, session: _SimulatedSession,
                         tab: _SimulatedTab) -> list[tuple[str, str, str]]:
        frames: list[tuple[str, str, str]] = [("frame:main", tab.url, tab.html)]
        walker = _AccessibilityWalker(tab.url)
        try:
            walker.feed(tab.html)
        except Exception:  # noqa: BLE001,S110
            pass
        index = 1
        for node in self._all_nodes(walker.root):
            if node.tag == "iframe":
                src = str(node.attrs.get("src") or "").strip()
                if not src:
                    continue
                resolved = urljoin(tab.url, src)
                content = self.pages.get(resolved, "")
                frames.append((f"frame:{index}", resolved, content))
                index += 1
        return frames

    @staticmethod
    def _all_nodes(nodes: list[_SimNode]) -> list[_SimNode]:
        out: list[_SimNode] = []
        for node in nodes:
            if node.tag == "__shadow__":
                continue
            out.append(node)
            out.extend(SimulatedBrowserTransport._all_nodes(node.children))
        return out

    def _resolve_ref(self, session_key: str, tab: _SimulatedTab,
                     ref: str) -> tuple[dict[str, Any], str]:
        record = self.refs.get(session_key, ref)
        if record is None:
            raise _ref_error(
                "element reference not found (never issued or already invalidated)",
                ProviderErrorCode.NOT_FOUND,
            )
        generation = self.refs.generation(session_key, tab.tab_id)
        frames = self._frame_documents(self.sessions[session_key], tab)
        frame = next((f for f in frames if f[0] == record.frame_id), None)
        if frame is None:
            raise _ref_error("element's frame no longer exists",
                             ProviderErrorCode.CONFLICT)
        frame_id, frame_url, html = frame
        self.refs.check_scope(
            record, session_key=session_key, active_tab_id=tab.tab_id,
            active_url=tab.url, generation=generation,
            frame_origin=_origin_of(frame_url),
        )
        matches = [
            d for d in _walk_html(html, base_url=frame_url)
            if _fingerprint_core(d) == record.fingerprint
        ]
        if not matches:
            raise _ref_error(
                "no element matches the reference (element removed or page drifted)",
                ProviderErrorCode.NOT_FOUND,
            )
        if len(matches) > 1:
            raise _ref_error(
                "multiple elements match the reference fingerprint — re-inspect",
                ProviderErrorCode.CONFLICT,
            )
        desc = matches[0]
        if tuple(desc["path"]) != record.path:
            raise _ref_error(
                "element moved or page drifted (fingerprint mismatch)",
                ProviderErrorCode.CONFLICT,
            )
        return desc, frame_id

    def _simulate_click(self, session_key: str, session: _SimulatedSession,
                        tab: _SimulatedTab, desc: dict[str, Any]) -> None:
        href = desc.get("href")
        if not href:
            return
        if desc.get("target") == "_blank":
            if href in self.pages:
                new_tab = self._new_tab(
                    session, href, self.pages[href], _title_from_html(self.pages[href]),
                )
                session.tabs[new_tab.tab_id] = new_tab
            return
        if href in self.pages:
            self._navigate_tab(
                session_key, session, tab, href, self.pages[href],
                _title_from_html(self.pages[href]),
            )

    def _simulate_click_legacy(self, session_key: str, session: _SimulatedSession,
                               tab: _SimulatedTab, text: str | None) -> None:
        # Phase 4A selector/text clicks stay record-only, but a text click on a
        # link whose href is a known page navigates deterministically (used by
        # popup/tab tests without element refs).
        if not text:
            return
        for desc in _walk_html(tab.html, base_url=tab.url):
            if desc.get("tag") == "a" and desc.get("name") == text:
                href = desc.get("href")
                if href and href in self.pages:
                    self._navigate_tab(
                        session_key, session, tab, href, self.pages[href],
                        _title_from_html(self.pages[href]),
                    )
                break

    def _download_target(self, session_key: str, tab: _SimulatedTab,
                         element_ref: str | None, selector: str | None,
                         text: str | None) -> tuple[dict[str, Any], str]:
        if element_ref is not None:
            desc, frame_id = self._resolve_ref(session_key, tab, element_ref)
            return desc, frame_id
        if text is not None:
            for desc in _walk_html(tab.html, base_url=tab.url):
                if desc.get("tag") == "a" and desc.get("name") == text:
                    return desc, "frame:main"
            raise _ref_error("no download link matches the given text",
                             ProviderErrorCode.NOT_FOUND)
        if selector is not None:
            raise _ref_error(
                "simulator requires an element_ref or text for downloads",
                ProviderErrorCode.NOT_IMPLEMENTED,
            )
        raise _ref_error("browser.download requires a target",
                         ProviderErrorCode.VALIDATION)

    def _interaction_data(self, session_key: str, tab: _SimulatedTab, *,
                          before_url: str, before_tabs: int, frame_id: str,
                          path: list[int], tag: str,
                          element_ref: str | None = None) -> dict[str, Any]:
        post = {
            "url": tab.url,
            "origin": _origin_of(tab.url),
            "tab_id": tab.tab_id,
            "frame_id": frame_id,
            "tab_count_before": before_tabs,
            "tab_count_after": len(self.sessions[session_key].tabs),
            "url_changed": tab.url != before_url,
            "element_attached": self._element_still_attached(session_key, tab,
                                                             frame_id, path, tag),
        }
        receipt: dict[str, Any] = {
            "url": tab.url,
            "title": tab.title,
            "tab_id": tab.tab_id,
            "frame_id": frame_id,
            "origin": _origin_of(tab.url),
            "post_condition": post,
        }
        if element_ref is not None:
            receipt["element_ref"] = element_ref
        return receipt

    def _element_still_attached(self, session_key: str, tab: _SimulatedTab,
                                frame_id: str, path: list[int], tag: str) -> bool:
        if not frame_id:
            return True   # legacy selector/text path: no ref to track
        frames = self._frame_documents(self.sessions[session_key], tab)
        frame = next((f for f in frames if f[0] == frame_id), None)
        if frame is None:
            return False
        _, frame_url, html = frame
        for desc in _walk_html(html, base_url=frame_url):
            if desc["path"] == path and desc["tag"] == tag:
                return True
        return False


@dataclass
class _BrowserCommand:
    operation: str
    session_key: str
    kwargs: dict[str, Any]
    response: queue.Queue[tuple[bool, Any]]
    deadline: float
    cancelled: threading.Event = field(default_factory=threading.Event)


@dataclass
class _PlaywrightSession:
    context: Any
    page: Any
    last_used: float


# JavaScript accessibility walk + element-resolution probe executed inside
# Chromium frames (works for cross-origin frames — it runs in the frame's own
# world).  Returns the same bounded descriptor schema as the offline walker:
# tag/role/name/input_type/sensitive/shadow flags/structural path + safe
# metadata.  Never reads input values, cookies, storage or headers.
_JS_ACCESSIBILITY = r"""
(opts) => {
  const mode = (opts && opts.mode) || 'list';
  const fingerprint = (opts && opts.fingerprint) || null;
  const wantPath = (opts && opts.path) || [];
  const root = document.documentElement;
  const clean = (value, n) => {
    if (value == null) return '';
    const s = String(value).replace(/\s+/g, ' ').trim();
    return s.length > n ? s.slice(0, n) : s;
  };
  const visible = (el) => {
    if (el.hasAttribute('hidden')) return false;
    if ((el.getAttribute('aria-hidden') || '').toLowerCase() === 'true') return false;
    try {
      const cs = el.ownerDocument.defaultView.getComputedStyle(el);
      return !cs || (cs.display !== 'none' && cs.visibility !== 'hidden' && cs.opacity !== '0');
    } catch (e) { return true; }
  };
  const roleOf = (el) => {
    const aria = clean(el.getAttribute('role'), 100);
    if (aria) return aria;
    const tag = el.tagName.toLowerCase();
    const tagMap = {a: 'link', button: 'button', select: 'combobox', textarea: 'textbox',
      img: 'img', nav: 'navigation', form: 'form', main: 'main', iframe: 'frame',
      summary: 'button', dialog: 'dialog'};
    if (tagMap[tag]) return tagMap[tag];
    if (/^h[1-6]$/.test(tag)) return 'heading';
    if (tag === 'input') {
      const t = (el.getAttribute('type') || 'text').toLowerCase();
      const inputMap = {button: 'button', submit: 'button', reset: 'button', image: 'button',
        checkbox: 'checkbox', radio: 'radio', range: 'slider', file: 'file',
        password: 'textbox'};
      return inputMap[t] || 'textbox';
    }
    if (el.isContentEditable) return 'textbox';
    return '';
  };
  const nameOf = (el) => {
    const label = clean(el.getAttribute('aria-label'), 300);
    if (label) return label;
    const lb = (el.getAttribute('aria-labelledby') || '').split(/\s+/).map((id) => {
      const ref = el.ownerDocument.getElementById(id);
      return ref ? clean(ref.textContent, 300) : '';
    }).filter(Boolean).join(' ').trim();
    if (lb) return lb.slice(0, 300);
    const tag = el.tagName.toLowerCase();
    if (tag === 'img') return clean(el.getAttribute('alt'), 300);
    if (tag === 'input') {
      const ph = clean(el.getAttribute('placeholder'), 300);
      if (ph) return ph;
      if (el.id) {
        const lbl = el.ownerDocument.querySelector('label[for="' + CSS.escape(el.id) + '"]');
        if (lbl) return clean(lbl.textContent, 300);
      }
      return '';
    }
    if (tag === 'iframe') return clean(el.getAttribute('title') || el.getAttribute('name'), 300);
    return clean(el.textContent, 300);
  };
  const found = [];
  const walk = (el, path, inShadow) => {
    if (!el || el.nodeType !== 1) return;
    const tag = el.tagName.toLowerCase();
    if (tag === 'script' || tag === 'style' || tag === 'noscript' || tag === 'template' ||
        tag === 'head' || tag === 'meta' || tag === 'link' || tag === 'title') return;
    const children = [];
    for (let child = el.firstElementChild; child; child = child.nextElementSibling) {
      children.push(child);
    }
    const lightLen = children.length;
    for (let i = 0; i < lightLen; i++) walk(children[i], path.concat(i), inShadow);
    const sr = el.shadowRoot;
    if (sr) {
      let j = 0;
      for (let sc = sr.firstElementChild; sc; sc = sc.nextElementSibling) {
        walk(sc, path.concat(lightLen + j), true);
        j++;
      }
    }
    const type = (el.getAttribute('type') || '').toLowerCase();
    const usable = (tag === 'a' && el.hasAttribute('href')) || tag === 'button' ||
      tag === 'input' || tag === 'select' || tag === 'textarea' || tag === 'summary' ||
      tag === 'iframe' || /^h[1-6]$/.test(tag) || tag === 'nav' || tag === 'form' ||
      tag === 'main' || tag === 'dialog' || el.isContentEditable ||
      (el.getAttribute('role') || '') !== '';
    if (!usable) return;
    if (tag === 'input' && type === 'hidden') return;
    if (!visible(el)) return;
    const role = roleOf(el);
    if (!role) return;
    const desc = {
      tag: tag,
      role: role,
      name: nameOf(el),
      input_type: tag === 'input' ? type : null,
      sensitive: tag === 'input' && type === 'password',
      disabled: el.disabled === true || el.hasAttribute('disabled'),
      checked: null,
      path: path,
      in_shadow: !!inShadow,
      shadow_root: !!el.shadowRoot,
    };
    if (tag === 'input' && (type === 'checkbox' || type === 'radio')) desc.checked = !!el.checked;
    if (tag === 'a') {
      const href = el.getAttribute('href');
      if (href) { try { desc.href = new URL(href, el.ownerDocument.baseURI).href; } catch (e) {} }
      const tgt = el.getAttribute('target');
      if (tgt) desc.target = tgt;
    }
    if (tag === 'img') { const alt = el.getAttribute('alt'); if (alt) desc.alt = alt; }
    if (tag === 'iframe') {
      const src = el.getAttribute('src');
      if (src) { try { desc.href = new URL(src, el.ownerDocument.baseURI).href; } catch (e) {} }
    }
    if (tag === 'form') {
      const act = el.getAttribute('action');
      if (act) { try { desc.action = new URL(act, el.ownerDocument.baseURI).href; } catch (e) {} }
    }
    const ph = el.getAttribute('placeholder');
    if (ph) desc.placeholder = ph;
    found.push({desc: desc, el: el});
  };
  walk(root, [], false);
  if (mode === 'list') {
    return found.map((o) => o.desc);
  }
  let matches = [];
  if (fingerprint) {
    matches = found.filter((o) =>
      o.desc.tag === fingerprint.tag && o.desc.role === fingerprint.role &&
      o.desc.name === fingerprint.name &&
      (o.desc.input_type || null) === (fingerprint.input_type || null));
  }
  let pathMatches = false;
  if (matches.length === 1) {
    pathMatches = JSON.stringify(matches[0].desc.path) === JSON.stringify(wantPath);
  }
  if (mode === 'resolve') {
    return {
      matches: matches.length,
      pathMatches: pathMatches,
      element: (matches.length === 1 && pathMatches) ? matches[0].el : null,
    };
  }
  return {matches: matches.length, pathMatches: pathMatches};
}
"""


class PlaywrightBrowserTransport:
    """Headless Chromium transport hosted on one dedicated worker thread.

    Playwright's synchronous objects are thread-affine, while ERA's hard
    timeout boundary invokes provider calls on short-lived worker threads.  A
    dedicated command thread keeps every Browser/Context/Page operation on the
    same owner thread and lets arbitrary ERA dispatch threads safely submit
    bounded operations.

    Phase 4B: element references are resolved through the same accessibility
    walk used for inspection; every resolution is fail-closed (scope, TTL,
    generation, tab, frame, origin, fingerprint).  Popups/tabs get opaque tab
    tokens; downloads are captured via ``expect_download`` and saved
    atomically inside the workspace; uploads use ``set_input_files``.
    """

    def __init__(self, *, headless: bool = True,
                 viewport_width: int = DEFAULT_VIEWPORT_WIDTH,
                 viewport_height: int = DEFAULT_VIEWPORT_HEIGHT,
                 user_agent: str = DEFAULT_USER_AGENT,
                 max_contexts: int = DEFAULT_MAX_CONTEXTS,
                 context_idle_seconds: float = DEFAULT_CONTEXT_IDLE_SECONDS,
                 command_queue_size: int = DEFAULT_COMMAND_QUEUE_SIZE,
                 proxy_server: str = "",
                 element_ref_ttl_seconds: float = DEFAULT_ELEMENT_REF_TTL_SECONDS):
        if int(max_contexts) < 1:
            raise ValueError("browser max_contexts must be positive")
        if float(context_idle_seconds) <= 0:
            raise ValueError("browser context_idle_seconds must be positive")
        if int(command_queue_size) < 1:
            raise ValueError("browser command_queue_size must be positive")
        proxy_server = proxy_server.strip()
        if proxy_server:
            proxy = urlsplit(proxy_server)
            if proxy.scheme not in {"http", "https", "socks5"} or not proxy.hostname:
                raise ValueError("browser proxy_server must be an HTTP(S) or SOCKS5 URL")
            if proxy.username is not None or proxy.password is not None:
                raise ValueError("browser proxy credentials must not be embedded in the URL")
        self.headless = bool(headless)
        self.viewport_width = int(viewport_width)
        self.viewport_height = int(viewport_height)
        self.user_agent = user_agent
        self.max_contexts = int(max_contexts)
        self.context_idle_seconds = float(context_idle_seconds)
        self.proxy_server = proxy_server
        self.refs = ElementReferenceRegistry(element_ref_ttl_seconds)
        self._commands: queue.Queue[_BrowserCommand | None] = queue.Queue(
            maxsize=int(command_queue_size),
        )
        self._start_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._closed = False
        self._playwright = None
        self._browser = None
        self._contexts: dict[str, _PlaywrightSession] = {}
        # Opaque tab tokens by live page object; frame tokens by live frame
        # object (strong refs prevent Python id() reuse across GC).
        self._tab_ids: dict[int, str] = {}
        self._frame_tokens: dict[int, tuple[str, Any]] = {}

    def navigate(self, session_key: str, url: str, *, wait_until: str,
                 timeout_ms: int) -> dict[str, Any]:
        return self._call("navigate", session_key, timeout_ms=timeout_ms,
                          url=url, wait_until=wait_until)

    def screenshot(self, session_key: str, *, selector: str | None,
                   full_page: bool, image_type: str, timeout_ms: int) -> bytes:
        return self._call("screenshot", session_key, timeout_ms=timeout_ms,
                          selector=selector, full_page=full_page, image_type=image_type)

    def extract(self, session_key: str, *, selector: str | None,
                timeout_ms: int) -> dict[str, Any]:
        return self._call("extract", session_key, timeout_ms=timeout_ms,
                          selector=selector)

    def inspect(self, session_key: str, *, max_elements: int,
                timeout_ms: int) -> dict[str, Any]:
        return self._call("inspect", session_key, timeout_ms=timeout_ms,
                          max_elements=max_elements)

    def list_tabs(self, session_key: str) -> dict[str, Any]:
        return self._call("tabs", session_key, timeout_ms=5_000)

    def activate_tab(self, session_key: str, tab_id: str,
                     timeout_ms: int) -> dict[str, Any]:
        return self._call("activate_tab", session_key, timeout_ms=timeout_ms,
                          tab_id=tab_id)

    def click(self, session_key: str, *, selector: str | None, text: str | None,
              exact: bool, element_ref: str | None = None,
              timeout_ms: int) -> dict[str, Any]:
        return self._call("click", session_key, timeout_ms=timeout_ms,
                          selector=selector, text=text, exact=exact,
                          element_ref=element_ref)

    def fill(self, session_key: str, *, selector: str | None,
             element_ref: str | None, text: str,
             timeout_ms: int) -> dict[str, Any]:
        return self._call("fill", session_key, timeout_ms=timeout_ms,
                          selector=selector, element_ref=element_ref, text=text)

    def submit(self, session_key: str, *, selector: str | None,
               element_ref: str | None = None,
               timeout_ms: int) -> dict[str, Any]:
        return self._call("submit", session_key, timeout_ms=timeout_ms,
                          selector=selector, element_ref=element_ref)

    def download(self, session_key: str, *, element_ref: str | None,
                 selector: str | None, text: str | None, exact: bool,
                 dest: str, max_bytes: int, timeout_ms: int) -> dict[str, Any]:
        return self._call("download", session_key, timeout_ms=timeout_ms,
                          element_ref=element_ref, selector=selector, text=text,
                          exact=exact, dest=dest, max_bytes=max_bytes)

    def upload(self, session_key: str, *, element_ref: str | None,
               selector: str | None, path: str,
               timeout_ms: int) -> dict[str, Any]:
        return self._call("upload", session_key, timeout_ms=timeout_ms,
                          element_ref=element_ref, selector=selector, path=path)

    def close_context(self, session_key: str) -> None:
        if self._thread is None or self._closed:
            return
        self._call("close_context", session_key, timeout_ms=5_000)

    def close(self) -> None:
        with self._start_lock:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
            thread = self._thread
            if thread is None:
                return
            try:
                self._commands.put_nowait(None)
            except queue.Full:
                pass  # worker observes _stop after the in-flight command
        thread.join(timeout=5.0)
        self.refs.invalidate_session("")

    def _ensure_started(self) -> None:
        with self._start_lock:
            if self._closed:
                raise ToolError("browser transport is closed", provider_id="browser",
                                code=ProviderErrorCode.UNAVAILABLE)
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._worker, name="era-browser-playwright", daemon=True,
                )
                self._thread.start()

    def _call(self, operation: str, session_key: str, *, timeout_ms: int,
              **kwargs: Any) -> Any:
        self._ensure_started()
        timeout_seconds = max(0.001, timeout_ms / 1000)
        deadline = time.monotonic() + timeout_seconds
        response: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)
        kwargs["timeout_ms"] = timeout_ms
        command = _BrowserCommand(
            operation, session_key, kwargs, response, deadline=deadline,
        )
        try:
            self._commands.put(command, timeout=timeout_seconds)
        except queue.Full as exc:
            command.cancelled.set()
            raise ToolError("browser command queue is full", provider_id="browser",
                            code=ProviderErrorCode.UNAVAILABLE) from exc
        remaining = max(0.001, deadline - time.monotonic())
        try:
            # Small grace lets the worker report its own deadline classification
            # while the provider's outer dispatch deadline remains authoritative.
            ok, value = response.get(timeout=remaining + 0.05)
        except queue.Empty as exc:
            command.cancelled.set()
            code = (
                ProviderErrorCode.SIDE_EFFECT_UNKNOWN
                if operation in _NON_RETRYABLE_OPERATIONS
                else ProviderErrorCode.TIMEOUT
            )
            raise ToolError("browser operation timed out", provider_id="browser",
                            code=code) from exc
        if ok:
            return value
        raise _transport_error(value)

    def _worker(self) -> None:
        poll_seconds = min(1.0, self.context_idle_seconds)
        while not self._stop.is_set():
            try:
                command = self._commands.get(timeout=poll_seconds)
            except queue.Empty:
                self._reap_idle_contexts()
                continue
            if command is None:
                break
            if command.cancelled.is_set() or time.monotonic() >= command.deadline:
                command.response.put((False, ToolError(
                    "browser command expired before dispatch",
                    provider_id="browser", code=ProviderErrorCode.TIMEOUT,
                )))
                continue
            try:
                self._ensure_runtime()
                value = self._dispatch(command)
            except BaseException as exc:  # noqa: BLE001 - returned to dispatch thread
                error = self._command_error(command, exc)
                command.response.put((False, error))
            else:
                if command.operation in _NON_RETRYABLE_OPERATIONS and (
                    command.cancelled.is_set() or time.monotonic() >= command.deadline
                ):
                    self._close_session(command.session_key)
                    command.response.put((False, ToolError(
                        "browser interaction outcome is unknown after timeout",
                        provider_id="browser",
                        code=ProviderErrorCode.SIDE_EFFECT_UNKNOWN,
                    )))
                else:
                    command.response.put((True, value))
            session = self._contexts.get(command.session_key)
            if session is not None:
                session.last_used = time.monotonic()
            self._reap_idle_contexts()
        self._shutdown_runtime()

    def _ensure_runtime(self) -> None:
        if self._browser is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise ToolError(
                "Playwright is not installed; install ERA with the browser extra",
                provider_id="browser", code=ProviderErrorCode.NOT_IMPLEMENTED,
            ) from exc
        self._playwright = sync_playwright().start()
        launch_options: dict[str, Any] = {
            "headless": self.headless,
            "args": [
                "--disable-quic",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            ],
        }
        if self.proxy_server:
            launch_options["proxy"] = {"server": self.proxy_server}
        self._browser = self._playwright.chromium.launch(**launch_options)

    def _context_page(self, session_key: str) -> tuple[Any, Any]:
        session = self._contexts.get(session_key)
        if session is not None:
            session.last_used = time.monotonic()
            return session.context, session.page
        self._reap_idle_contexts()
        if len(self._contexts) >= self.max_contexts:
            raise ToolError(
                "browser context limit reached",
                provider_id="browser", code=ProviderErrorCode.UNAVAILABLE,
            )
        context = self._browser.new_context(
            viewport={"width": self.viewport_width, "height": self.viewport_height},
            user_agent=self.user_agent,
            # Phase 4B: downloads are captured only when browser.download wraps a
            # click in expect_download(); unconsumed downloads are discarded.
            accept_downloads=True,
            service_workers="block",
        )
        context.route("**/*", self._guard_route)
        # WebSocket handshakes have historically bypassed regular request
        # routing. Disable them rather than risk private-network access.
        context.add_init_script(
            "Object.defineProperty(window, 'WebSocket', {value: class {"
            "constructor(){throw new Error('WebSocket blocked by ERA policy')}}});"
        )
        page = context.new_page()
        self._tab_ids[id(page)] = f"tab_{secrets.token_urlsafe(10)}"
        self._contexts[session_key] = _PlaywrightSession(
            context=context, page=page, last_used=time.monotonic(),
        )
        return context, page

    @staticmethod
    def _guard_route(route: Any, request: Any) -> None:
        try:
            guard_browser_request(request.url)
        except ToolError:
            route.abort("blockedbyclient")
        else:
            route.continue_()

    def _dispatch(self, command: _BrowserCommand) -> Any:
        operation = command.operation
        session_key = command.session_key
        if operation == "close_context":
            session = self._contexts.pop(session_key, None)
            self.refs.invalidate_session(session_key)
            if session is not None:
                try:
                    session.context.close()
                except Exception:  # noqa: BLE001,S110 - fail-closed cleanup
                    pass
            return None

        if operation in ("tabs", "activate_tab") and session_key not in self._contexts:
            raise _ref_error("browser context has no open page",
                             ProviderErrorCode.NOT_FOUND)

        _, page = self._context_page(session_key)
        kwargs = command.kwargs
        remaining_ms = max(1, int((command.deadline - time.monotonic()) * 1000))
        timeout_ms = min(int(kwargs.get("timeout_ms", 30_000)), remaining_ms)
        page.set_default_timeout(timeout_ms)
        page.set_default_navigation_timeout(timeout_ms)

        if operation == "navigate":
            response = page.goto(
                kwargs["url"], wait_until=kwargs["wait_until"], timeout=timeout_ms,
            )
            guard_browser_request(page.url)
            self.refs.invalidate_tab(session_key, self._tab_id_for(page))
            return {
                "url": page.url,
                "title": self._safe_title(page),
                "status": response.status if response is not None else None,
            }
        if operation == "screenshot":
            selector = kwargs.get("selector")
            if selector:
                return page.locator(selector).first.screenshot(
                    type=kwargs["image_type"], timeout=timeout_ms,
                )
            return page.screenshot(
                full_page=bool(kwargs["full_page"]),
                type=kwargs["image_type"], timeout=timeout_ms,
            )
        if operation == "extract":
            selector = kwargs.get("selector")
            if selector:
                locator = page.locator(selector).first
                html = locator.evaluate("element => element.outerHTML")
                text = locator.inner_text(timeout=timeout_ms)
            else:
                html = page.content()
                text = page.locator("body").inner_text(timeout=timeout_ms)
            return {"url": page.url, "title": self._safe_title(page), "html": html,
                    "text": text}
        if operation == "inspect":
            return self._inspect(session_key, page, int(kwargs.get("max_elements", 200)),
                                 timeout_ms)
        if operation == "tabs":
            return self._list_tabs(session_key, page)
        if operation == "activate_tab":
            return self._activate_tab(session_key, page, str(kwargs["tab_id"]))
        if operation == "click":
            return self._click(session_key, page, kwargs, timeout_ms)
        if operation == "fill":
            return self._fill(session_key, page, kwargs, timeout_ms)
        if operation == "submit":
            return self._submit(session_key, page, kwargs, timeout_ms)
        if operation == "download":
            return self._download(session_key, page, kwargs, timeout_ms)
        if operation == "upload":
            return self._upload(session_key, page, kwargs, timeout_ms)
        raise ToolError("unsupported browser transport operation", provider_id="browser",
                        code=ProviderErrorCode.NOT_IMPLEMENTED)

    # -- Phase 4B operations ----------------------------------------------------
    def _inspect(self, session_key: str, page: Any, max_elements: int,
                 timeout_ms: int) -> dict[str, Any]:
        del timeout_ms
        tab_id = self._tab_id_for(page)
        generation = self.refs.begin_snapshot(session_key, tab_id)
        frame_infos: list[dict[str, Any]] = []
        elements: list[dict[str, Any]] = []
        truncated = False
        for frame in page.frames:
            frame_id = self._frame_id_for(frame)
            frame_url = frame.url
            frame_infos.append({"frame_id": frame_id, "url": frame_url})
            try:
                descriptors = frame.evaluate(_JS_ACCESSIBILITY, {"mode": "list"})
            except Exception:  # noqa: BLE001 - detached/blocked frame: skip
                descriptors = []
            if not isinstance(descriptors, list):
                continue
            for desc in descriptors:
                if not isinstance(desc, dict) or "tag" not in desc or "path" not in desc:
                    continue
                desc["frame_id"] = frame_id
                desc["tab_id"] = tab_id
                desc["origin"] = _origin_of(frame_url)
                desc["snapshot_generation"] = generation
                desc["element_ref"] = self.refs.register(
                    session_key, tab_id=tab_id, frame_id=frame_id,
                    generation=generation, url=page.url, origin=_origin_of(frame_url),
                    fingerprint=_fingerprint_core(desc), path=tuple(desc["path"]),
                )
                elements.append(desc)
                if len(elements) >= max_elements:
                    truncated = True
                    break
            if truncated:
                break
        return {
            "url": page.url,
            "title": self._safe_title(page),
            "tab_id": tab_id,
            "tab_count": len(page.context.pages),
            "snapshot_id": secrets.token_urlsafe(16),
            "generation": generation,
            "frames": frame_infos,
            "elements": elements,
            "elements_shown": len(elements),
            "truncated": truncated,
        }

    def _list_tabs(self, session_key: str, page: Any) -> dict[str, Any]:
        del session_key
        tabs = []
        for other in page.context.pages:
            try:
                title = self._safe_title(other)
            except Exception:  # noqa: BLE001
                title = ""
            tabs.append({
                "tab_id": self._tab_id_for(other),
                "url": other.url,
                "title": title,
                "origin": _origin_of(other.url),
                "active": other == page,
            })
        return {"tabs": tabs, "active_tab_id": self._tab_id_for(page)}

    def _activate_tab(self, session_key: str, page: Any, tab_id: str) -> dict[str, Any]:
        del session_key
        target = next(
            (p for p in page.context.pages if self._tab_id_for(p) == tab_id), None,
        )
        if target is None:
            raise _ref_error("tab not found (closed or never existed)",
                             ProviderErrorCode.NOT_FOUND)
        target.bring_to_front()
        session = self._contexts.get(
            next((key for key, s in self._contexts.items() if s.page == page), ""),
        )
        if session is not None:
            session.page = target
        return {"tab_id": tab_id, "url": target.url,
                "title": self._safe_title(target), "origin": _origin_of(target.url),
                "active": True}

    def _click(self, session_key: str, page: Any, kwargs: dict[str, Any],
               timeout_ms: int) -> dict[str, Any]:
        element_ref = kwargs.get("element_ref")
        if element_ref:
            element, tab_id, frame_id, _record = self._resolve_ref_handle(
                session_key, page, element_ref,
            )
            before_url = page.url
            before_tabs = len(page.context.pages)
            element.click(timeout=timeout_ms)
            self._register_new_pages(page.context)
            self._guard_current_page(page)
            return self._post_data(
                session_key, page, tab_id, frame_id, element_ref,
                before_url, before_tabs, element,
            )
        selector = kwargs.get("selector")
        if selector:
            page.locator(selector).first.click(timeout=timeout_ms)
        else:
            page.get_by_text(kwargs["text"], exact=bool(kwargs["exact"])).first.click(
                timeout=timeout_ms,
            )
        self._register_new_pages(page.context)
        self._guard_current_page(page)
        return {"url": page.url, "title": self._safe_title(page)}

    def _fill(self, session_key: str, page: Any, kwargs: dict[str, Any],
              timeout_ms: int) -> dict[str, Any]:
        element_ref = kwargs.get("element_ref")
        if element_ref:
            element, tab_id, frame_id, _record = self._resolve_ref_handle(
                session_key, page, element_ref,
            )
            input_type = ""
            try:
                input_type = (element.get_attribute("type") or "").lower()
            except Exception:  # noqa: BLE001 - detached after resolve
                input_type = ""
            if input_type == "file":
                raise _ref_error(
                    "browser.fill cannot target a file input — use browser.upload",
                    ProviderErrorCode.VALIDATION,
                )
            before_url = page.url
            before_tabs = len(page.context.pages)
            element.fill(kwargs["text"], timeout=timeout_ms)
            self._guard_current_page(page)
            return self._post_data(
                session_key, page, tab_id, frame_id, element_ref,
                before_url, before_tabs, element,
            )
        selector = kwargs.get("selector")
        if selector is None:
            raise _ref_error("browser.fill requires a selector or element_ref",
                             ProviderErrorCode.VALIDATION)
        page.locator(selector).first.fill(kwargs["text"], timeout=timeout_ms)
        return {"url": page.url, "title": self._safe_title(page)}

    def _submit(self, session_key: str, page: Any, kwargs: dict[str, Any],
                timeout_ms: int) -> dict[str, Any]:
        del timeout_ms
        element_ref = kwargs.get("element_ref")
        if element_ref:
            element, tab_id, frame_id, _record = self._resolve_ref_handle(
                session_key, page, element_ref,
            )
            before_url = page.url
            before_tabs = len(page.context.pages)
            element.evaluate(
                "element => {"
                "const form = element.tagName === 'FORM' ? element : "
                "(element.form || element.closest('form'));"
                "if (!form) throw new Error('element is not associated with a form');"
                "if (form.requestSubmit) form.requestSubmit(); else form.submit();"
                "}",
            )
            self._register_new_pages(page.context)
            self._guard_current_page(page)
            return self._post_data(
                session_key, page, tab_id, frame_id, element_ref,
                before_url, before_tabs, element,
            )
        selector = kwargs.get("selector") or "form"
        page.locator(selector).first.evaluate(
            "element => {"
            "const form = element.tagName === 'FORM' ? element : "
            "(element.form || element.closest('form'));"
            "if (!form) throw new Error('element is not associated with a form');"
            "if (form.requestSubmit) form.requestSubmit(); else form.submit();"
            "}",
        )
        self._register_new_pages(page.context)
        self._guard_current_page(page)
        return {"url": page.url, "title": self._safe_title(page)}

    def _download(self, session_key: str, page: Any, kwargs: dict[str, Any],
                  timeout_ms: int) -> dict[str, Any]:
        max_bytes = int(kwargs["max_bytes"])
        dest = str(kwargs["dest"])
        element_ref = kwargs.get("element_ref")
        tab_id = self._tab_id_for(page)
        frame_id = ""
        try:
            if element_ref:
                element, tab_id, frame_id, _record = self._resolve_ref_handle(
                    session_key, page, element_ref,
                )
                with page.expect_download(timeout=timeout_ms) as dl_info:
                    element.click(timeout=timeout_ms)
            else:
                selector = kwargs.get("selector")
                if selector:
                    locator = page.locator(selector).first
                else:
                    locator = page.get_by_text(
                        kwargs["text"], exact=bool(kwargs["exact"]),
                    ).first
                with page.expect_download(timeout=timeout_ms) as dl_info:
                    locator.click(timeout=timeout_ms)
            download = dl_info.value
        except Exception as exc:
            # Playwright raises its own TimeoutError (not the builtin) when no
            # download event arrives within the window — a clean no-side-effect
            # outcome, so classify it as NOT_FOUND rather than ambiguous.
            if type(exc).__name__ == "TimeoutError":
                raise _ref_error("no download was triggered by the element",
                                 ProviderErrorCode.NOT_FOUND) from exc
            raise
        try:
            tmp_path = download.path()
        except Exception as exc:
            raise _ref_error("download failed before completion",
                             ProviderErrorCode.PROVIDER_ERROR) from exc
        if tmp_path is None:
            raise _ref_error("download did not complete", ProviderErrorCode.NOT_FOUND)
        source = Path(tmp_path)
        try:
            size = source.stat().st_size
        except OSError as exc:
            raise _ref_error("download artifact is unreadable",
                             ProviderErrorCode.PROVIDER_ERROR) from exc
        if size > max_bytes:
            raise _ref_error("download exceeds the configured size limit",
                             ProviderErrorCode.VALIDATION)
        dest_path = Path(dest)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        temp = dest_path.with_name(
            dest_path.name + f".era-part-{secrets.token_urlsafe(8)}",
        )
        try:
            self._bounded_copy(source, temp, max_bytes)
            os.replace(temp, dest_path)
        except OSError as exc:
            raise ToolError("browser download write failed", provider_id="browser",
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        finally:
            try:
                if temp.exists():
                    temp.unlink()
            except OSError:
                pass
            try:
                download.cancel()
            except Exception:  # noqa: BLE001,S110 - already finished is fine
                pass
        if not dest_path.is_file():
            raise _ref_error("download artifact missing after save",
                             ProviderErrorCode.PROVIDER_ERROR)
        return {
            "path": dest,
            "suggested_filename": _safe_filename(
                getattr(download, "suggested_filename", None),
            ),
            "bytes": size,
            "url": page.url,
            "tab_id": tab_id,
            "frame_id": frame_id,
        }

    def _upload(self, session_key: str, page: Any, kwargs: dict[str, Any],
                timeout_ms: int) -> dict[str, Any]:
        del timeout_ms
        element_ref = kwargs.get("element_ref")
        if element_ref:
            element, tab_id, frame_id, _record = self._resolve_ref_handle(
                session_key, page, element_ref,
            )
            input_type = ""
            try:
                input_type = (element.get_attribute("type") or "").lower()
            except Exception:  # noqa: BLE001
                input_type = ""
            if input_type != "file":
                raise _ref_error("element is not a file input",
                                 ProviderErrorCode.VALIDATION)
            element.set_input_files(kwargs["path"])
            return {"uploaded": True, "path": kwargs["path"], "tab_id": tab_id,
                    "frame_id": frame_id}
        selector = kwargs.get("selector")
        if selector is None:
            raise _ref_error("browser.upload requires an element_ref or selector",
                             ProviderErrorCode.VALIDATION)
        locator = page.locator(selector).first
        input_type = (locator.get_attribute("type") or "").lower()
        if input_type != "file":
            raise _ref_error("element is not a file input",
                             ProviderErrorCode.VALIDATION)
        locator.set_input_files(kwargs["path"])
        return {"uploaded": True, "path": kwargs["path"],
                "tab_id": self._tab_id_for(page), "frame_id": ""}

    # -- element-reference resolution ------------------------------------------
    def _resolve_ref_handle(self, session_key: str, page: Any, ref: str):
        """Resolve exactly one element or raise a deterministic error."""
        tab_id = self._tab_id_for(page)
        record = self.refs.get(session_key, ref)
        if record is None:
            raise _ref_error(
                "element reference not found (never issued or already invalidated)",
                ProviderErrorCode.NOT_FOUND,
            )
        frame = self._find_frame(page, record.frame_id)
        if frame is None:
            raise _ref_error("element's frame no longer exists",
                             ProviderErrorCode.CONFLICT)
        generation = self.refs.generation(session_key, tab_id)
        self.refs.check_scope(
            record, session_key=session_key, active_tab_id=tab_id,
            active_url=page.url, generation=generation,
            frame_origin=_origin_of(frame.url),
        )
        try:
            handle = frame.evaluate_handle(_JS_ACCESSIBILITY, {
                "mode": "resolve",
                "fingerprint": record.fingerprint,
                "path": list(record.path),
            })
        except Exception as exc:
            raise _ref_error("element's frame no longer exists",
                             ProviderErrorCode.CONFLICT) from exc
        try:
            matches = int(handle.get_property("matches").json_value())
            path_ok = bool(handle.get_property("pathMatches").json_value())
            element = handle.get_property("element").as_element()
        except Exception as exc:
            raise _ref_error("element reference could not be resolved",
                             ProviderErrorCode.CONFLICT) from exc
        if matches == 0 or element is None:
            raise _ref_error(
                "no element matches the reference (element removed or page drifted)",
                ProviderErrorCode.NOT_FOUND,
            )
        if matches > 1:
            raise _ref_error(
                "multiple elements match the reference fingerprint — re-inspect",
                ProviderErrorCode.CONFLICT,
            )
        if not path_ok:
            raise _ref_error(
                "element moved or page drifted (fingerprint mismatch)",
                ProviderErrorCode.CONFLICT,
            )
        return element, tab_id, record.frame_id, record

    def _find_frame(self, page: Any, frame_id: str) -> Any | None:
        for frame in page.frames:
            token = self._frame_tokens.get(id(frame))
            if token is not None and token[0] == frame_id:
                return frame
        return None

    # -- tab/frame identity -----------------------------------------------------
    def _tab_id_for(self, page: Any) -> str:
        key = id(page)
        token = self._tab_ids.get(key)
        if token is None:
            token = f"tab_{secrets.token_urlsafe(10)}"
            self._tab_ids[key] = token
        return token

    def _frame_id_for(self, frame: Any) -> str:
        key = id(frame)
        existing = self._frame_tokens.get(key)
        if existing is not None:
            return existing[0]
        if frame == frame.page.main_frame:
            token = "frame:main"
        else:
            count = sum(
                1 for stored in self._frame_tokens.values()
                if stored[0] != "frame:main"
            )
            token = f"frame:{count + 1}"
        self._frame_tokens[key] = (token, frame)
        return token

    def _register_new_pages(self, context: Any) -> None:
        """Bounded wait for asynchronously opened popups, assigning tab tokens."""
        known = set(context.pages)
        deadline = time.monotonic() + _POPUP_DETECTION_WINDOW_SECONDS
        while time.monotonic() < deadline:
            current = set(context.pages)
            if current - known:
                break
            time.sleep(0.05)
        for page in context.pages:
            self._tab_id_for(page)

    def _post_data(self, session_key: str, page: Any, tab_id: str, frame_id: str,
                   element_ref: str, before_url: str, before_tabs: int,
                   element: Any) -> dict[str, Any]:
        attached = True
        if element is not None:
            try:
                attached = bool(element.is_connected())
            except Exception:  # noqa: BLE001 - detached/navigated page
                attached = False
        post = {
            "url": page.url,
            "origin": _origin_of(page.url),
            "tab_id": tab_id,
            "frame_id": frame_id,
            "tab_count_before": before_tabs,
            "tab_count_after": len(page.context.pages),
            "url_changed": page.url != before_url,
            "element_attached": attached,
        }
        if page.url != before_url:
            self.refs.invalidate_tab(session_key, tab_id)
        return {
            "url": page.url,
            "title": self._safe_title(page),
            "tab_id": tab_id,
            "frame_id": frame_id,
            "origin": _origin_of(page.url),
            "element_ref": element_ref,
            "post_condition": post,
        }

    @staticmethod
    def _safe_title(page: Any) -> str:
        try:
            return page.title()
        except Exception:  # noqa: BLE001 - page mid-navigation
            return ""

    @staticmethod
    def _bounded_copy(source: Path, dest: Path, max_bytes: int) -> int:
        total = 0
        with source.open("rb") as src, dest.open("wb") as out:
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise _ref_error("download exceeds the configured size limit",
                                     ProviderErrorCode.VALIDATION)
                out.write(chunk)
        return total

    @staticmethod
    def _guard_current_page(page: Any) -> None:
        if page.url and page.url != "about:blank":
            guard_browser_request(page.url)

    def _command_error(self, command: _BrowserCommand, exc: BaseException) -> ToolError:
        error = _transport_error(exc)
        if command.operation in _NON_RETRYABLE_OPERATIONS \
                and error.code is ProviderErrorCode.TIMEOUT:
            # Chromium may have delivered the interaction before its wait timed
            # out. Never report a clean TIMEOUT (which implies no side effect),
            # and quarantine all resulting page/cookie state.
            self._close_session(command.session_key)
            return ToolError(
                "browser interaction outcome is unknown after timeout",
                provider_id="browser",
                code=ProviderErrorCode.SIDE_EFFECT_UNKNOWN,
            )
        return error

    def _close_session(self, session_key: str) -> None:
        session = self._contexts.pop(session_key, None)
        self.refs.invalidate_session(session_key)
        if session is None:
            return
        try:
            session.context.close()
        except Exception:  # noqa: BLE001,S110 - fail-closed cleanup
            pass

    def _reap_idle_contexts(self) -> None:
        cutoff = time.monotonic() - self.context_idle_seconds
        expired = [
            key for key, session in self._contexts.items()
            if session.last_used <= cutoff
        ]
        for key in expired:
            self._close_session(key)

    def _shutdown_runtime(self) -> None:
        for key in list(self._contexts):
            self._close_session(key)
        self._contexts.clear()
        self._tab_ids.clear()
        self._frame_tokens.clear()
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:  # noqa: BLE001,S110
                pass
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:  # noqa: BLE001,S110
                pass


def _safe_filename(name: str | None) -> str:
    base = Path(name or "download").name
    base = "".join(ch for ch in base if ch.isprintable() and ch not in "/\\\x00")
    return _bounded(base or "download", MAX_NAME_CHARS)


def _transport_error(exc: BaseException) -> ToolError:
    if isinstance(exc, ToolError):
        return exc
    name = type(exc).__name__.lower()
    message = str(exc).lower()
    if "timeout" in name:
        code = ProviderErrorCode.TIMEOUT
        safe_message = "browser operation timed out"
    elif "executable doesn't exist" in message or "browser executable" in message:
        code = ProviderErrorCode.NOT_IMPLEMENTED
        safe_message = "Chromium is not installed; run 'playwright install chromium'"
    else:
        code = ProviderErrorCode.PROVIDER_ERROR
        safe_message = f"browser engine error: {type(exc).__name__}"
    return ToolError(safe_message, provider_id="browser", code=code)


class BrowserProvider:
    """ERA ToolProvider implementing the catalogued browser actions.

    Phase 4B adds ``browser.inspect`` (bounded accessibility snapshots with
    provider-issued element refs), ``browser.tabs`` / ``browser.activate_tab``,
    ``browser.download`` and ``browser.upload``, and extends the mutating
    actions with ``element_ref`` targeting and deterministic post-condition
    verification.  All refs are resolved fail-closed by the transport.
    """

    id = "browser"
    action_types = _ACTION_TYPES
    # ExecutionService and AgentLoop both consult this declaration. Transport
    # errors or failed post-condition checks must never repeat these effects.
    non_retryable_action_types = _NON_RETRYABLE_ACTION_TYPES

    def __init__(self, *, workspace_root: str | Path,
                 transport: BrowserTransport | None = None,
                 headless: bool = True,
                 timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
                 viewport_width: int = DEFAULT_VIEWPORT_WIDTH,
                 viewport_height: int = DEFAULT_VIEWPORT_HEIGHT,
                 user_agent: str = DEFAULT_USER_AGENT,
                 max_contexts: int = DEFAULT_MAX_CONTEXTS,
                 context_idle_seconds: float = DEFAULT_CONTEXT_IDLE_SECONDS,
                 command_queue_size: int = DEFAULT_COMMAND_QUEUE_SIZE,
                 proxy_server: str = "",
                 secret_resolver: Any | None = None,
                 element_ref_ttl_seconds: float = DEFAULT_ELEMENT_REF_TTL_SECONDS,
                 max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
                 max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES):
        if float(timeout_seconds) <= 0:
            raise ValueError("browser timeout_seconds must be positive")
        if int(viewport_width) <= 0 or int(viewport_height) <= 0:
            raise ValueError("browser viewport dimensions must be positive")
        if not isinstance(user_agent, str) or not user_agent.strip():
            raise ValueError("browser user_agent must be non-empty")
        if int(max_download_bytes) <= 0 or int(max_download_bytes) > MAX_TRANSFER_BYTES_CAP:
            raise ValueError("browser max_download_bytes out of range")
        if int(max_upload_bytes) <= 0 or int(max_upload_bytes) > MAX_TRANSFER_BYTES_CAP:
            raise ValueError("browser max_upload_bytes out of range")
        self.workspace = WorkspaceRoot(workspace_root)
        self.timeout_seconds = float(timeout_seconds)
        self.viewport_width = int(viewport_width)
        self.viewport_height = int(viewport_height)
        self.user_agent = user_agent
        self.headless = bool(headless)
        self._secret_resolver = secret_resolver
        self.element_ref_ttl_seconds = float(element_ref_ttl_seconds)
        self.max_download_bytes = int(max_download_bytes)
        self.max_upload_bytes = int(max_upload_bytes)
        self.transport = transport or PlaywrightBrowserTransport(
            headless=self.headless,
            viewport_width=self.viewport_width,
            viewport_height=self.viewport_height,
            user_agent=self.user_agent,
            max_contexts=max_contexts,
            context_idle_seconds=context_idle_seconds,
            command_queue_size=command_queue_size,
            proxy_server=proxy_server,
            element_ref_ttl_seconds=self.element_ref_ttl_seconds,
        )

    def validate(self, action: Action) -> None:
        params = action.params or {}
        action_type = action.action_type
        if action_type not in self.action_types:
            raise ToolError(f"browser cannot handle {action_type}", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)

        if action_type == ActionType.BROWSER_NAVIGATE.value:
            url = _required_string(params, "url", self.id)
            validate_public_url(url)
            wait_until = params.get("wait_until", "domcontentloaded")
            if wait_until not in {"commit", "domcontentloaded", "load", "networkidle"}:
                raise ToolError("invalid wait_until value", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            return

        if action_type == ActionType.BROWSER_SCREENSHOT.value:
            path = _required_string(params, "path", self.id)
            resolved = self.workspace.resolve(path)
            if resolved.suffix.lower() not in {".png", ".jpg", ".jpeg"}:
                raise ToolError("screenshot path must end in .png, .jpg or .jpeg",
                                provider_id=self.id, code=ProviderErrorCode.VALIDATION)
            selector = params.get("selector")
            _optional_string(selector, "selector", self.id)
            if selector and params.get("full_page", False):
                raise ToolError("element screenshots cannot use full_page",
                                provider_id=self.id, code=ProviderErrorCode.VALIDATION)
            return

        if action_type == ActionType.BROWSER_EXTRACT_DOM.value:
            _optional_string(params.get("selector"), "selector", self.id)
            max_chars = params.get("max_chars", DEFAULT_DOM_CHARS)
            if not isinstance(max_chars, int) or isinstance(max_chars, bool) \
                    or not 1 <= max_chars <= MAX_DOM_CHARS:
                raise ToolError(f"max_chars must be between 1 and {MAX_DOM_CHARS}",
                                provider_id=self.id, code=ProviderErrorCode.VALIDATION)
            dump_path = params.get("save_html_path")
            if dump_path is not None:
                _optional_string(dump_path, "save_html_path", self.id)
                resolved = self.workspace.resolve(dump_path)
                if resolved.suffix.lower() not in {".html", ".htm"}:
                    raise ToolError("HTML dump path must end in .html or .htm",
                                    provider_id=self.id,
                                    code=ProviderErrorCode.VALIDATION)
            return

        if action_type == ActionType.BROWSER_CLICK.value:
            _validate_target_choice(params, self.id)
            _validate_expect(params, self.id)
            return

        if action_type == ActionType.BROWSER_FILL.value:
            selector = params.get("selector")
            element_ref = params.get("element_ref")
            _optional_string(selector, "selector", self.id)
            _optional_string(element_ref, "element_ref", self.id)
            if bool(selector) == bool(element_ref):
                raise ToolError(
                    "browser.fill requires exactly one of selector or element_ref",
                    provider_id=self.id, code=ProviderErrorCode.VALIDATION,
                )
            text = params.get("text")
            value_ref = params.get("value_ref")
            if (text is None) == (value_ref is None):
                raise ToolError(
                    "browser.fill requires exactly one of text or value_ref",
                    provider_id=self.id, code=ProviderErrorCode.VALIDATION,
                )
            if text is not None and not isinstance(text, str):
                raise ToolError("browser.fill text must be a string", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if value_ref is not None:
                if not is_vault_ref(value_ref):
                    raise ToolError("browser.fill value_ref must be a vault reference",
                                    provider_id=self.id,
                                    code=ProviderErrorCode.VALIDATION)
                parsed = parse_vault_ref(value_ref)
                if parsed is None or parsed[0] != "browser":
                    raise ToolError("browser.fill value_ref must use the browser vault domain",
                                    provider_id=self.id,
                                    code=ProviderErrorCode.VALIDATION)
            return

        if action_type == ActionType.BROWSER_SUBMIT.value:
            _optional_string(params.get("selector"), "selector", self.id)
            _optional_string(params.get("element_ref"), "element_ref", self.id)
            if params.get("selector") is not None and params.get("element_ref") is not None:
                raise ToolError(
                    "browser.submit accepts at most one of selector or element_ref",
                    provider_id=self.id, code=ProviderErrorCode.VALIDATION,
                )
            _validate_expect(params, self.id)
            return

        if action_type == ActionType.BROWSER_INSPECT.value:
            max_elements = params.get("max_elements", DEFAULT_MAX_INSPECT_ELEMENTS)
            if not isinstance(max_elements, int) or isinstance(max_elements, bool) \
                    or not 1 <= max_elements <= MAX_INSPECT_ELEMENTS_CAP:
                raise ToolError(
                    f"max_elements must be between 1 and {MAX_INSPECT_ELEMENTS_CAP}",
                    provider_id=self.id, code=ProviderErrorCode.VALIDATION,
                )
            return

        if action_type == ActionType.BROWSER_TABS.value:
            return

        if action_type == ActionType.BROWSER_ACTIVATE_TAB.value:
            _required_string(params, "tab_id", self.id)
            return

        if action_type == ActionType.BROWSER_DOWNLOAD.value:
            _required_string(params, "path", self.id)
            self.workspace.resolve(str(params["path"]))
            _validate_target_choice(params, self.id)
            max_bytes = params.get("max_bytes", self.max_download_bytes)
            if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) \
                    or not 1 <= max_bytes <= MAX_TRANSFER_BYTES_CAP:
                raise ToolError("download max_bytes out of range", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            return

        if action_type == ActionType.BROWSER_UPLOAD.value:
            path = _required_string(params, "path", self.id)
            resolved = self.workspace.resolve(path)
            if not resolved.is_file():
                raise ToolError("upload source file does not exist", provider_id=self.id,
                                code=ProviderErrorCode.NOT_FOUND)
            if resolved.stat().st_size > self.max_upload_bytes:
                raise ToolError("upload source file exceeds the size limit",
                                provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            _validate_target_choice(params, self.id)
            return

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        # Repeat all checks at the last responsible moment.  In particular this
        # repeats DNS/IP URL validation after authorization and before Chromium.
        self.validate(action)
        params = action.params or {}
        session_key = self._session_key(ctx)
        timeout_seconds = self.timeout_seconds
        if ctx.deadline is not None:
            remaining = ctx.deadline - time.monotonic() - _DISPATCH_SAFETY_MARGIN_SECONDS
            if remaining <= 0:
                raise ToolError("browser dispatch deadline exhausted", provider_id=self.id,
                                code=ProviderErrorCode.TIMEOUT)
            timeout_seconds = min(timeout_seconds, remaining)
        timeout_ms = max(1, int(timeout_seconds * 1000))
        action_type = action.action_type

        try:
            if action_type == ActionType.BROWSER_NAVIGATE.value:
                url = str(params["url"])
                validate_public_url(url)
                data = self.transport.navigate(
                    session_key, url,
                    wait_until=str(params.get("wait_until", "domcontentloaded")),
                    timeout_ms=timeout_ms,
                )
                return ActionResult(
                    success=True,
                    summary=f"navigated to {data.get('url', url)}",
                    data=_public_page_metadata(data),
                )

            if action_type == ActionType.BROWSER_SCREENSHOT.value:
                rel_path = str(params["path"])
                path = self.workspace.resolve(rel_path)
                suffix = path.suffix.lower()
                image_type = "jpeg" if suffix in {".jpg", ".jpeg"} else "png"
                image = self.transport.screenshot(
                    session_key,
                    selector=params.get("selector"),
                    full_page=bool(params.get("full_page", False)),
                    image_type=image_type,
                    timeout_ms=timeout_ms,
                )
                if not isinstance(image, bytes) or not image:
                    raise ToolError("browser returned an empty screenshot",
                                    provider_id=self.id,
                                    code=ProviderErrorCode.PROVIDER_ERROR)
                if len(image) > MAX_SCREENSHOT_BYTES:
                    raise ToolError("browser screenshot exceeds the size limit",
                                    provider_id=self.id,
                                    code=ProviderErrorCode.PROVIDER_ERROR)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(image)
                return ActionResult(
                    success=True,
                    summary=f"saved browser screenshot to {rel_path}",
                    data={"path": self.workspace.path_of(path), "bytes": len(image)},
                )

            if action_type == ActionType.BROWSER_EXTRACT_DOM.value:
                raw = self.transport.extract(
                    session_key, selector=params.get("selector"), timeout_ms=timeout_ms,
                )
                return self._dom_result(raw, params)

            if action_type == ActionType.BROWSER_INSPECT.value:
                max_elements = int(params.get("max_elements", DEFAULT_MAX_INSPECT_ELEMENTS))
                raw = self.transport.inspect(
                    session_key, max_elements=max_elements, timeout_ms=timeout_ms,
                )
                return self._inspect_result(raw)

            if action_type == ActionType.BROWSER_TABS.value:
                data = self.transport.list_tabs(session_key)
                return ActionResult(
                    success=True,
                    summary=(f"{len(data.get('tabs', []))} browser tab(s) open"),
                    data=data,
                )

            if action_type == ActionType.BROWSER_ACTIVATE_TAB.value:
                data = self.transport.activate_tab(
                    session_key, str(params["tab_id"]), timeout_ms=timeout_ms,
                )
                return ActionResult(
                    success=True,
                    summary=f"activated browser tab {data.get('tab_id')}",
                    data=_interaction_receipt(data),
                )

            if action_type == ActionType.BROWSER_CLICK.value:
                data = self.transport.click(
                    session_key,
                    selector=params.get("selector"),
                    text=params.get("text"),
                    element_ref=params.get("element_ref"),
                    exact=bool(params.get("exact", False)),
                    timeout_ms=timeout_ms,
                )
                self._verify_expect(params.get("expect"), data)
                return ActionResult(success=True, summary="clicked browser element",
                                    data=_interaction_receipt(data))

            if action_type == ActionType.BROWSER_FILL.value:
                fill_text = self._resolve_fill_text(params, ctx)
                data = self.transport.fill(
                    session_key, selector=params.get("selector"),
                    element_ref=params.get("element_ref"),
                    text=fill_text, timeout_ms=timeout_ms,
                )
                return ActionResult(success=True, summary="filled browser input",
                                    data=_interaction_receipt(data))

            if action_type == ActionType.BROWSER_SUBMIT.value:
                data = self.transport.submit(
                    session_key, selector=params.get("selector"),
                    element_ref=params.get("element_ref"), timeout_ms=timeout_ms,
                )
                self._verify_expect(params.get("expect"), data)
                return ActionResult(success=True, summary="submitted browser form",
                                    data=_interaction_receipt(data))

            if action_type == ActionType.BROWSER_DOWNLOAD.value:
                rel_path = str(params["path"])
                dest = self.workspace.resolve(rel_path)
                max_bytes = int(params.get("max_bytes", self.max_download_bytes))
                data = self.transport.download(
                    session_key,
                    element_ref=params.get("element_ref"),
                    selector=params.get("selector"),
                    text=params.get("text"),
                    exact=bool(params.get("exact", False)),
                    dest=str(dest),
                    max_bytes=min(max_bytes, self.max_download_bytes),
                    timeout_ms=timeout_ms,
                )
                self._verify_download_artifact(dest)
                return ActionResult(
                    success=True,
                    summary=(f"downloaded {data.get('bytes', 0)} bytes to {rel_path}"),
                    data={
                        "path": self.workspace.path_of(dest),
                        "bytes": data.get("bytes"),
                        "suggested_filename": data.get("suggested_filename"),
                        "tab_id": data.get("tab_id"),
                        "frame_id": data.get("frame_id"),
                        "url": data.get("url"),
                    },
                )

            if action_type == ActionType.BROWSER_UPLOAD.value:
                rel_path = str(params["path"])
                source = self.workspace.resolve(rel_path)
                if not source.is_file():
                    raise ToolError("upload source file does not exist",
                                    provider_id=self.id,
                                    code=ProviderErrorCode.NOT_FOUND)
                if source.stat().st_size > self.max_upload_bytes:
                    raise ToolError("upload source file exceeds the size limit",
                                    provider_id=self.id,
                                    code=ProviderErrorCode.VALIDATION)
                data = self.transport.upload(
                    session_key,
                    element_ref=params.get("element_ref"),
                    selector=params.get("selector"),
                    path=str(source),
                    timeout_ms=timeout_ms,
                )
                return ActionResult(
                    success=True,
                    summary=f"uploaded {rel_path} to the page",
                    data={"path": rel_path, "tab_id": data.get("tab_id"),
                          "frame_id": data.get("frame_id")},
                )
        except ToolError:
            raise
        except TimeoutError as exc:
            if action_type in self.non_retryable_action_types:
                self.close_context(ctx)
                raise ToolError(
                    "browser interaction outcome is unknown after timeout",
                    provider_id=self.id,
                    code=ProviderErrorCode.SIDE_EFFECT_UNKNOWN,
                ) from exc
            raise _transport_error(exc) from exc
        except OSError as exc:
            raise ToolError("browser workspace write failed", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        except Exception as exc:
            raise _transport_error(exc) from exc

        raise ToolError(f"browser cannot handle {action_type}", provider_id=self.id,
                        code=ProviderErrorCode.NOT_IMPLEMENTED)

    # -- Phase 4B result shaping -------------------------------------------------
    def _inspect_result(self, raw: dict[str, Any]) -> ActionResult:
        elements = raw.get("elements", [])
        data: dict[str, Any] = {
            "url": raw.get("url", ""),
            "title": str(raw.get("title", ""))[:500],
            "tab_id": raw.get("tab_id"),
            "tab_count": raw.get("tab_count"),
            "snapshot_id": raw.get("snapshot_id"),
            "generation": raw.get("generation"),
            "frames": raw.get("frames", []),
            "elements": elements,
            "elements_shown": len(elements),
            "truncated": bool(raw.get("truncated", False)),
            # Webpage-derived content is data, never instructions (Phase 4B
            # prompt-injection defense: consumers must treat it as untrusted).
            "content_untrusted": True,
        }
        return ActionResult(
            success=True,
            summary=(f"inspected {len(elements)} usable element(s) in "
                     f"{len(raw.get('frames', []))} frame(s)"),
            data=data,
        )

    @staticmethod
    def _verify_expect(expect: Any, data: dict[str, Any]) -> None:
        if not expect:
            return
        kind = str(expect.get("kind", ""))
        post = data.get("post_condition") or {}
        url = str(data.get("url", ""))
        if kind == "navigation":
            url_contains = expect.get("url_contains")
            ok = bool(url_contains) and url_contains in url
            if not url_contains:
                ok = bool(post.get("url_changed"))
        elif kind == "tab_opened":
            ok = int(post.get("tab_count_after", 0)) > int(post.get("tab_count_before", 0))
        elif kind == "element_detached":
            ok = not bool(post.get("element_attached"))
        else:
            ok = False
        if not ok:
            raise ToolError(
                f"post-condition verification failed: expected {kind}",
                provider_id="browser", code=ProviderErrorCode.CONFLICT,
            )

    def _verify_download_artifact(self, dest: Path) -> None:
        """Fail closed unless the final artifact exists inside the workspace."""
        if not dest.is_file():
            raise ToolError("download artifact missing after save", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR)
        resolved = dest.resolve()
        if resolved != self.workspace.root and self.workspace.root not in resolved.parents:
            raise ToolError("download artifact escaped the workspace sandbox",
                            provider_id=self.id, code=ProviderErrorCode.FORBIDDEN)

    def _resolve_fill_text(self, params: dict[str, Any], ctx: ExecutionContext) -> str:
        text = params.get("text")
        if isinstance(text, str):
            return text
        value_ref = str(params.get("value_ref", ""))
        if self._secret_resolver is None \
                or not hasattr(self._secret_resolver, "resolve_ref"):
            raise ToolError("browser vault resolver is unavailable", provider_id=self.id,
                            code=ProviderErrorCode.AUTH)
        try:
            resolved = self._secret_resolver.resolve_ref(
                value_ref, actor_id=ctx.actor_id, require_owner=True,
            )
        except VaultError as exc:
            raise ToolError("browser fill credential could not be resolved",
                            provider_id=self.id, code=ProviderErrorCode.AUTH) from exc
        if not isinstance(resolved, str):
            raise ToolError("browser fill credential resolved to an invalid value",
                            provider_id=self.id, code=ProviderErrorCode.AUTH)
        return resolved

    def close_context(self, ctx: ExecutionContext) -> None:
        """Discard one actor/session's ephemeral cookies and page state."""

        self.transport.close_context(self._session_key(ctx))

    def close(self) -> None:
        """Close all browser contexts and the underlying Chromium process."""

        self.transport.close()

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.8.1",
            display_name="Browser (self-hosted Playwright Chromium)",
            is_stub=False,
            capabilities=(
                "navigate", "screenshot", "dynamic-dom", "click", "fill", "submit",
                "accessibility-inspect", "element-refs", "tabs", "frames",
                "shadow-dom", "downloads", "uploads", "post-conditions",
                "ssrf-guarded", "isolated-contexts", "workspace-confined",
            ),
        )

    def _dom_result(self, raw: dict[str, Any], params: dict[str, Any]) -> ActionResult:
        max_chars = int(params.get("max_chars", DEFAULT_DOM_CHARS))
        html = str(raw.get("html", ""))
        source_truncated = len(html) > MAX_DOM_SOURCE_CHARS
        html = html[:MAX_DOM_SOURCE_CHARS]
        base_url = str(raw.get("url", ""))
        parser = _ReadableDOMParser(base_url)
        try:
            parser.feed(html)
        except Exception:  # noqa: BLE001,S110 - malformed live HTML is expected
            pass

        raw_text = str(raw.get("text", "")) or parser.text
        text = _clean_text(raw_text)[:max_chars]
        markdown = _clean_markdown(parser.markdown)[:max_chars]
        links = parser.links[:MAX_LINKS]
        data: dict[str, Any] = {
            "url": base_url,
            "title": str(raw.get("title", ""))[:500],
            "text": text,
            "markdown": markdown,
            "links": links,
            "text_chars": len(text),
            "markdown_chars": len(markdown),
            "source_truncated": source_truncated,
        }

        dump_path = params.get("save_html_path")
        if dump_path:
            path = self.workspace.resolve(str(dump_path))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html, encoding="utf-8")
            data["html_path"] = self.workspace.path_of(path)
            data["html_bytes"] = len(html.encode("utf-8"))

        return ActionResult(
            success=True,
            summary=(f"extracted {len(text)} text chars, {len(markdown)} markdown chars "
                     f"and {len(links)} link(s) from the browser DOM"),
            data=data,
        )

    @staticmethod
    def _session_key(ctx: ExecutionContext) -> str:
        actor = ctx.actor_id or "anonymous"
        scope = ctx.execution_scope or ctx.session_id or "default"
        material = f"{len(actor)}:{actor}|{len(scope)}:{scope}".encode()
        return hashlib.sha256(material).hexdigest()


class _ReadableDOMParser(HTMLParser):
    """Small dependency-free readable-text/Markdown/link extractor."""

    _BLOCKS = frozenset({
        "article", "aside", "blockquote", "div", "footer", "header", "main", "nav",
        "p", "section", "table", "tr",
    })
    _SKIP = frozenset({"script", "style", "noscript", "template", "svg"})

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self._skip_depth = 0
        self._markdown: list[str] = []
        self._text: list[str] = []
        self._anchor_stack: list[dict[str, Any]] = []
        self.links: list[dict[str, str]] = []

    @property
    def text(self) -> str:
        return " ".join(self._text)

    @property
    def markdown(self) -> str:
        return "".join(self._markdown)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in self._SKIP:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        values = dict(attrs)
        if tag in self._BLOCKS:
            self._markdown.append("\n\n")
        elif tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._markdown.append("\n\n" + "#" * int(tag[1]) + " ")
        elif tag == "li":
            self._markdown.append("\n- ")
        elif tag == "br":
            self._markdown.append("\n")
        elif tag in {"strong", "b"}:
            self._markdown.append("**")
        elif tag in {"em", "i"}:
            self._markdown.append("*")
        elif tag == "a":
            href = str(values.get("href") or "").strip()
            resolved = urljoin(self.base_url, href) if href else ""
            self._anchor_stack.append({"href": resolved, "text": []})
            self._markdown.append("[")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self._SKIP:
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag == "a" and self._anchor_stack:
            anchor = self._anchor_stack.pop()
            href = anchor["href"]
            self._markdown.append(f"]({href})" if href else "]")
            if href and len(self.links) < MAX_LINKS:
                label = _clean_inline(" ".join(anchor["text"]))
                self.links.append({"text": label[:500], "url": href[:2048]})
        elif tag in {"strong", "b"}:
            self._markdown.append("**")
        elif tag in {"em", "i"}:
            self._markdown.append("*")
        elif tag in self._BLOCKS or tag.startswith("h") and len(tag) == 2:
            self._markdown.append("\n\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        clean = _clean_inline(data)
        if not clean:
            return
        self._text.append(clean)
        self._markdown.append(clean + " ")
        if self._anchor_stack:
            self._anchor_stack[-1]["text"].append(clean)


def _required_string(params: dict[str, Any], key: str, provider_id: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ToolError(f"'{key}' is required", provider_id=provider_id,
                        code=ProviderErrorCode.VALIDATION)
    return value.strip()


def _optional_string(value: Any, name: str, provider_id: str) -> None:
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise ToolError(f"'{name}' must be a non-empty string", provider_id=provider_id,
                        code=ProviderErrorCode.VALIDATION)


def _public_page_metadata(data: dict[str, Any]) -> dict[str, Any]:
    return {
        key: data[key]
        for key in ("url", "title", "status")
        if key in data and data[key] is not None
    }


def _validate_target_choice(params: dict[str, Any], provider_id: str) -> None:
    """Require exactly one of selector | text | element_ref (Phase 4B)."""
    selector = params.get("selector")
    text = params.get("text")
    element_ref = params.get("element_ref")
    _optional_string(selector, "selector", provider_id)
    _optional_string(text, "text", provider_id)
    _optional_string(element_ref, "element_ref", provider_id)
    chosen = sum(1 for value in (selector, text, element_ref) if value is not None)
    if chosen != 1:
        raise ToolError(
            "action requires exactly one of selector, text or element_ref",
            provider_id=provider_id, code=ProviderErrorCode.VALIDATION,
        )


def _validate_expect(params: dict[str, Any], provider_id: str) -> None:
    expect = params.get("expect")
    if expect is None:
        return
    if not isinstance(expect, dict):
        raise ToolError("expect must be an object", provider_id=provider_id,
                        code=ProviderErrorCode.VALIDATION)
    kind = expect.get("kind")
    if kind not in {"navigation", "tab_opened", "element_detached"}:
        raise ToolError("expect.kind must be navigation, tab_opened or "
                        "element_detached", provider_id=provider_id,
                        code=ProviderErrorCode.VALIDATION)
    url_contains = expect.get("url_contains")
    if url_contains is not None and (not isinstance(url_contains, str)
                                     or not url_contains.strip()):
        raise ToolError("expect.url_contains must be a non-empty string",
                        provider_id=provider_id, code=ProviderErrorCode.VALIDATION)


def _interaction_receipt(data: dict[str, Any]) -> dict[str, Any]:
    """Bounded, sanitized interaction receipt (Phase 4B Priority 15).

    Includes action target reference (opaque), tab/frame context, origin and
    post-condition outcome.  Never includes filled values, credentials,
    cookies or raw DOM content.
    """
    return {
        key: data[key]
        for key in ("url", "title", "status", "tab_id", "frame_id", "origin",
                    "element_ref", "post_condition")
        if key in data and data[key] is not None
    }


def _clean_inline(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _clean_text(text: str) -> str:
    lines = [_clean_inline(line) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def _clean_markdown(text: str) -> str:
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _title_from_html(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    return _clean_inline(re.sub(r"<[^>]+>", "", match.group(1))) if match else ""


def _plain_text_from_html(html: str) -> str:
    parser = _ReadableDOMParser("")
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001,S110
        pass
    return _clean_text(parser.text)
