"""ASGI middleware for input hardening (Phase 2A) and response hardening (Phase 3E).

* :class:`BodySizeLimitMiddleware` rejects oversized HTTP request bodies
  (including chunked bodies without a ``Content-Length`` header) with HTTP 413,
  before the request reaches any handler. This complements Pydantic strict
  schemas and the parameter budget validator, and protects handlers from
  memory-exhaustion via giant payloads.
* :class:`SecurityHeadersMiddleware` (Phase 3E) injects browser security headers
  (CSP, clickjacking, MIME sniffing, referrer, permissions) onto every HTTP
  response so the embedded web UI is hardened by default.
"""

from __future__ import annotations

from typing import Any

DEFAULT_MAX_BODY_BYTES = 262144  # 256 KiB

#: Content-Security-Policy for the bundled web UI (Phase 3E). Everything is
#: same-origin; no inline scripts/styles, no third-party origins, no object
#: embedding. ``frame-ancestors 'none'`` denies clickjacking.
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CSP_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class _RequestTooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    def __init__(self, app: Any, max_bytes: int = DEFAULT_MAX_BODY_BYTES):
        self.app = app
        self.max_bytes = int(max_bytes)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = _content_length(scope)
        if content_length is not None and content_length > self.max_bytes:
            await _send_413(send)
            return

        total = 0

        async def wrapped_receive():
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    raise _RequestTooLarge()
            return message

        try:
            await self.app(scope, wrapped_receive, send)
        except _RequestTooLarge:
            await _send_413(send)


def _content_length(scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    return None


async def _send_413(send) -> None:
    body = b"request body too large"
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
        ],
    })
    await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    """Inject browser security headers onto every HTTP response (Phase 3E).

    Implemented as a pure ASGI wrapper (not ``BaseHTTPMiddleware``) so it works
    correctly with streaming responses (SSE chat) — it rewrites the
    ``http.response.start`` message in place without buffering the body. Headers
    already set by the app (e.g. ``Content-Type``) are left untouched.
    """

    def __init__(self, app: Any, headers: dict[str, str] | None = None):
        self.app = app
        self.headers = {
            k.lower().encode("latin-1"): v.encode("latin-1")
            for k, v in (headers or SECURITY_HEADERS).items()
        }

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                existing = {k.lower(): v for k, v in message.get("headers", [])}
                for name, value in self.headers.items():
                    existing.setdefault(name, value)
                message = {**message, "headers": list(existing.items())}
            await send(message)

        await self.app(scope, receive, send_with_headers)
