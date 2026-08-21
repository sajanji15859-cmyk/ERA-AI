"""ASGI middleware for input hardening (Phase 2A).

:class:`BodySizeLimitMiddleware` rejects oversized HTTP request bodies (including
chunked bodies without a ``Content-Length`` header) with HTTP 413, before the
request reaches any handler. This complements Pydantic strict schemas and the
parameter budget validator, and protects handlers from memory-exhaustion via
giant payloads.
"""

from __future__ import annotations

from typing import Any

DEFAULT_MAX_BODY_BYTES = 262144  # 256 KiB


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
