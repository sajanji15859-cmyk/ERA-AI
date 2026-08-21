"""Bounded fixed-window rate limiting by API key and source IP (Phase 3F)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class _Window:
    started_at: float
    count: int = 0


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int


class FixedWindowRateLimiter:
    """Concurrency-safe, bounded in-process limiter with lazy stale cleanup."""

    def __init__(
        self,
        *,
        key_limit: int,
        ip_limit: int,
        window_seconds: float,
        now=time.monotonic,
    ):
        if key_limit < 1 or ip_limit < 1:
            raise ValueError("rate limits must be >= 1")
        if window_seconds <= 0:
            raise ValueError("rate-limit window must be > 0")
        self.key_limit = int(key_limit)
        self.ip_limit = int(ip_limit)
        self.window_seconds = float(window_seconds)
        self._now = now
        self._windows: dict[str, _Window] = {}
        self._lock = asyncio.Lock()
        self._checks = 0

    async def check(self, *, api_key_hash: str | None, ip: str) -> RateLimitDecision:
        now = self._now()
        buckets = [(f"ip:{ip}", self.ip_limit)]
        if api_key_hash:
            buckets.append((f"key:{api_key_hash}", self.key_limit))

        async with self._lock:
            self._checks += 1
            active: list[tuple[_Window, int]] = []
            for identity, limit in buckets:
                window = self._windows.get(identity)
                if window is None or now - window.started_at >= self.window_seconds:
                    window = _Window(started_at=now)
                    self._windows[identity] = window
                active.append((window, limit))
                # IP is deliberately checked first. Once it is exhausted, do
                # not allocate attacker-controlled buckets for endless fake
                # Authorization values.
                if window.count >= limit:
                    retry = max(
                        1,
                        math.ceil(self.window_seconds - (now - window.started_at)),
                    )
                    return RateLimitDecision(False, limit, 0, retry)

            for window, _limit in active:
                window.count += 1
            limit = min(limit for _window, limit in active)
            remaining = min(limit - window.count for window, limit in active)
            retry = max(
                1,
                math.ceil(min(
                    self.window_seconds - (now - window.started_at)
                    for window, _limit in active
                )),
            )
            if self._checks % 256 == 0:
                self._remove_stale(now)
            return RateLimitDecision(True, limit, max(0, remaining), retry)

    def _remove_stale(self, now: float) -> None:
        cutoff = now - self.window_seconds
        self._windows = {
            key: window
            for key, window in self._windows.items()
            if window.started_at > cutoff
        }


class RateLimitMiddleware:
    """Apply key+IP limits to versioned API paths without exposing raw keys."""

    def __init__(
        self,
        app: Any,
        *,
        key_limit: int,
        ip_limit: int,
        window_seconds: float,
        enabled: bool = True,
        limiter: FixedWindowRateLimiter | None = None,
    ):
        self.app = app
        self.enabled = enabled
        self.limiter = limiter or FixedWindowRateLimiter(
            key_limit=key_limit,
            ip_limit=ip_limit,
            window_seconds=window_seconds,
        )

    async def __call__(self, scope, receive, send):
        if (
            not self.enabled
            or scope["type"] != "http"
            or not scope.get("path", "").startswith("/v1/")
        ):
            await self.app(scope, receive, send)
            return

        decision = await self.limiter.check(
            api_key_hash=_api_key_fingerprint(scope),
            ip=_source_ip(scope),
        )
        if not decision.allowed:
            await _send_429(send, decision)
            return

        async def send_with_limit_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend([
                    (b"x-ratelimit-limit", str(decision.limit).encode("ascii")),
                    (b"x-ratelimit-remaining", str(decision.remaining).encode("ascii")),
                ])
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_limit_headers)


def _api_key_fingerprint(scope) -> str | None:
    for name, value in scope.get("headers", []):
        if name.lower() != b"authorization":
            continue
        try:
            scheme, token = value.decode("latin-1").split(" ", 1)
        except ValueError:
            return None
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            return None
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
    return None


def _source_ip(scope) -> str:
    # Do not trust X-Forwarded-For from arbitrary clients. The ASGI server/proxy
    # is responsible for supplying the verified peer in scope["client"].
    client = scope.get("client")
    if client and client[0]:
        return str(client[0])
    return "unknown"


async def _send_429(send, decision: RateLimitDecision) -> None:
    body = json.dumps({"detail": "rate limit exceeded"}, separators=(",", ":")).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"retry-after", str(decision.retry_after).encode("ascii")),
        (b"x-ratelimit-limit", str(decision.limit).encode("ascii")),
        (b"x-ratelimit-remaining", b"0"),
    ]
    await send({"type": "http.response.start", "status": 429, "headers": headers})
    await send({"type": "http.response.body", "body": body})
