"""Outbound URL validation and DNS-pinning inputs for SSRF-safe providers.

The web provider accepts public **HTTPS** resources only.  Validation resolves a
hostname once, verifies *every* returned address is globally routable, and
returns the vetted addresses to the transport.  The transport must connect to
one of those returned IP literals instead of resolving the hostname again;
that pairing closes the normal DNS-rebinding TOCTOU gap.

This module deliberately has no HTTP client dependency.  Browser and other
providers can use :func:`validate_public_url` for the policy check, while the
web provider consumes :func:`resolve_public_url` and pins its TCP connection.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from era.core.result import ProviderErrorCode, ToolError

#: Phase 5A deliberately narrows the legacy HTTP(S) surface to HTTPS only.
ALLOWED_SCHEMES: frozenset[str] = frozenset({"https"})
ALLOWED_PORTS: frozenset[int] = frozenset({443})
MAX_URL_LEN = 2048
MAX_HOST_LEN = 253

# URLs end up in action params/audit metadata.  Credentials belong in provider
# headers or vault references, never in an outbound URL.
_SECRET_QUERY_HINTS = frozenset({
    "access_token", "api_key", "apikey", "auth", "authorization", "credential",
    "key", "password", "secret", "signature", "token",
})


@dataclass(frozen=True)
class ResolvedPublicURL:
    """A validated URL and the exact public addresses resolved for its host."""

    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]

    @property
    def connect_address(self) -> str:
        """The first validated address suitable for a pinned TCP connection."""

        return self.addresses[0]


def validate_public_url(url: str) -> tuple[str, str, int]:
    """Validate an outbound public HTTPS URL.

    Returns ``(scheme, host, port)`` for backwards compatibility.  Call
    :func:`resolve_public_url` when the caller will open a network connection:
    it supplies the vetted IP addresses that must be used by that transport.

    ``VALIDATION`` is reserved for malformed input.  Any attempt to reach a
    private, link-local, loopback, reserved, multicast, or credential-bearing
    target is ``FORBIDDEN`` and is never retry-eligible.
    """

    resolved = resolve_public_url(url)
    return resolved.scheme, resolved.host, resolved.port


def resolve_public_url(url: str) -> ResolvedPublicURL:
    """Validate and resolve ``url`` without allowing a DNS rebinding bypass."""

    if not isinstance(url, str) or not url:
        raise ToolError("url must be a non-empty string", code=ProviderErrorCode.VALIDATION)
    if len(url) > MAX_URL_LEN:
        raise ToolError("url too long", code=ProviderErrorCode.VALIDATION)
    if any(ord(char) < 0x20 for char in url):
        raise ToolError("URL contains control characters", code=ProviderErrorCode.VALIDATION)

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ToolError("invalid URL", code=ProviderErrorCode.VALIDATION) from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ToolError(f"scheme {parts.scheme!r} is not allowed", code=ProviderErrorCode.FORBIDDEN)
    if not parts.hostname:
        raise ToolError("URL has no hostname", code=ProviderErrorCode.VALIDATION)
    if parts.username is not None or parts.password is not None:
        raise ToolError("credentials in URLs are not allowed", code=ProviderErrorCode.FORBIDDEN)

    try:
        port = parts.port or 443
    except ValueError as exc:
        raise ToolError("invalid URL port", code=ProviderErrorCode.VALIDATION) from exc
    if port not in ALLOWED_PORTS:
        raise ToolError(f"port {port} is not allowed", code=ProviderErrorCode.FORBIDDEN)

    host = parts.hostname.rstrip(".").lower()
    if not host or len(host) > MAX_HOST_LEN or "%" in host:
        # A zone-scoped IPv6 address is always local-interface-specific and
        # must never be accepted as an internet destination.
        raise ToolError("invalid URL hostname", code=ProviderErrorCode.VALIDATION)
    _reject_secret_query(parts.query)
    addresses = _resolve_public_host(host, port)
    return ResolvedPublicURL(
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        addresses=addresses,
    )


def _reject_secret_query(query: str) -> None:
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError as exc:
        raise ToolError("invalid URL query", code=ProviderErrorCode.VALIDATION) from exc
    for key, _value in pairs:
        normalized = key.strip().lower().replace("-", "_")
        if normalized in _SECRET_QUERY_HINTS:
            raise ToolError("credentials in URLs are not allowed", code=ProviderErrorCode.FORBIDDEN)


def _is_public_address(address: str) -> bool:
    """Return whether an IP is a public globally routable unicast address."""

    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False

    # ``is_global`` rejects RFC1918, loopback, link-local, documentation,
    # carrier-grade NAT, reserved, unspecified and multicast ranges.  The
    # explicit checks make the security intent clear and protect us from
    # implementation differences across Python/ipaddress releases.
    return bool(
        parsed.is_global
        and not parsed.is_private
        and not parsed.is_loopback
        and not parsed.is_link_local
        and not parsed.is_multicast
        and not parsed.is_unspecified
        and not parsed.is_reserved
    )


def _resolve_public_host(host: str, port: int) -> tuple[str, ...]:
    """Resolve all addresses and reject the whole host if any is non-public."""

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _is_public_address(str(literal)):
            raise ToolError(
                "non-public IP literals are blocked (SSRF guard)",
                code=ProviderErrorCode.FORBIDDEN,
            )
        return (str(literal),)

    try:
        infos = socket.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        # DNS failure is an availability issue for a valid destination, not a
        # malformed action.  It remains retry-eligible at the execution layer.
        raise ToolError("host could not be resolved", code=ProviderErrorCode.UNAVAILABLE) from exc
    except OSError as exc:
        raise ToolError("host could not be resolved", code=ProviderErrorCode.UNAVAILABLE) from exc

    if not infos:
        raise ToolError("host resolved to no addresses", code=ProviderErrorCode.UNAVAILABLE)

    addresses: list[str] = []
    for info in infos:
        try:
            address = str(info[4][0]).split("%", 1)[0]
        except (IndexError, TypeError) as exc:
            raise ToolError(
                "host resolved to an invalid address (SSRF guard)",
                code=ProviderErrorCode.FORBIDDEN,
            ) from exc
        if not _is_public_address(address):
            # Do not cherry-pick a public A/AAAA record if DNS also returns a
            # private one.  That pattern is a common rebinding payload.
            raise ToolError(
                "host resolves to a non-public address (SSRF guard)",
                code=ProviderErrorCode.FORBIDDEN,
            )
        if address not in addresses:
            addresses.append(address)

    if not addresses:
        raise ToolError("host resolved to no addresses", code=ProviderErrorCode.UNAVAILABLE)
    return tuple(addresses)


# Kept as a private compatibility hook for older tests/extensions that imported
# it.  New code should use ``resolve_public_url``.
def _ensure_public_host(host: str, port: int) -> None:
    _resolve_public_host(host, port)
