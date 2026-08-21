"""Outbound URL / SSRF guards (Phase 3A).

A WebProvider must only fetch public internet resources. Guards applied before
any connection attempt (and again on every HTTP redirect hop, see
:class:`era.providers.web.SafeRedirectHandler`):

* scheme allowlist: ``http`` / ``https`` only;
* no userinfo (credentials) in the URL;
* hostname must be a DNS name or a *public* IP literal — private, loopback,
  link-local, reserved, unspecified and multicast ranges are always blocked;
* ports restricted to 80/443;
* DNS resolution: EVERY resolved address must be global unicast, which blocks
  DNS-rebinding to private ranges at pre-connect time.

Known limitation (documented, Phase G hardening): a concurrent DNS-rebinding
race between this check and the actual connect() is not fully mitigated with
plain ``urllib`` — that hardening ships with the browser/git phase.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from era.core.result import ProviderErrorCode, ToolError

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
ALLOWED_PORTS: frozenset[int] = frozenset({80, 443})
MAX_URL_LEN = 2048


def validate_public_url(url: str) -> tuple[str, str, int]:
    """Validate ``url``; return ``(scheme, host, port)``. Raises ``ToolError``.

    * malformed/oversized URL -> ``VALIDATION``;
    * disallowed scheme, embedded credentials, disallowed port, non-public
      host or non-public resolved address -> ``FORBIDDEN`` (SSRF guard).
    """
    if not isinstance(url, str) or not url:
        raise ToolError("url must be a non-empty string", code=ProviderErrorCode.VALIDATION)
    if len(url) > MAX_URL_LEN:
        raise ToolError("url too long", code=ProviderErrorCode.VALIDATION)
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ToolError("invalid URL", code=ProviderErrorCode.VALIDATION) from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ToolError(f"scheme {parts.scheme!r} is not allowed",
                        code=ProviderErrorCode.FORBIDDEN)
    if not parts.hostname:
        raise ToolError("URL has no hostname", code=ProviderErrorCode.VALIDATION)
    if parts.username is not None or parts.password is not None:
        raise ToolError("credentials in URLs are not allowed",
                        code=ProviderErrorCode.FORBIDDEN)
    host = parts.hostname
    port = parts.port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise ToolError(f"port {port} is not allowed", code=ProviderErrorCode.FORBIDDEN)
    _ensure_public_host(host, port)
    return scheme, host, port


def _ensure_public_host(host: str, port: int) -> None:
    """Block non-public IP literals and any hostname resolving to non-public IPs."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if not (ip.is_global and not ip.is_multicast and not ip.is_unspecified):
            raise ToolError("non-public IP literals are blocked (SSRF guard)",
                            code=ProviderErrorCode.FORBIDDEN)
        return

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ToolError("host could not be resolved", code=ProviderErrorCode.VALIDATION) from exc
    if not infos:
        raise ToolError("host resolved to no addresses", code=ProviderErrorCode.VALIDATION)
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]
        try:
            resolved = ipaddress.ip_address(addr)
        except ValueError:
            raise ToolError("host resolved to a non-IP address (SSRF guard)",
                            code=ProviderErrorCode.FORBIDDEN) from None
        if not (resolved.is_global and not resolved.is_multicast and not resolved.is_unspecified):
            raise ToolError("host resolves to a non-public address (SSRF guard)",
                            code=ProviderErrorCode.FORBIDDEN)
