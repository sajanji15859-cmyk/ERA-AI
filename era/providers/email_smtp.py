"""Real, bounded SMTP email provider.

The provider owns SMTP credentials (plain environment values or vault
references) and never accepts an SMTP password through action parameters.
``email.send`` remains a COMMUNICATION action in the catalog, so all sends pass
through confirmation and audit-before-execute in :class:`ExecutionService`.

Attachments are optional workspace-relative files.  They are read only after
path confinement, size, recipient, and rate-limit checks have succeeded.
"""

from __future__ import annotations

import mimetypes
import smtplib
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Any

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.providers._rate_limit import ActorRateLimiter
from era.registry.actions import ActionType
from era.security.path_safety import WorkspaceRoot
from era.security.vault import VaultError, is_vault_ref

_MAX_ADDRESS_LEN = 320
_MAX_SUBJECT_LEN = 998
DEFAULT_MAX_RECIPIENTS = 10
DEFAULT_MAX_BODY_BYTES = 102_400
DEFAULT_MAX_ATTACHMENTS = 5
DEFAULT_MAX_ATTACHMENT_BYTES = 5_242_880
DEFAULT_MAX_SENDS_PER_HOUR = 20


class EmailSmtpProvider:
    """Sends ``email.send`` over SMTP with vault-resolvable credentials."""

    id = "email-smtp"
    action_types = frozenset({ActionType.EMAIL_SEND.value})

    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str = "",
        password: str = "",
        from_address: str = "",
        starttls: bool = False,
        use_ssl: bool = False,
        timeout_seconds: float = 10.0,
        secret_resolver=None,
        workspace_root: str | Path | None = None,
        max_recipients: int = DEFAULT_MAX_RECIPIENTS,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        max_attachments: int = DEFAULT_MAX_ATTACHMENTS,
        max_attachment_bytes: int = DEFAULT_MAX_ATTACHMENT_BYTES,
        max_sends_per_hour: int = DEFAULT_MAX_SENDS_PER_HOUR,
    ):
        if not str(host or "").strip():
            raise ValueError("EmailSmtpProvider requires an SMTP host")
        if bool(starttls) and bool(use_ssl):
            raise ValueError("SMTP STARTTLS and implicit SSL cannot both be enabled")
        self._host = str(host).strip()
        self._port = int(port)
        self._username_ref = str(username or "")
        self._password_ref = str(password or "")
        self._from_address = str(from_address or "").strip()
        self._starttls = bool(starttls)
        self._use_ssl = bool(use_ssl)
        self._timeout = max(0.1, float(timeout_seconds))
        self._resolver = secret_resolver
        self._workspace = WorkspaceRoot(workspace_root) if workspace_root is not None else None
        self._max_recipients = max(1, int(max_recipients))
        self._max_body_bytes = max(1, int(max_body_bytes))
        self._max_attachments = max(0, int(max_attachments))
        self._max_attachment_bytes = max(1, int(max_attachment_bytes))
        self._rate_limiter = ActorRateLimiter(limit=max_sends_per_hour, window_seconds=3600.0)

    # -- SPI -----------------------------------------------------------------
    def validate(self, action: Action) -> None:
        if action.action_type not in self.action_types:
            raise ToolError(f"SMTP provider cannot handle {action.action_type}", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)
        params = action.params or {}
        recipients = _collect_recipients(params)
        if not recipients:
            raise ToolError("email.send requires a non-empty 'to' address", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        if len(recipients) > self._max_recipients:
            raise ToolError(
                f"email.send allows at most {self._max_recipients} recipients",
                provider_id=self.id,
                code=ProviderErrorCode.VALIDATION,
            )
        for address in recipients:
            _validate_address(address)

        body = params.get("body")
        if not isinstance(body, str) or not body.strip():
            raise ToolError("email.send requires a non-empty 'body'", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        if len(body.encode("utf-8")) > self._max_body_bytes:
            raise ToolError(
                f"'body' exceeds max size ({self._max_body_bytes} bytes)",
                provider_id=self.id,
                code=ProviderErrorCode.VALIDATION,
            )
        subject = params.get("subject")
        if subject is not None and (not isinstance(subject, str)
                                    or len(subject) > _MAX_SUBJECT_LEN
                                    or "\r" in subject or "\n" in subject):
            raise ToolError("'subject' must be a safe string (<= 998 chars)", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)

        attachments = _attachments(params)
        if len(attachments) > self._max_attachments:
            raise ToolError(
                f"email.send allows at most {self._max_attachments} attachments",
                provider_id=self.id,
                code=ProviderErrorCode.VALIDATION,
            )
        if attachments and self._workspace is None:
            raise ToolError("attachments require a configured workspace", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)
        for attachment in attachments:
            rel_path = attachment.get("path")
            if not isinstance(rel_path, str) or not rel_path:
                raise ToolError("every attachment requires a workspace-relative 'path'", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            resolved = self._workspace.resolve(rel_path)  # type: ignore[union-attr]
            if not resolved.exists() or not resolved.is_file():
                raise ToolError("attachment was not found", provider_id=self.id,
                                code=ProviderErrorCode.NOT_FOUND)
            if resolved.stat().st_size > self._max_attachment_bytes:
                raise ToolError(
                    f"attachment exceeds max size ({self._max_attachment_bytes} bytes)",
                    provider_id=self.id,
                    code=ProviderErrorCode.VALIDATION,
                )

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        # Providers remain safe when invoked by an integration test/worker
        # directly; ExecutionService calls this same pure check before dispatch.
        self.validate(action)
        if not self._rate_limiter.allow(ctx.actor_id):
            raise ToolError("SMTP send rate limit exceeded for actor", provider_id=self.id,
                            code=ProviderErrorCode.FORBIDDEN)

        params = action.params or {}
        to_recipients = _addresses_for(params.get("to"))
        cc_recipients = _addresses_for(params.get("cc"))
        bcc_recipients = _addresses_for(params.get("bcc"))
        recipients = _dedupe(to_recipients + cc_recipients + bcc_recipients)
        if not recipients:
            raise ToolError("email.send requires recipients", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        subject = str(params.get("subject") or "")
        body = str(params.get("body") or "")

        username = self._resolve(self._username_ref, "SMTP username")
        password = self._resolve(self._password_ref, "SMTP password")
        if not password:
            raise ToolError("SMTP password not configured or not resolvable", provider_id=self.id,
                            code=ProviderErrorCode.AUTH)
        from_addr = self._from_address or username
        if not from_addr:
            raise ToolError("no sender address configured", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        _validate_address(from_addr)

        message = EmailMessage()
        message["From"] = from_addr
        message["To"] = ", ".join(to_recipients)
        if cc_recipients:
            message["Cc"] = ", ".join(cc_recipients)
        message["Subject"] = subject
        message.set_content(body)
        attachment_count = self._add_attachments(message, _attachments(params))
        raw = message.as_bytes()

        try:
            server = self._connect()
        except (OSError, TimeoutError, smtplib.SMTPException) as exc:
            raise ToolError("cannot connect to SMTP server", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc

        try:
            with server:
                if self._starttls and not self._use_ssl:
                    try:
                        server.starttls()
                    except (OSError, TimeoutError, smtplib.SMTPException) as exc:
                        raise ToolError("SMTP STARTTLS negotiation failed", provider_id=self.id,
                                        code=ProviderErrorCode.UNAVAILABLE) from exc
                if username:
                    try:
                        server.login(username, password)
                    except smtplib.SMTPAuthenticationError as exc:
                        raise ToolError("SMTP authentication failed", provider_id=self.id,
                                        code=ProviderErrorCode.AUTH) from exc
                try:
                    server.sendmail(from_addr, recipients, raw)
                except smtplib.SMTPServerDisconnected as exc:
                    raise ToolError("SMTP server disconnected during send", provider_id=self.id,
                                    code=ProviderErrorCode.UNAVAILABLE) from exc
                except (OSError, TimeoutError, smtplib.SMTPException) as exc:
                    raise ToolError("SMTP send failed", provider_id=self.id,
                                    code=ProviderErrorCode.UNAVAILABLE) from exc
        except TimeoutError as exc:
            raise ToolError("SMTP operation timed out", provider_id=self.id,
                            code=ProviderErrorCode.TIMEOUT) from exc

        # Do not include body, attachments, BCC, or credential-related data in
        # the result. ExecutionService persists only this generic summary.
        return ActionResult(
            success=True,
            summary=f"email sent to {len(recipients)} recipient(s)",
            data={"to": to_recipients, "recipient_count": len(recipients),
                  "attachments": attachment_count, "bytes": len(raw)},
        )

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.9.0",
            display_name=f"SMTP email ({self._host}:{self._port})",
            is_stub=False,
            capabilities=("email.send", "vault-secrets", "bounded-attachments"),
        )

    # -- internals -----------------------------------------------------------
    def _connect(self):
        if self._use_ssl:
            return smtplib.SMTP_SSL(self._host, self._port, timeout=self._timeout)
        return smtplib.SMTP(self._host, self._port, timeout=self._timeout)

    def _add_attachments(self, message: EmailMessage, attachments: list[dict[str, Any]]) -> int:
        count = 0
        for attachment in attachments:
            path = self._workspace.resolve(str(attachment["path"]))  # type: ignore[union-attr]
            try:
                payload = path.read_bytes()
            except OSError as exc:
                raise ToolError("attachment could not be read", provider_id=self.id,
                                code=ProviderErrorCode.PROVIDER_ERROR) from exc
            if len(payload) > self._max_attachment_bytes:
                raise ToolError("attachment exceeds configured size limit", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            supplied_mime = attachment.get("mime_type")
            mime = str(supplied_mime) if isinstance(supplied_mime, str) else (
                mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            )
            if "/" not in mime:
                mime = "application/octet-stream"
            maintype, subtype = mime.split("/", 1)
            filename = attachment.get("filename")
            filename = str(filename) if isinstance(filename, str) and filename else path.name
            if "\r" in filename or "\n" in filename or len(filename) > 255:
                raise ToolError("invalid attachment filename", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            message.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
            count += 1
        return count

    def _resolve(self, ref_or_plain: str, what: str) -> str:
        if not ref_or_plain:
            return ""
        if not is_vault_ref(ref_or_plain):
            return ref_or_plain
        if self._resolver is None:
            raise ToolError(f"{what} is a vault reference but no vault is wired", provider_id=self.id,
                            code=ProviderErrorCode.AUTH)
        try:
            return self._resolver.resolve_ref(ref_or_plain)
        except (VaultError, ValueError, TypeError) as exc:
            raise ToolError(f"{what} could not be resolved from the vault", provider_id=self.id,
                            code=ProviderErrorCode.AUTH) from exc


def _attachments(params: dict[str, Any]) -> list[dict[str, Any]]:
    value = params.get("attachments", [])
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ToolError("'attachments' must be an array of attachment objects", provider_id="email-smtp",
                        code=ProviderErrorCode.VALIDATION)
    return value


def _addresses_for(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_values = [value]
    elif isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        raw_values = list(value)
    else:
        raise ToolError("recipient fields must be strings or arrays of strings", provider_id="email-smtp",
                        code=ProviderErrorCode.VALIDATION)
    pairs = getaddresses(raw_values)
    addresses = [address.strip() for _name, address in pairs if address.strip()]
    return _dedupe(addresses)


def _collect_recipients(params: dict[str, Any]) -> list[str]:
    return _dedupe(
        _addresses_for(params.get("to"))
        + _addresses_for(params.get("cc"))
        + _addresses_for(params.get("bcc"))
    )


def _dedupe(addresses: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for address in addresses:
        key = address.casefold()
        if key not in seen:
            seen.add(key)
            result.append(address)
    return result


def _validate_address(address: str) -> None:
    if not isinstance(address, str) or not address or len(address) > _MAX_ADDRESS_LEN:
        raise ToolError("invalid email address", provider_id="email-smtp",
                        code=ProviderErrorCode.VALIDATION)
    if "\r" in address or "\n" in address:
        raise ToolError("invalid email address", provider_id="email-smtp",
                        code=ProviderErrorCode.VALIDATION)
    _display, parsed = parseaddr(address)
    if parsed != address or "@" not in parsed or parsed.startswith("@") or parsed.endswith("@"):
        raise ToolError("invalid email address", provider_id="email-smtp",
                        code=ProviderErrorCode.VALIDATION)
