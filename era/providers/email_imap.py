"""Read-only IMAP provider for ``email.read`` and ``email.search``.

The provider only issues ``LOGIN``, ``SELECT`` in read-only mode, ``SEARCH``,
and ``FETCH BODY.PEEK``.  It deliberately has no delete, move, store/flag, or
forwarding operation.  Message previews are capped and passed through the
central sensitive-text redactor before they can reach a response or agent
observation; audit entries receive only generic summaries from ExecutionService.
"""

from __future__ import annotations

import imaplib
import re
from email import policy
from email.parser import BytesParser
from typing import Any

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.registry.actions import ActionType
from era.security.result_safety import redact_sensitive_text
from era.security.vault import VaultError, is_vault_ref

DEFAULT_IMAP_PORT = 993
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_MESSAGES = 50
DEFAULT_MAX_PREVIEW_BYTES = 5_120
_MAILBOX_RE = re.compile(r"^[A-Za-z0-9._ -]{1,128}$")
_UID_RE = re.compile(r"^[0-9]{1,20}$")


class EmailImapProvider:
    """Bounded, read-only IMAP4-over-TLS mail reader."""

    id = "email-imap"
    action_types = frozenset({ActionType.EMAIL_READ.value, ActionType.EMAIL_SEARCH.value})

    def __init__(
        self,
        *,
        host: str,
        port: int = DEFAULT_IMAP_PORT,
        username: str = "",
        password: str = "",
        mailbox: str = "INBOX",
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        secret_resolver=None,
        max_messages: int = DEFAULT_MAX_MESSAGES,
        max_body_preview_bytes: int = DEFAULT_MAX_PREVIEW_BYTES,
    ):
        if not str(host or "").strip():
            raise ValueError("EmailImapProvider requires an IMAP host")
        self._host = str(host).strip()
        self._port = int(port)
        self._username_ref = str(username or "")
        self._password_ref = str(password or "")
        self._mailbox = str(mailbox or "INBOX").strip()
        self._timeout = max(0.1, float(timeout_seconds))
        self._resolver = secret_resolver
        self._max_messages = max(1, min(DEFAULT_MAX_MESSAGES, int(max_messages)))
        self._max_preview_bytes = max(1, min(DEFAULT_MAX_PREVIEW_BYTES, int(max_body_preview_bytes)))

    def validate(self, action: Action) -> None:
        if action.action_type not in self.action_types:
            raise ToolError(f"IMAP provider cannot handle {action.action_type}", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)
        params = action.params or {}
        mailbox = str(params.get("mailbox") or self._mailbox)
        if not _MAILBOX_RE.fullmatch(mailbox):
            raise ToolError("invalid IMAP mailbox", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        limit = params.get("limit", 20)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= self._max_messages:
            raise ToolError(
                f"'limit' must be an integer between 1 and {self._max_messages}",
                provider_id=self.id,
                code=ProviderErrorCode.VALIDATION,
            )
        if action.action_type == ActionType.EMAIL_READ.value:
            message_id = params.get("message_id")
            if message_id is not None and (not isinstance(message_id, str)
                                           or not _UID_RE.fullmatch(message_id)):
                raise ToolError("'message_id' must be a numeric IMAP UID", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
        else:
            query = params.get("query", params.get("q"))
            if not isinstance(query, str) or not query.strip() or len(query) > 500:
                raise ToolError("email.search requires a bounded non-empty 'query'", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if any(char in query for char in "\r\n\x00"):
                raise ToolError("IMAP search query contains unsafe characters", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        self.validate(action)
        username = self._resolve(self._username_ref, "IMAP username")
        password = self._resolve(self._password_ref, "IMAP password")
        if not username or not password:
            raise ToolError("IMAP credentials are not configured or not resolvable", provider_id=self.id,
                            code=ProviderErrorCode.AUTH)
        params = action.params or {}
        mailbox = str(params.get("mailbox") or self._mailbox)
        limit = int(params.get("limit", 20))

        client = self._connect()
        try:
            self._login_and_select(client, username, password, mailbox)
            if action.action_type == ActionType.EMAIL_SEARCH.value:
                query = str(params.get("query", params.get("q", ""))).strip()
                uids = self._search_uids(client, query)
            else:
                message_id = params.get("message_id")
                uids = [str(message_id)] if message_id else self._all_uids(client)
            uids = list(reversed(uids))[:limit]
            messages = [self._fetch_message(client, uid) for uid in uids]
        finally:
            try:
                client.logout()
            except Exception:  # noqa: BLE001,S110 -- logout is best effort only
                pass

        label = "search returned" if action.action_type == ActionType.EMAIL_SEARCH.value else "retrieved"
        return ActionResult(
            success=True,
            summary=f"IMAP {label} {len(messages)} message(s)",
            data={"messages": messages, "count": len(messages), "mailbox": mailbox},
        )

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.9.0",
            display_name=f"IMAP email (read-only, {self._host}:{self._port})",
            is_stub=False,
            capabilities=("email.read", "email.search", "imap-tls", "read-only", "bounded-preview"),
        )

    # -- IMAP transport ------------------------------------------------------
    def _connect(self):
        try:
            return imaplib.IMAP4_SSL(self._host, self._port, timeout=self._timeout)
        except TimeoutError as exc:
            raise ToolError("IMAP connection timed out", provider_id=self.id,
                            code=ProviderErrorCode.TIMEOUT) from exc
        except (OSError, imaplib.IMAP4.error) as exc:
            raise ToolError("IMAP server unavailable", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc

    def _login_and_select(self, client, username: str, password: str, mailbox: str) -> None:
        try:
            status, _data = client.login(username, password)
            if _status(status) != "OK":
                raise ToolError("IMAP authentication failed", provider_id=self.id,
                                code=ProviderErrorCode.AUTH)
            status, _data = client.select(mailbox, readonly=True)
            if _status(status) != "OK":
                raise ToolError("IMAP mailbox was not found or cannot be opened", provider_id=self.id,
                                code=ProviderErrorCode.NOT_FOUND)
        except ToolError:
            raise
        except imaplib.IMAP4.error as exc:
            message = str(exc).lower()
            code = ProviderErrorCode.AUTH if any(word in message for word in ("auth", "login", "credential")) else ProviderErrorCode.PROVIDER_ERROR
            raise ToolError("IMAP authentication/select failed", provider_id=self.id, code=code) from exc
        except TimeoutError as exc:
            raise ToolError("IMAP operation timed out", provider_id=self.id,
                            code=ProviderErrorCode.TIMEOUT) from exc
        except OSError as exc:
            raise ToolError("IMAP server unavailable", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc

    def _all_uids(self, client) -> list[str]:
        return self._uids_from_response(client.uid("search", None, "ALL"))

    def _search_uids(self, client, query: str) -> list[str]:
        # One quoted TEXT criterion is intentionally used instead of exposing
        # arbitrary IMAP SEARCH grammar. This eliminates command injection and
        # keeps the operation strictly read-only.
        escaped = query.replace("\\", "\\\\").replace('"', '\\"')
        return self._uids_from_response(client.uid("search", None, "TEXT", f'"{escaped}"'))

    def _uids_from_response(self, response: Any) -> list[str]:
        try:
            status, data = response
        except (TypeError, ValueError) as exc:
            raise ToolError("IMAP search returned an invalid response", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR) from exc
        if _status(status) != "OK":
            raise ToolError("IMAP search failed", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR)
        values: list[str] = []
        for item in data or []:
            raw = item.decode("ascii", "ignore") if isinstance(item, bytes) else str(item)
            values.extend(uid for uid in raw.split() if _UID_RE.fullmatch(uid))
        return values

    def _fetch_message(self, client, uid: str) -> dict[str, str]:
        try:
            status, data = client.uid(
                "fetch",
                uid,
                f"(BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)] BODY.PEEK[TEXT]<0.{self._max_preview_bytes}>)",
            )
        except TimeoutError as exc:
            raise ToolError("IMAP fetch timed out", provider_id=self.id,
                            code=ProviderErrorCode.TIMEOUT) from exc
        except (OSError, imaplib.IMAP4.error) as exc:
            raise ToolError("IMAP fetch failed", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc
        if _status(status) != "OK":
            raise ToolError("IMAP message was not found", provider_id=self.id,
                            code=ProviderErrorCode.NOT_FOUND)
        raw = _extract_fetch_bytes(data)
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        preview = _body_preview(parsed, self._max_preview_bytes)
        return {
            "message_id": uid,
            "from": redact_sensitive_text(str(parsed.get("From", "")))[:500],
            "to": redact_sensitive_text(str(parsed.get("To", "")))[:500],
            "subject": redact_sensitive_text(str(parsed.get("Subject", "")))[:500],
            "date": str(parsed.get("Date", ""))[:200],
            "body_preview": preview,
        }

    def _resolve(self, ref_or_plain: str, label: str) -> str:
        if not ref_or_plain:
            return ""
        if not is_vault_ref(ref_or_plain):
            return ref_or_plain
        if self._resolver is None:
            raise ToolError(f"{label} is a vault reference but no resolver is attached", provider_id=self.id,
                            code=ProviderErrorCode.AUTH)
        try:
            return self._resolver.resolve_ref(ref_or_plain, actor_id="email-imap-provider")
        except (VaultError, ValueError, TypeError) as exc:
            raise ToolError(f"{label} could not be resolved from the vault", provider_id=self.id,
                            code=ProviderErrorCode.AUTH) from exc


def _status(value: Any) -> str:
    return value.decode("ascii", "ignore").upper() if isinstance(value, bytes) else str(value).upper()


def _extract_fetch_bytes(data: Any) -> bytes:
    chunks: list[bytes] = []
    for item in data or []:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
            chunks.append(item[1])
        elif isinstance(item, bytes) and b":" in item:
            # Some minimal IMAP test servers return a raw RFC822 fragment.
            chunks.append(item)
    if not chunks:
        raise ToolError("IMAP fetch returned no message data", provider_id="email-imap",
                        code=ProviderErrorCode.NOT_FOUND)
    return b"\r\n".join(chunks)


def _body_preview(message, max_bytes: int) -> str:
    payload: bytes | str | None = None
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "text" and part.get_content_disposition() != "attachment":
                payload = part.get_payload(decode=True) or ""
                break
    else:
        payload = message.get_payload(decode=True)
        if payload is None:
            payload = message.get_payload()
    if isinstance(payload, bytes):
        text = payload[:max_bytes].decode("utf-8", errors="replace")
    else:
        text = str(payload or "")[:max_bytes]
    return redact_sensitive_text(re.sub(r"\s+", " ", text).strip())[:max_bytes]
