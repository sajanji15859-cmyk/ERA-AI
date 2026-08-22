"""Meta WhatsApp Cloud API provider with bounded, webhook-aware operations.

All three catalogued WhatsApp actions are communication/sensitive actions and
therefore remain permission/confirmation controlled by the execution service.
This provider supplies only the vendor boundary: token resolution, bounded Meta
payloads, local delivery/inbound tracking, and stable error mapping.
"""

from __future__ import annotations

import hmac
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from typing import Any

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.providers._rate_limit import ActorRateLimiter
from era.registry.actions import ActionType
from era.security.result_safety import redact_sensitive_text
from era.security.vault import VaultError, is_vault_ref

DEFAULT_API_URL = "https://graph.facebook.com/v20.0"
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_MESSAGE_CHARS = 1_000
DEFAULT_MAX_MEDIA = 5
DEFAULT_MAX_RECIPIENTS = 10
DEFAULT_MAX_READ = 50
DEFAULT_LOOKBACK_HOURS = 24
_PHONE_RE = re.compile(r"^[1-9]\d{6,15}$")
_SUPPORTED_MEDIA_TYPES = frozenset({"image", "document", "audio", "video", "sticker"})

_ACTION_TYPES = frozenset({
    ActionType.WHATSAPP_SEND.value,
    ActionType.WHATSAPP_READ.value,
    ActionType.WHATSAPP_REACT.value,
})


class WhatsAppProvider:
    """Real Meta Cloud API provider with opt-in webhook state tracking."""

    id = "whatsapp"
    action_types = _ACTION_TYPES

    def __init__(
        self,
        *,
        phone_number_id: str = "",
        access_token: str = "",
        api_url: str = DEFAULT_API_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        secret_resolver=None,
        webhook_verify_token: str = "",
        webhook_app_secret: str = "",
        max_messages_per_hour: int = 100,
        max_message_chars: int = DEFAULT_MAX_MESSAGE_CHARS,
        max_media_attachments: int = DEFAULT_MAX_MEDIA,
        max_recipients_per_call: int = DEFAULT_MAX_RECIPIENTS,
        max_read_messages: int = DEFAULT_MAX_READ,
        max_lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
        enforce_customer_window: bool = False,
    ):
        self._phone_number_id = str(phone_number_id or "").strip()
        self._access_token_ref = str(access_token or "").strip()
        self._api_url = str(api_url or DEFAULT_API_URL).rstrip("/")
        self._timeout = max(0.1, float(timeout_seconds))
        self._resolver = secret_resolver
        self._webhook_verify_token_ref = str(webhook_verify_token or "").strip()
        self._webhook_app_secret_ref = str(webhook_app_secret or "").strip()
        self._max_message_chars = max(1, int(max_message_chars))
        self._max_media = max(0, int(max_media_attachments))
        self._max_recipients = max(1, int(max_recipients_per_call))
        self._max_read = max(1, min(DEFAULT_MAX_READ, int(max_read_messages)))
        self._max_lookback_hours = max(1, min(DEFAULT_LOOKBACK_HOURS, int(max_lookback_hours)))
        self._enforce_customer_window = bool(enforce_customer_window)
        self._send_limiter = ActorRateLimiter(limit=max_messages_per_hour, window_seconds=3600.0)
        self._inbound: deque[dict[str, Any]] = deque(maxlen=500)
        self._last_inbound_at: dict[str, float] = {}
        self._delivery_status: dict[str, str] = {}

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.9.0",
            display_name="WhatsApp (Meta Cloud API)",
            is_stub=False,
            capabilities=("send", "read", "react", "webhook-state", "bounded"),
        )

    # -- SPI -----------------------------------------------------------------
    def validate(self, action: Action) -> None:
        action_type = action.action_type
        params = action.params or {}
        if action_type not in self.action_types:
            raise ToolError(f"unsupported action {action_type!r}", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)

        if action_type == ActionType.WHATSAPP_SEND.value:
            recipients = _recipients(params.get("to"))
            if not recipients:
                raise ToolError("whatsapp.send requires 'to' recipient number", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if len(recipients) > self._max_recipients:
                raise ToolError(
                    f"whatsapp.send allows at most {self._max_recipients} recipients",
                    provider_id=self.id,
                    code=ProviderErrorCode.VALIDATION,
                )
            message = params.get("message", params.get("text"))
            template = params.get("template")
            media = _media(params.get("media"))
            if not message and not template and not media:
                raise ToolError("whatsapp.send requires 'message', 'template', or 'media'", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if message is not None and (not isinstance(message, str)
                                        or len(message) > self._max_message_chars):
                raise ToolError(
                    f"'message' exceeds max length ({self._max_message_chars} chars)",
                    provider_id=self.id,
                    code=ProviderErrorCode.VALIDATION,
                )
            if template is not None and (not isinstance(template, str) or not template.strip()
                                         or len(template) > 512):
                raise ToolError("invalid WhatsApp template name", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if len(media) > self._max_media:
                raise ToolError(f"whatsapp.send allows at most {self._max_media} media attachments",
                                provider_id=self.id, code=ProviderErrorCode.VALIDATION)
            for item in media:
                media_type = str(item.get("type", "")).lower()
                if media_type not in _SUPPORTED_MEDIA_TYPES:
                    raise ToolError("unsupported WhatsApp media type", provider_id=self.id,
                                    code=ProviderErrorCode.VALIDATION)
                if not isinstance(item.get("id") or item.get("link"), str):
                    raise ToolError("media item requires Meta media 'id' or HTTPS 'link'", provider_id=self.id,
                                    code=ProviderErrorCode.VALIDATION)

        elif action_type == ActionType.WHATSAPP_REACT.value:
            msg_id = str(params.get("message_id", "")).strip()
            emoji = str(params.get("emoji", "")).strip()
            if not msg_id or len(msg_id) > 512:
                raise ToolError("whatsapp.react requires a valid 'message_id'", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if not emoji or len(emoji) > 32:
                raise ToolError("whatsapp.react requires a bounded 'emoji'", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            recipients = _recipients(params.get("to"))
            if len(recipients) != 1:
                raise ToolError("whatsapp.react requires exactly one 'to' recipient", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)

        elif action_type == ActionType.WHATSAPP_READ.value:
            limit = params.get("limit", 20)
            lookback = params.get("lookback_hours", self._max_lookback_hours)
            if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= self._max_read:
                raise ToolError(f"'limit' must be an integer between 1 and {self._max_read}", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if not isinstance(lookback, int) or isinstance(lookback, bool) or not 1 <= lookback <= self._max_lookback_hours:
                raise ToolError(
                    f"'lookback_hours' must be an integer between 1 and {self._max_lookback_hours}",
                    provider_id=self.id,
                    code=ProviderErrorCode.VALIDATION,
                )

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        self.validate(action)
        token = self._resolve(self._access_token_ref, "WhatsApp access token")
        if not token or not self._phone_number_id:
            # Runtime wiring normally avoids this condition and leaves Stub in
            # place. Direct construction fails closed with the taxonomy's
            # configuration signal rather than pretending authentication failed.
            raise ToolError("WhatsApp provider is not configured", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)

        action_type = action.action_type
        params = action.params or {}
        if action_type == ActionType.WHATSAPP_SEND.value:
            recipients = _recipients(params.get("to"))
            media = _media(params.get("media"))
            outbound_count = len(recipients) * max(1, len(media) + (1 if params.get("message", params.get("text")) else 0))
            if not self._send_limiter.allow_many(ctx.actor_id, count=outbound_count):
                raise ToolError("WhatsApp send rate limit exceeded for actor", provider_id=self.id,
                                code=ProviderErrorCode.FORBIDDEN)
            return self._send_message(params, token)
        if action_type == ActionType.WHATSAPP_REACT.value:
            if not self._send_limiter.allow(ctx.actor_id):
                raise ToolError("WhatsApp send rate limit exceeded for actor", provider_id=self.id,
                                code=ProviderErrorCode.FORBIDDEN)
            return self._send_reaction(params, token)
        if action_type == ActionType.WHATSAPP_READ.value:
            return self._read_messages(params, token)
        raise ToolError(f"unsupported action {action_type!r}", provider_id=self.id,
                        code=ProviderErrorCode.NOT_IMPLEMENTED)

    # -- Meta Cloud API actions ----------------------------------------------
    def _send_message(self, params: dict[str, Any], token: str) -> ActionResult:
        recipients = _recipients(params["to"])
        template = params.get("template")
        message = params.get("message", params.get("text"))
        media = _media(params.get("media"))
        if message and not template:
            self._require_customer_window(recipients)

        message_ids: list[str] = []
        for recipient in recipients:
            if template:
                payload = {
                    "messaging_product": "whatsapp",
                    "recipient_type": "individual",
                    "to": recipient,
                    "type": "template",
                    "template": {
                        "name": str(template),
                        "language": {"code": str(params.get("language_code", "en_US"))},
                        "components": params.get("template_params", []),
                    },
                }
                message_ids.extend(self._send_payload(payload, token))
            elif message:
                payload = {
                    "messaging_product": "whatsapp",
                    "recipient_type": "individual",
                    "to": recipient,
                    "type": "text",
                    "text": {"body": str(message)},
                }
                message_ids.extend(self._send_payload(payload, token))
            for attachment in media:
                media_type = str(attachment["type"]).lower()
                media_body: dict[str, Any] = {}
                if attachment.get("id"):
                    media_body["id"] = str(attachment["id"])
                else:
                    media_body["link"] = str(attachment["link"])
                if attachment.get("caption") and media_type in {"image", "document", "video"}:
                    media_body["caption"] = str(attachment["caption"])[:1024]
                payload = {
                    "messaging_product": "whatsapp",
                    "recipient_type": "individual",
                    "to": recipient,
                    "type": media_type,
                    media_type: media_body,
                }
                message_ids.extend(self._send_payload(payload, token))

        first = message_ids[0] if message_ids else "wamid.generated"
        for message_id in message_ids:
            self._delivery_status[message_id] = "sent"
        return ActionResult(
            success=True,
            summary=f"WhatsApp message sent to {len(recipients)} recipient(s)",
            data={"message_id": first, "message_ids": message_ids or [first],
                  "recipient_count": len(recipients), "status": "sent",
                  "mode": "template" if template else "freeform"},
        )

    def _send_payload(self, payload: dict[str, Any], token: str) -> list[str]:
        url = f"{self._api_url}/{self._phone_number_id}/messages"
        response = self._http_call("POST", url, payload, token)
        messages = response.get("messages", []) if isinstance(response, dict) else []
        values = [str(item.get("id")) for item in messages if isinstance(item, dict) and item.get("id")]
        return values or ["wamid.generated"]

    def _send_reaction(self, params: dict[str, Any], token: str) -> ActionResult:
        recipient = _recipients(params.get("to"))[0]
        message_id = str(params["message_id"]).strip()
        emoji = str(params["emoji"]).strip()
        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": recipient,
            "type": "reaction",
            "reaction": {"message_id": message_id, "emoji": emoji},
        }
        self._send_payload(payload, token)
        return ActionResult(
            success=True,
            summary="WhatsApp reaction sent",
            data={"message_id": message_id, "emoji": emoji, "status": "reacted"},
        )

    def _read_messages(self, params: dict[str, Any], token: str) -> ActionResult:
        limit = int(params.get("limit", 20))
        lookback_hours = int(params.get("lookback_hours", self._max_lookback_hours))
        sender = str(params.get("sender", "")).replace("+", "").strip()
        cutoff = time.time() - lookback_hours * 3600
        local = [
            _safe_message(item) for item in reversed(self._inbound)
            if float(item.get("received_at", 0)) >= cutoff
            and (not sender or str(item.get("from", "")) == sender)
        ][:limit]
        if local:
            return ActionResult(success=True, summary=f"Retrieved {len(local)} WhatsApp messages",
                                data={"messages": local, "count": len(local), "source": "webhook"})

        # Meta's inbound-message history is ordinarily delivered by webhook;
        # retain a bounded Graph API fallback for compatible partner gateways.
        url = f"{self._api_url}/{self._phone_number_id}?{urllib.parse.urlencode({'fields': f'messages.limit({limit})'})}"
        response = self._http_call("GET", url, None, token)
        raw_messages = response.get("messages", {}).get("data", []) if isinstance(response, dict) else []
        messages = [_safe_message(item) for item in raw_messages if isinstance(item, dict)][:limit]
        return ActionResult(success=True, summary=f"Retrieved {len(messages)} WhatsApp messages",
                            data={"messages": messages, "count": len(messages), "source": "api"})

    # -- webhook state -------------------------------------------------------
    def verify_webhook_token(self, candidate: str | None) -> bool:
        """Constant-time verification for a Meta webhook challenge request."""

        expected = self._resolve(self._webhook_verify_token_ref, "WhatsApp webhook verify token")
        return bool(expected and candidate and hmac.compare_digest(expected, str(candidate)))

    def verify_webhook_signature(self, raw_body: bytes, signature: str | None) -> bool:
        """Verify Meta's POST HMAC before accepting inbound/customer-window state."""
        secret = self._resolve(self._webhook_app_secret_ref, "WhatsApp webhook app secret")
        if not secret or not signature or not signature.startswith("sha256="):
            return False
        digest = hmac.new(secret.encode("utf-8"), raw_body, "sha256").hexdigest()
        return hmac.compare_digest(f"sha256={digest}", signature)

    def ingest_webhook(self, payload: dict[str, Any]) -> int:
        """Store bounded inbound/status records from a verified Meta webhook.

        Callers must call :meth:`verify_webhook_token` during Meta's verification
        handshake. This method intentionally does not execute any action or
        make an outbound request.
        """

        if not isinstance(payload, dict):
            raise ToolError("invalid WhatsApp webhook payload", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        count = 0
        for entry in payload.get("entry", []) if isinstance(payload.get("entry", []), list) else []:
            for change in entry.get("changes", []) if isinstance(entry, dict) else []:
                value = change.get("value", {}) if isinstance(change, dict) else {}
                for message in value.get("messages", []) if isinstance(value, dict) else []:
                    if not isinstance(message, dict):
                        continue
                    sender = str(message.get("from", "")).replace("+", "")
                    received_at = _meta_timestamp(message.get("timestamp"))
                    text = ""
                    text_data = message.get("text")
                    if isinstance(text_data, dict):
                        text = str(text_data.get("body", ""))
                    self._inbound.append({
                        "id": str(message.get("id", "")),
                        "from": sender,
                        "received_at": received_at,
                        "text": text,
                        "type": str(message.get("type", "")),
                    })
                    if sender:
                        self._last_inbound_at[sender] = received_at
                    count += 1
                for status in value.get("statuses", []) if isinstance(value, dict) else []:
                    if isinstance(status, dict) and status.get("id"):
                        self._delivery_status[str(status["id"])] = str(status.get("status", "sent"))
        return count

    # -- transport / credentials --------------------------------------------
    def _http_call(self, method: str, url: str, body: dict | None, token: str) -> dict:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "ERA-Agent/0.9.0",
        }
        encoded = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=encoded, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = response.read(1_048_577)
                if len(raw) > 1_048_576:
                    raise ToolError("WhatsApp API response exceeded size cap", provider_id=self.id,
                                    code=ProviderErrorCode.PROVIDER_ERROR)
                return json.loads(raw.decode("utf-8")) if raw else {}
        except ToolError:
            raise
        except urllib.error.HTTPError as exc:
            self._map_http_error(exc)
        except TimeoutError as exc:
            raise ToolError("WhatsApp API timed out", provider_id=self.id,
                            code=ProviderErrorCode.TIMEOUT) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ToolError("WhatsApp API network unavailable", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc

    def _map_http_error(self, exc: urllib.error.HTTPError) -> None:
        status_code = int(exc.code)
        try:
            body_text = exc.read().decode("utf-8", errors="replace")
            err_doc = json.loads(body_text)
            err_msg = str(err_doc.get("error", {}).get("message", "provider error"))
        except Exception:  # noqa: BLE001 -- vendor error bodies are untrusted
            err_msg = "provider error"
        if status_code in (401, 403):
            raise ToolError(f"WhatsApp authentication failed ({status_code})", provider_id=self.id,
                            code=ProviderErrorCode.AUTH) from exc
        if status_code == 404:
            raise ToolError("WhatsApp resource not found", provider_id=self.id,
                            code=ProviderErrorCode.NOT_FOUND) from exc
        if status_code in (400, 422):
            raise ToolError(f"WhatsApp parameter error ({status_code}): {redact_sensitive_text(err_msg)}",
                            provider_id=self.id, code=ProviderErrorCode.VALIDATION) from exc
        if status_code == 409:
            raise ToolError("WhatsApp request conflict", provider_id=self.id,
                            code=ProviderErrorCode.CONFLICT) from exc
        if status_code == 429 or status_code >= 500:
            raise ToolError("WhatsApp API temporarily unavailable", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc
        raise ToolError(f"WhatsApp provider error ({status_code})", provider_id=self.id,
                        code=ProviderErrorCode.PROVIDER_ERROR) from exc

    def _resolve(self, ref: str, label: str) -> str:
        if not ref:
            return ""
        if not is_vault_ref(ref):
            return ref
        if self._resolver is None:
            raise ToolError(f"{label} uses a vault reference but no resolver is attached", provider_id=self.id,
                            code=ProviderErrorCode.AUTH)
        try:
            return self._resolver.resolve_ref(ref, actor_id="whatsapp-provider")
        except (VaultError, ValueError, TypeError) as exc:
            raise ToolError(f"cannot resolve {label} from vault", provider_id=self.id,
                            code=ProviderErrorCode.AUTH) from exc

    def _require_customer_window(self, recipients: list[str]) -> None:
        if not self._enforce_customer_window:
            return
        cutoff = time.time() - DEFAULT_LOOKBACK_HOURS * 3600
        if any(self._last_inbound_at.get(recipient, 0.0) < cutoff for recipient in recipients):
            raise ToolError(
                "free-form WhatsApp messages require a verified inbound message within 24 hours; use a template",
                provider_id=self.id,
                code=ProviderErrorCode.CONFLICT,
            )


def _recipients(value: Any) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        values = list(value)
    elif value is None:
        return []
    else:
        raise ToolError("'to' must be a phone number or an array of phone numbers", provider_id="whatsapp",
                        code=ProviderErrorCode.VALIDATION)
    result: list[str] = []
    for raw in values:
        cleaned = re.sub(r"[\s\-()+]", "", raw)
        if not _PHONE_RE.fullmatch(cleaned):
            raise ToolError("invalid recipient phone number", provider_id="whatsapp",
                            code=ProviderErrorCode.VALIDATION)
        if cleaned not in result:
            result.append(cleaned)
    return result


def _media(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ToolError("'media' must be an array of objects", provider_id="whatsapp",
                        code=ProviderErrorCode.VALIDATION)
    return value


def _safe_message(message: dict[str, Any]) -> dict[str, Any]:
    text_data = message.get("text", "")
    if isinstance(text_data, dict):
        text = str(text_data.get("body", ""))
    else:
        text = str(text_data or message.get("body", ""))
    return {
        "id": str(message.get("id", ""))[:512],
        "from": str(message.get("from", ""))[:64],
        "type": str(message.get("type", "text"))[:32],
        "text_preview": redact_sensitive_text(text)[:1_000],
        "status": str(message.get("status", "received"))[:32],
    }


def _meta_timestamp(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return time.time()
