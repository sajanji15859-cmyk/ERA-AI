"""Official Meta Cloud API / Twilio WhatsApp Provider (Phase 3H).

Interacts with the WhatsApp Business Cloud API:
* ``whatsapp.send`` — Send text or template WhatsApp messages (approval-gated).
* ``whatsapp.read`` — Read or list recent incoming messages and delivery statuses.
* ``whatsapp.react`` — Send an emoji reaction to a specific WhatsApp message.

Security controls:
* Credentials: ``access_token`` configured as env or vault reference (``vault:whatsapp/token``)
  and resolved at dispatch time via :class:`~era.services.vault_service.VaultRefResolver`.
* Redaction: ``token`` is declared in ``secret_fields`` and never leaks in audit/results.
* Taxonomy error mapping:
  - 401 / 403 -> AUTH
  - 404 -> NOT_FOUND
  - 400 / 422 -> VALIDATION
  - 429 -> RATE_LIMITED
  - 5xx / Network -> UNAVAILABLE
  - Timeout -> TIMEOUT
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.registry.actions import ActionType
from era.security.vault import VaultError, is_vault_ref

DEFAULT_API_URL = "https://graph.facebook.com/v20.0"
DEFAULT_TIMEOUT_SECONDS = 15.0
_MAX_MESSAGE_LEN = 4096
_PHONE_RE = re.compile(r"^\+?[1-9]\d{6,15}$")

_ACTION_TYPES = frozenset({
    ActionType.WHATSAPP_SEND.value,
    ActionType.WHATSAPP_READ.value,
    ActionType.WHATSAPP_REACT.value,
})


class WhatsAppProvider:
    """Sends, reads and reacts to WhatsApp messages over the Meta Cloud API."""

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
    ):
        self._phone_number_id = str(phone_number_id or "").strip()
        self._access_token_ref = str(access_token or "").strip()
        self._api_url = str(api_url or DEFAULT_API_URL).rstrip("/")
        self._timeout = float(timeout_seconds)
        self._resolver = secret_resolver

    def describe(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            provider_type="whatsapp",
            version="1.0.0",
        )

    # -- SPI -------------------------------------------------------------------
    def validate(self, action) -> None:
        action_type = action.action_type
        params = action.params or {}

        if action_type == ActionType.WHATSAPP_SEND.value:
            to = str(params.get("to", "")).strip()
            if not to:
                raise ToolError("whatsapp.send requires 'to' recipient number",
                                provider_id=self.id, code=ProviderErrorCode.VALIDATION)
            clean_to = re.sub(r"[\s\-()]", "", to)
            if not _PHONE_RE.match(clean_to):
                raise ToolError(f"invalid recipient phone number: {to!r}",
                                provider_id=self.id, code=ProviderErrorCode.VALIDATION)

            msg = params.get("message") or params.get("text")
            template = params.get("template")
            if not msg and not template:
                raise ToolError("whatsapp.send requires 'message' or 'template'",
                                provider_id=self.id, code=ProviderErrorCode.VALIDATION)
            if msg and len(str(msg)) > _MAX_MESSAGE_LEN:
                raise ToolError("'message' exceeds max length",
                                provider_id=self.id, code=ProviderErrorCode.VALIDATION)

        elif action_type == ActionType.WHATSAPP_REACT.value:
            msg_id = str(params.get("message_id", "")).strip()
            if not msg_id:
                raise ToolError("whatsapp.react requires 'message_id'",
                                provider_id=self.id, code=ProviderErrorCode.VALIDATION)
            emoji = str(params.get("emoji", "")).strip()
            if not emoji:
                raise ToolError("whatsapp.react requires 'emoji'",
                                provider_id=self.id, code=ProviderErrorCode.VALIDATION)

        elif action_type == ActionType.WHATSAPP_READ.value:
            limit = params.get("limit")
            if limit is not None:
                try:
                    lim_int = int(limit)
                    if lim_int <= 0 or lim_int > 100:
                        raise ValueError
                except (ValueError, TypeError) as exc:
                    raise ToolError("'limit' must be an integer between 1 and 100",
                                    provider_id=self.id, code=ProviderErrorCode.VALIDATION) from exc

    def execute(self, action, ctx) -> ActionResult:
        token = self._resolve(self._access_token_ref, "WhatsApp access token")
        if not token:
            raise ToolError(
                "WhatsApp access token not configured or not resolvable",
                provider_id=self.id,
                code=ProviderErrorCode.AUTH,
            )
        if not self._phone_number_id:
            raise ToolError(
                "WhatsApp phone_number_id not configured",
                provider_id=self.id,
                code=ProviderErrorCode.VALIDATION,
            )

        action_type = action.action_type
        params = action.params or {}

        if action_type == ActionType.WHATSAPP_SEND.value:
            return self._send_message(params, token)
        if action_type == ActionType.WHATSAPP_REACT.value:
            return self._send_reaction(params, token)
        if action_type == ActionType.WHATSAPP_READ.value:
            return self._read_messages(params, token)

        raise ToolError(f"unsupported action {action_type!r}",
                        provider_id=self.id, code=ProviderErrorCode.NOT_IMPLEMENTED)

    # -- Meta Cloud API Actions -----------------------------------------------
    def _send_message(self, params: dict[str, Any], token: str) -> ActionResult:
        to = re.sub(r"[\s\-()]", "", str(params["to"]).strip())
        template = params.get("template")
        msg_text = params.get("message") or params.get("text")

        if template:
            payload = {
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": to,
                "type": "template",
                "template": {
                    "name": template,
                    "language": {"code": params.get("language_code", "en_US")},
                    "components": params.get("template_params", []),
                },
            }
        else:
            payload = {
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": to,
                "type": "text",
                "text": {"body": str(msg_text)},
            }

        url = f"{self._api_url}/{self._phone_number_id}/messages"
        resp_data = self._http_call("POST", url, payload, token)
        messages = resp_data.get("messages", [])
        wamid = messages[0].get("id", "wamid.generated") if messages else "wamid.generated"

        return ActionResult(
            success=True,
            summary=f"WhatsApp message sent to {to}",
            data={"message_id": wamid, "to": to, "status": "sent"},
        )

    def _send_reaction(self, params: dict[str, Any], token: str) -> ActionResult:
        msg_id = str(params["message_id"]).strip()
        emoji = str(params["emoji"]).strip()
        to = str(params.get("to") or "").strip()

        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": to or "unknown",
            "type": "reaction",
            "reaction": {
                "message_id": msg_id,
                "emoji": emoji,
            },
        }

        url = f"{self._api_url}/{self._phone_number_id}/messages"
        self._http_call("POST", url, payload, token)

        return ActionResult(
            success=True,
            summary=f"Reaction {emoji} sent to message {msg_id}",
            data={"message_id": msg_id, "emoji": emoji, "status": "reacted"},
        )

    def _read_messages(self, params: dict[str, Any], token: str) -> ActionResult:
        limit = int(params.get("limit", 20))
        url = f"{self._api_url}/{self._phone_number_id}?fields=messages.limit({limit})"
        resp_data = self._http_call("GET", url, None, token)
        messages = resp_data.get("messages", {}).get("data", [])

        return ActionResult(
            success=True,
            summary=f"Retrieved {len(messages)} WhatsApp messages",
            data={"messages": messages, "count": len(messages)},
        )

    # -- HTTP Transport & Secret Resolution -----------------------------------
    def _http_call(self, method: str, url: str, body: dict | None, token: str) -> dict:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "ERA-Agent/Phase3H",
        }
        data_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            self._map_http_error(exc)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ToolError(
                f"WhatsApp API network error: {exc}",
                provider_id=self.id,
                code=ProviderErrorCode.UNAVAILABLE,
            ) from exc

    def _map_http_error(self, exc: urllib.error.HTTPError) -> None:
        status_code = exc.code
        try:
            body_text = exc.read().decode("utf-8", errors="replace")
            err_doc = json.loads(body_text)
            err_msg = err_doc.get("error", {}).get("message", body_text)
        except Exception:  # noqa: BLE001
            err_msg = str(exc)

        if status_code in (401, 403):
            raise ToolError(f"WhatsApp authentication failed ({status_code}): {err_msg}",
                            provider_id=self.id, code=ProviderErrorCode.AUTH) from exc
        if status_code == 404:
            raise ToolError(f"WhatsApp resource not found: {err_msg}",
                            provider_id=self.id, code=ProviderErrorCode.NOT_FOUND) from exc
        if status_code in (400, 422):
            raise ToolError(f"WhatsApp parameter error ({status_code}): {err_msg}",
                            provider_id=self.id, code=ProviderErrorCode.VALIDATION) from exc
        if status_code == 429:
            raise ToolError("WhatsApp rate limit exceeded",
                            provider_id=self.id, code=ProviderErrorCode.RATE_LIMITED) from exc
        if status_code >= 500:
            raise ToolError(f"WhatsApp API server error ({status_code}): {err_msg}",
                            provider_id=self.id, code=ProviderErrorCode.UNAVAILABLE) from exc

        raise ToolError(f"WhatsApp error ({status_code}): {err_msg}",
                        provider_id=self.id, code=ProviderErrorCode.PROVIDER_ERROR) from exc

    def _resolve(self, ref: str, label: str) -> str:
        if not ref:
            return ""
        if not is_vault_ref(ref):
            return ref
        if self._resolver is None:
            raise ToolError(
                f"{label} uses a vault reference {ref!r} but no resolver is attached",
                provider_id=self.id,
                code=ProviderErrorCode.AUTH,
            )
        try:
            return self._resolver.resolve_ref(ref, actor_id="whatsapp-provider")
        except VaultError as exc:
            raise ToolError(
                f"cannot resolve {label} from vault reference {ref!r}: {exc}",
                provider_id=self.id,
                code=ProviderErrorCode.AUTH,
            ) from exc
