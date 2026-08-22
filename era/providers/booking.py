"""Official travel-partner booking provider with strong side-effect handling.

A configured instance talks only to an operator-supplied partner API.  Search
is read-only; holds and booking mutations carry idempotency keys; confirmation
and cancellation are explicitly non-retryable and surface
``SIDE_EFFECT_UNKNOWN`` when a downstream failure happens after dispatch may
have begun.  The catalog / ExecutionService supply the separate BOOKING
CONFIRM_STRONG + dual-approval gate.

For backwards-compatible offline unit tests, an entirely unconfigured direct
``BookingProvider()`` exposes a deterministic in-memory simulator.  Runtime
wiring never registers that simulator: when partner configuration is absent it
leaves the booking actions to ``StubProvider`` instead.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.provider_info import ProviderInfo
from era.core.result import ActionResult, ProviderErrorCode, ToolError
from era.registry.actions import ActionType
from era.security.hashing import canonical_json
from era.security.vault import VaultError, is_vault_ref

_ACTION_TYPES = frozenset({
    ActionType.BOOKING_SEARCH.value,
    ActionType.BOOKING_HOLD.value,
    ActionType.BOOKING_CONFIRM.value,
    ActionType.BOOKING_CANCEL.value,
})
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")


class BookingProvider:
    """Travel partner API adapter with local idempotency safety rails."""

    id = "booking"
    action_types = _ACTION_TYPES
    #: The execution reliability layer must never replay an irreversible call.
    non_retryable_action_types = frozenset({
        ActionType.BOOKING_CONFIRM.value,
        ActionType.BOOKING_CANCEL.value,
    })
    #: A timeout/network/provider error after dispatch leaves the partner state
    #: unknowable; ExecutionService converts these codes at its boundary too.
    ambiguous_on_failure_action_types = non_retryable_action_types

    def __init__(
        self,
        *,
        partner_api_key: str = "",
        partner_url: str = "",
        timeout_seconds: float = 15.0,
        secret_resolver=None,
        max_amount_minor: int = 10_000_000,
        hold_ttl_seconds: int = 86_400,
    ):
        self._partner_api_key_ref = str(partner_api_key or "").strip()
        self._partner_url = str(partner_url or "").strip().rstrip("/")
        self._timeout = max(0.1, float(timeout_seconds))
        self._resolver = secret_resolver
        self._max_amount_minor = max(1, int(max_amount_minor))
        self._hold_ttl_seconds = max(60, min(86_400, int(hold_ttl_seconds)))
        self._configured = bool(self._partner_api_key_ref and self._partner_url)
        self._simulator = not self._partner_api_key_ref and not self._partner_url
        self._drafts: dict[str, dict[str, Any]] = {}
        self._bookings: dict[str, dict[str, Any]] = {}
        self._idempotent_results: dict[tuple[str, str], ActionResult] = {}

    def describe(self) -> ProviderInfo:
        mode = "partner API" if self._configured else "offline simulator"
        return ProviderInfo(
            id=self.id,
            action_types=self.action_types,
            version="0.9.0",
            display_name=f"Travel booking ({mode})",
            is_stub=False,
            capabilities=("search", "hold", "confirm", "cancel", "idempotency", "minor-units"),
        )

    # -- SPI -----------------------------------------------------------------
    def validate(self, action: Action) -> None:
        action_type = action.action_type
        params = action.params or {}
        if action_type not in self.action_types:
            raise ToolError(f"unsupported action {action_type!r}", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)

        if action_type == ActionType.BOOKING_SEARCH.value:
            origin = str(params.get("origin", "")).strip()
            destination = str(params.get("destination", "")).strip()
            if not origin:
                raise ToolError("booking.search requires 'origin'", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            if not destination:
                raise ToolError("booking.search requires 'destination'", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            date_value = params.get("date") or params.get("departure_date")
            if date_value and not _DATE_RE.fullmatch(str(date_value).strip()):
                raise ToolError("travel date must be YYYY-MM-DD format", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)

        elif action_type == ActionType.BOOKING_HOLD.value:
            offer_ref = params.get("offer_ref") or params.get("trip_id") or params.get("service_number") or params.get("booking_id")
            if not isinstance(offer_ref, str) or not offer_ref.strip():
                raise ToolError("booking.hold requires 'offer_ref' or 'trip_id'", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            self._validate_amount_if_present(params, required=self._configured)

        elif action_type == ActionType.BOOKING_CONFIRM.value:
            hold_ref = params.get("hold_ref") or params.get("draft_id") or params.get("booking_id")
            if not isinstance(hold_ref, str) or not hold_ref.strip():
                raise ToolError("booking.confirm requires 'hold_ref' or 'draft_id'", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            self._validate_idempotency_key(params)

        elif action_type == ActionType.BOOKING_CANCEL.value:
            booking_ref = params.get("booking_ref") or params.get("booking_id")
            if not isinstance(booking_ref, str) or not booking_ref.strip():
                raise ToolError("booking.cancel requires 'booking_ref' or 'booking_id'", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            self._validate_idempotency_key(params)

    def execute(self, action: Action, ctx: ExecutionContext) -> ActionResult:
        self.validate(action)
        if not self._simulator and not self._configured:
            raise ToolError("booking partner configuration is incomplete", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)
        if self._simulator:
            return self._execute_simulated(action)

        api_key = self._resolve(self._partner_api_key_ref, "booking partner API key")
        if not api_key:
            raise ToolError("booking partner API key is not configured", provider_id=self.id,
                            code=ProviderErrorCode.NOT_IMPLEMENTED)
        action_type = action.action_type
        params = action.params or {}
        try:
            if action_type == ActionType.BOOKING_SEARCH.value:
                return self._remote_search(params, api_key)
            if action_type == ActionType.BOOKING_HOLD.value:
                return self._idempotent_remote(action_type, params, lambda key: self._remote_hold(params, api_key, key))
            if action_type == ActionType.BOOKING_CONFIRM.value:
                return self._idempotent_remote(action_type, params, lambda key: self._remote_confirm(params, api_key, key))
            if action_type == ActionType.BOOKING_CANCEL.value:
                return self._idempotent_remote(action_type, params, lambda key: self._remote_cancel(params, api_key, key))
        except ToolError as exc:
            if action_type in self.ambiguous_on_failure_action_types and exc.code in {
                ProviderErrorCode.UNAVAILABLE,
                ProviderErrorCode.TIMEOUT,
                ProviderErrorCode.PROVIDER_ERROR,
            }:
                raise ToolError(
                    "booking partner outcome is unknown; do not retry automatically",
                    provider_id=self.id,
                    code=ProviderErrorCode.SIDE_EFFECT_UNKNOWN,
                ) from exc
            raise
        raise ToolError(f"unsupported action {action_type!r}", provider_id=self.id,
                        code=ProviderErrorCode.NOT_IMPLEMENTED)

    # -- configured partner API ---------------------------------------------
    def _remote_search(self, params: dict[str, Any], api_key: str) -> ActionResult:
        payload = {
            "origin": str(params["origin"]).strip().upper(),
            "destination": str(params["destination"]).strip().upper(),
            "date": str(params.get("date") or params.get("departure_date") or ""),
            "mode": str(params.get("mode") or "flight"),
        }
        response = self._partner_call("POST", "/search", payload, api_key)
        raw_results = response.get("results", response.get("data", [])) if isinstance(response, dict) else []
        if not isinstance(raw_results, list):
            raise ToolError("booking partner returned invalid search results", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR)
        results = [_normalise_offer(item) for item in raw_results if isinstance(item, dict)][:20]
        return ActionResult(
            success=True,
            summary=f"booking search returned {len(results)} result(s)",
            data={"results": results, "count": len(results)},
        )

    def _remote_hold(self, params: dict[str, Any], api_key: str, idempotency_key: str) -> ActionResult:
        amount_minor, currency = self._amount(params)
        payload = {
            "offer_ref": str(params.get("offer_ref") or params.get("trip_id") or params.get("service_number") or params.get("booking_id")),
            "amount_minor": amount_minor,
            "currency": currency,
            "passengers": _passengers(params),
        }
        response = self._partner_call("POST", "/holds", payload, api_key, idempotency_key)
        hold_ref = _first(response, "hold_ref", "id", "booking_ref")
        if not hold_ref:
            raise ToolError("booking partner did not return a hold reference", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR)
        expires_at = str(response.get("expires_at") or _expiry(self._hold_ttl_seconds))
        return ActionResult(
            success=True,
            summary="booking hold created",
            data={"hold_ref": hold_ref, "status": "held", "expires_at": expires_at,
                  "amount_minor": amount_minor, "currency": currency},
        )

    def _remote_confirm(self, params: dict[str, Any], api_key: str, idempotency_key: str) -> ActionResult:
        hold_ref = str(params.get("hold_ref") or params.get("draft_id") or params.get("booking_id"))
        payload = {"hold_ref": hold_ref}
        if params.get("payment_ref"):
            payload["payment_ref"] = str(params["payment_ref"])
        response = self._partner_call("POST", "/confirm", payload, api_key, idempotency_key)
        booking_ref = _first(response, "booking_ref", "booking_id", "reference", "id")
        if not booking_ref:
            raise ToolError("booking partner did not return a booking reference", provider_id=self.id,
                            code=ProviderErrorCode.PROVIDER_ERROR)
        amount_minor = _response_amount_minor(response)
        data: dict[str, Any] = {"booking_ref": booking_ref, "status": "confirmed"}
        if amount_minor is not None:
            data["amount_minor"] = amount_minor
        if response.get("currency"):
            data["currency"] = str(response["currency"]).upper()
        return ActionResult(success=True, summary="booking confirmed", data=data)

    def _remote_cancel(self, params: dict[str, Any], api_key: str, idempotency_key: str) -> ActionResult:
        booking_ref = str(params.get("booking_ref") or params.get("booking_id"))
        payload = {"booking_ref": booking_ref, "reason": str(params.get("reason") or "")}
        response = self._partner_call("POST", "/cancel", payload, api_key, idempotency_key)
        cancellation_ref = _first(response, "cancellation_ref", "cancel_ref", "id") or booking_ref
        data: dict[str, Any] = {"booking_ref": booking_ref, "cancellation_ref": cancellation_ref,
                                "status": "cancelled"}
        refund_minor = _response_amount_minor(response, prefix="refund_")
        if refund_minor is not None:
            data["refund_amount_minor"] = refund_minor
        if response.get("currency"):
            data["currency"] = str(response["currency"]).upper()
        return ActionResult(success=True, summary="booking cancelled", data=data)

    def _idempotent_remote(self, action_type: str, params: dict[str, Any], operation) -> ActionResult:
        key = self._idempotency_key(action_type, params)
        cached = self._idempotent_results.get((action_type, key))
        if cached is not None:
            return cached.model_copy(deep=True)
        result = operation(key)
        self._idempotent_results[(action_type, key)] = result.model_copy(deep=True)
        return result

    def _partner_call(self, method: str, path: str, payload: dict[str, Any], api_key: str,
                      idempotency_key: str | None = None) -> dict[str, Any]:
        if not self._partner_url.lower().startswith("https://"):
            raise ToolError("booking partner URL must use HTTPS", provider_id=self.id,
                            code=ProviderErrorCode.FORBIDDEN)
        url = f"{self._partner_url}{path}"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ERA-Agent/0.9.0",
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        request = urllib.request.Request(
            url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = response.read(1_048_577)
                if len(raw) > 1_048_576:
                    raise ToolError("booking partner response exceeded size cap", provider_id=self.id,
                                    code=ProviderErrorCode.PROVIDER_ERROR)
                decoded = json.loads(raw.decode("utf-8")) if raw else {}
                if not isinstance(decoded, dict):
                    raise ToolError("booking partner returned invalid JSON", provider_id=self.id,
                                    code=ProviderErrorCode.PROVIDER_ERROR)
                return decoded
        except ToolError:
            raise
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            if status in (401, 403):
                code = ProviderErrorCode.AUTH
            elif status == 404:
                code = ProviderErrorCode.NOT_FOUND
            elif status == 409:
                code = ProviderErrorCode.CONFLICT
            elif status in (400, 422):
                code = ProviderErrorCode.VALIDATION
            elif status == 429 or status >= 500:
                code = ProviderErrorCode.UNAVAILABLE
            else:
                code = ProviderErrorCode.PROVIDER_ERROR
            raise ToolError(f"booking partner request failed (HTTP {status})", provider_id=self.id,
                            code=code) from exc
        except TimeoutError as exc:
            raise ToolError("booking partner request timed out", provider_id=self.id,
                            code=ProviderErrorCode.TIMEOUT) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ToolError("booking partner network unavailable", provider_id=self.id,
                            code=ProviderErrorCode.UNAVAILABLE) from exc

    # -- offline compatibility simulator ------------------------------------
    def _execute_simulated(self, action: Action) -> ActionResult:
        params = action.params or {}
        if action.action_type == ActionType.BOOKING_SEARCH.value:
            return self._sim_search(params)
        if action.action_type == ActionType.BOOKING_HOLD.value:
            return self._sim_hold(params)
        if action.action_type == ActionType.BOOKING_CONFIRM.value:
            return self._sim_confirm(params)
        if action.action_type == ActionType.BOOKING_CANCEL.value:
            return self._sim_cancel(params)
        raise ToolError("unsupported booking action", provider_id=self.id,
                        code=ProviderErrorCode.NOT_IMPLEMENTED)

    def _sim_search(self, params: dict[str, Any]) -> ActionResult:
        origin = str(params["origin"]).strip().upper()
        destination = str(params["destination"]).strip().upper()
        date_str = str(params.get("date") or params.get("departure_date") or "2026-09-01")
        mode = str(params.get("mode") or "train").lower()
        if "train" in mode:
            results = [
                {"service_number": "12951", "name": "Rajdhani Express", "origin": origin,
                 "destination": destination, "departure": f"{date_str} 16:30",
                 "arrival": f"{date_str} 08:35 (+1)", "class": "3A", "availability": "AVAILABLE-42",
                 "fare_inr": 2180.0, "amount_minor": 218000, "currency": "INR",
                 "trip_id": f"TRN-12951-{origin}-{destination}"},
                {"service_number": "12953", "name": "August Kranti Rajdhani", "origin": origin,
                 "destination": destination, "departure": f"{date_str} 17:15",
                 "arrival": f"{date_str} 09:45 (+1)", "class": "2A", "availability": "AVAILABLE-18",
                 "fare_inr": 3120.0, "amount_minor": 312000, "currency": "INR",
                 "trip_id": f"TRN-12953-{origin}-{destination}"},
            ]
        else:
            results = [{"service_number": "6E-204", "name": "IndiGo", "origin": origin,
                        "destination": destination, "departure": f"{date_str} 07:00",
                        "arrival": f"{date_str} 09:15", "class": "Economy", "availability": "AVAILABLE-9",
                        "fare_inr": 4850.0, "amount_minor": 485000, "currency": "INR",
                        "trip_id": f"FLT-6E204-{origin}-{destination}"}]
        return ActionResult(success=True, summary=f"Found {len(results)} {mode} options from {origin} to {destination}",
                            data={"results": results, "count": len(results), "mode": mode})

    def _sim_hold(self, params: dict[str, Any]) -> ActionResult:
        trip_id = str(params.get("offer_ref") or params.get("trip_id") or params.get("service_number") or params.get("booking_id"))
        passenger = str(params.get("passenger_name") or "Primary Passenger")
        fare = float(params.get("fare") or 2180.0)
        draft_id = f"DRAFT-{uuid.uuid4().hex[:8].upper()}"
        draft = {"draft_id": draft_id, "hold_ref": draft_id, "trip_id": trip_id,
                 "passenger_name": passenger, "fare_inr": fare, "status": "held",
                 "expires_in_minutes": self._hold_ttl_seconds // 60,
                 "expires_at": _expiry(self._hold_ttl_seconds)}
        self._drafts[draft_id] = draft
        return ActionResult(success=True, summary=f"Draft reservation {draft_id} created",
                            data=draft)

    def _sim_confirm(self, params: dict[str, Any]) -> ActionResult:
        draft_id = str(params.get("hold_ref") or params.get("draft_id") or params.get("booking_id"))
        key = self._idempotency_key(ActionType.BOOKING_CONFIRM.value, params)
        cached = self._idempotent_results.get((ActionType.BOOKING_CONFIRM.value, key))
        if cached is not None:
            return cached.model_copy(deep=True)
        draft = self._drafts.get(draft_id)
        if draft is None:
            raise ToolError("booking hold was not found", provider_id=self.id,
                            code=ProviderErrorCode.NOT_FOUND)
        if str(draft.get("expires_at", "")) < datetime.now(UTC).isoformat():
            raise ToolError("booking hold has expired", provider_id=self.id,
                            code=ProviderErrorCode.CONFLICT)
        pnr = f"PNR{uuid.uuid4().hex[:10].upper()}"
        booking_id = f"BK-{uuid.uuid4().hex[:8].upper()}"
        fare = draft.get("fare_inr", 2180.0) if draft else 2180.0
        passenger = draft.get("passenger_name", "Passenger") if draft else "Passenger"
        data = {"booking_id": booking_id, "booking_ref": booking_id, "pnr": pnr,
                "draft_id": draft_id, "passenger_name": passenger, "fare_inr": fare,
                "status": "confirmed"}
        self._bookings[booking_id] = data
        if draft:
            draft["status"] = "confirmed"
        result = ActionResult(success=True, summary=f"Booking confirmed successfully: PNR {pnr}", data=data)
        self._idempotent_results[(ActionType.BOOKING_CONFIRM.value, key)] = result.model_copy(deep=True)
        return result

    def _sim_cancel(self, params: dict[str, Any]) -> ActionResult:
        booking_id = str(params.get("booking_ref") or params["booking_id"]).strip()
        key = self._idempotency_key(ActionType.BOOKING_CANCEL.value, params)
        cached = self._idempotent_results.get((ActionType.BOOKING_CANCEL.value, key))
        if cached is not None:
            return cached.model_copy(deep=True)
        booking = self._bookings.get(booking_id)
        fare = booking.get("fare_inr", 2000.0) if booking else 2000.0
        refund = max(0.0, fare - 240.0)
        if booking:
            booking["status"] = "cancelled"
            booking["refund_inr"] = refund
        data = {"booking_id": booking_id, "booking_ref": booking_id, "status": "cancelled", "refund_inr": refund}
        result = ActionResult(success=True, summary=f"Booking {booking_id} cancelled", data=data)
        self._idempotent_results[(ActionType.BOOKING_CANCEL.value, key)] = result.model_copy(deep=True)
        return result

    # -- validation / secret helpers ----------------------------------------
    def _validate_amount_if_present(self, params: dict[str, Any], *, required: bool) -> None:
        if "amount_minor" not in params:
            if required:
                raise ToolError("booking.hold requires integer 'amount_minor'", provider_id=self.id,
                                code=ProviderErrorCode.VALIDATION)
            return
        self._amount(params)

    def _amount(self, params: dict[str, Any]) -> tuple[int, str]:
        amount = params.get("amount_minor")
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise ToolError("amount_minor must be a positive integer", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        if amount > self._max_amount_minor:
            raise ToolError("amount_minor exceeds configured booking cap", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        currency = str(params.get("currency") or "INR").upper()
        if not _CURRENCY_RE.fullmatch(currency):
            raise ToolError("currency must be an ISO-4217 three-letter code", provider_id=self.id,
                            code=ProviderErrorCode.VALIDATION)
        return amount, currency

    @staticmethod
    def _validate_idempotency_key(params: dict[str, Any]) -> None:
        key = params.get("idempotency_key")
        if key is not None and (not isinstance(key, str) or not key.strip() or len(key) > 128):
            raise ToolError("idempotency_key must be a bounded non-empty string", provider_id="booking",
                            code=ProviderErrorCode.VALIDATION)

    @staticmethod
    def _idempotency_key(action_type: str, params: dict[str, Any]) -> str:
        supplied = params.get("idempotency_key")
        if isinstance(supplied, str) and supplied.strip():
            return supplied.strip()
        # A deterministic fallback makes a duplicate delivery of the same
        # action safe without exposing raw passenger data in a vendor header.
        safe_params = {k: v for k, v in params.items() if k not in {"token", "payment_token"}}
        return hashlib.sha256(canonical_json({"action_type": action_type, "params": safe_params}).encode()).hexdigest()

    def _resolve(self, ref: str, label: str) -> str:
        if not ref:
            return ""
        if not is_vault_ref(ref):
            return ref
        if self._resolver is None:
            raise ToolError(f"{label} uses a vault reference but no resolver is attached", provider_id=self.id,
                            code=ProviderErrorCode.AUTH)
        try:
            return self._resolver.resolve_ref(ref, actor_id="booking-provider")
        except (VaultError, ValueError, TypeError) as exc:
            raise ToolError(f"cannot resolve {label} from vault", provider_id=self.id,
                            code=ProviderErrorCode.AUTH) from exc


def _passengers(params: dict[str, Any]) -> list[Any]:
    value = params.get("passengers", params.get("guests"))
    if value is None:
        name = params.get("passenger_name")
        return [{"name": str(name)}] if name else []
    if not isinstance(value, list) or len(value) > 10:
        raise ToolError("passengers must be an array with at most 10 entries", provider_id="booking",
                        code=ProviderErrorCode.VALIDATION)
    return value


def _normalise_offer(item: dict[str, Any]) -> dict[str, Any]:
    amount = _response_amount_minor(item)
    data: dict[str, Any] = {
        "provider": str(item.get("provider") or item.get("supplier") or "partner")[:200],
        "availability": str(item.get("availability") or item.get("status") or "unknown")[:100],
        "booking_ref": str(item.get("booking_ref") or item.get("offer_ref") or item.get("id") or "")[:256],
    }
    if amount is not None:
        data["amount_minor"] = amount
    if item.get("currency"):
        data["currency"] = str(item["currency"]).upper()[:3]
    for key in ("origin", "destination", "departure", "arrival", "name"):
        if item.get(key) is not None:
            data[key] = str(item[key])[:500]
    return data


def _first(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if value is not None and str(value):
            return str(value)[:256]
    return ""


def _response_amount_minor(data: dict[str, Any], prefix: str = "") -> int | None:
    for key in (f"{prefix}amount_minor", f"{prefix}price_minor", f"{prefix}amount"):
        value = data.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    price = data.get("price")
    if isinstance(price, dict):
        value = price.get("amount_minor")
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def _expiry(seconds: int) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()
