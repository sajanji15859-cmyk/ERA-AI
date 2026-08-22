"""Offline Phase 5A provider integration and security matrix.

Parameterized cases deliberately cover more than one hundred provider-boundary
scenarios without opening an external network connection or requiring a device.
"""

from __future__ import annotations

import hashlib
import hmac
import socket

import pytest

from era.config import Settings
from era.container import build_container
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError
from era.providers.android_device import AndroidDeviceProvider
from era.providers.booking import BookingProvider
from era.providers.email_imap import EmailImapProvider
from era.providers.email_smtp import EmailSmtpProvider
from era.providers.stub import StubProvider
from era.providers.web import WebProvider
from era.providers.whatsapp import WhatsAppProvider
from era.security.url_safety import resolve_public_url, validate_public_url
from tests.conftest import action

CTX = ExecutionContext(actor_id="phase5a")


# -- Web / SSRF ---------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://example.com", "ftp://example.com", "file:///etc/passwd", "data:text/plain,x",
    "https://127.0.0.1", "https://127.1", "https://127.0.0.2", "https://10.0.0.1",
    "https://10.255.255.255", "https://172.16.0.1", "https://172.31.0.1",
    "https://192.168.0.1", "https://169.254.169.254", "https://0.0.0.0",
    "https://100.64.0.1", "https://224.0.0.1", "https://[::1]", "https://[fe80::1]",
    "https://[fc00::1]", "https://[ff02::1]", "https://u:p@example.com",
    "https://example.com:8443", "https://example.com/?token=x",
    "https://example.com/?api_key=x", "https://example.com/?password=x",
    "https://example.com/?access_token=x", "https://example.com/\x00x",
])
def test_phase5a_ssrf_literal_and_url_matrix(url):
    with pytest.raises(ToolError) as error:
        validate_public_url(url)
    assert error.value.code in {ProviderErrorCode.FORBIDDEN, ProviderErrorCode.VALIDATION}


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.1.2.3", "172.20.1.1", "192.168.1.1", "169.254.1.1",
    "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1", "ff02::1",
])
def test_phase5a_dns_rebinding_matrix(monkeypatch, address):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *_a, **_k: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))],
    )
    with pytest.raises(ToolError) as error:
        resolve_public_url("https://rebinding.example/")
    assert error.value.code is ProviderErrorCode.FORBIDDEN


@pytest.fixture
def safe_dns(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *_a, **_k: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))],
    )


def _fake_web(monkeypatch, body: bytes, content_type: str = "text/html"):
    class Response:
        def __init__(self):
            self.headers = {"Content-Type": content_type}
            self.status = 200

        def read(self, amount):
            return body[:amount]

        def geturl(self):
            return "https://example.com/final"

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Opener:
        def open(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr("era.providers.web.urllib.request.build_opener", lambda _handler: Opener())


@pytest.mark.parametrize("content_type", ["application/octet-stream", "image/png", "application/pdf", "video/mp4"])
def test_phase5a_fetch_rejects_explicit_binary(safe_dns, monkeypatch, tmp_path, content_type):
    _fake_web(monkeypatch, b"binary", content_type)
    with pytest.raises(ToolError) as error:
        WebProvider(workspace_root=tmp_path).execute(action("web.fetch", url="https://example.com/x"), CTX)
    assert error.value.code is ProviderErrorCode.FORBIDDEN


def test_phase5a_fetch_truncates_and_download_receipts(safe_dns, monkeypatch, tmp_path):
    _fake_web(monkeypatch, b"<title>Title</title><p>abcdefghijklmnopqrstuvwxyz</p>")
    provider = WebProvider(workspace_root=tmp_path, max_fetch_bytes=16, max_download_bytes=100)
    fetched = provider.execute(action("web.fetch", url="https://example.com/x"), CTX)
    assert fetched.data["truncated"] and fetched.data["bytes"] == 16
    _fake_web(monkeypatch, b"artifact", "application/octet-stream")
    downloaded = provider.execute(action("web.download", url="https://example.com/x", path="nested/a.bin"), CTX)
    assert downloaded.data["sha256"] == hashlib.sha256(b"artifact").hexdigest()
    assert (tmp_path / "nested/a.bin").read_bytes() == b"artifact"


def test_phase5a_download_cap_path_and_rate_bound(safe_dns, monkeypatch, tmp_path):
    _fake_web(monkeypatch, b"1234", "application/octet-stream")
    provider = WebProvider(workspace_root=tmp_path, max_download_bytes=3, max_fetches_per_minute=2)
    with pytest.raises(ToolError):
        provider.execute(action("web.download", url="https://example.com/x", path="a.bin"), CTX)
    assert not (tmp_path / "a.bin").exists()
    _fake_web(monkeypatch, b"{}", "application/json")
    provider.execute(action("web.fetch", url="https://example.com/x"), CTX)
    with pytest.raises(ToolError) as error:
        provider.execute(action("web.fetch", url="https://example.com/x"), CTX)
    assert error.value.code is ProviderErrorCode.FORBIDDEN


# -- SMTP / IMAP --------------------------------------------------------------

@pytest.mark.parametrize("recipients", [
    [f"p{i}@example.com" for i in range(11)],
    "a@example.com,b@example.com,c@example.com,d@example.com,e@example.com,f@example.com,g@example.com,h@example.com,i@example.com,j@example.com,k@example.com",
])
def test_phase5a_smtp_recipients_are_bounded(tmp_path, recipients):
    provider = EmailSmtpProvider(host="smtp.example", port=587, password="p", workspace_root=tmp_path)
    with pytest.raises(ToolError) as error:
        provider.validate(action("email.send", to=recipients, body="hello"))
    assert error.value.code is ProviderErrorCode.VALIDATION


@pytest.mark.parametrize("size", [102_401, 110_000, 150_000, 200_000, 250_000, 500_000, 750_000, 1_000_000])
def test_phase5a_smtp_body_byte_cap(tmp_path, size):
    provider = EmailSmtpProvider(host="smtp.example", port=587, password="p", workspace_root=tmp_path)
    with pytest.raises(ToolError):
        provider.validate(action("email.send", to="a@example.com", body="x" * size))


@pytest.mark.parametrize("path", ["../secret", "/tmp/secret", "missing.txt"])
def test_phase5a_smtp_attachment_paths_are_confined(tmp_path, path):
    provider = EmailSmtpProvider(host="smtp.example", port=587, password="p", workspace_root=tmp_path)
    with pytest.raises(ToolError):
        provider.validate(action("email.send", to="a@example.com", body="x", attachments=[{"path": path}]))


class _Imap:
    def __init__(self):
        self.readonly = False

    def login(self, *_args):
        return "OK", [b""]

    def select(self, _mailbox, readonly=False):
        self.readonly = readonly
        return "OK", [b"2"]

    def uid(self, command, *_args):
        if command == "search":
            return "OK", [b"1 2 3"]
        return "OK", [(b"FETCH", b"From: x@example.com\r\nSubject: Hi\r\n\r\npassword=secret-value")]

    def logout(self):
        return "BYE", [b""]


def test_phase5a_imap_only_selects_readonly(monkeypatch):
    fake = _Imap()
    monkeypatch.setattr("era.providers.email_imap.imaplib.IMAP4_SSL", lambda *_a, **_k: fake)
    result = EmailImapProvider(host="imap.example", username="u", password="p", max_messages=2).execute(
        action("email.search", query="invoice", limit=2), CTX)
    assert fake.readonly and result.data["count"] == 2
    assert "secret-value" not in result.data["messages"][0]["body_preview"]


@pytest.mark.parametrize("limit", [-1, 0, 51, 99, "one"])
def test_phase5a_imap_result_cap(limit):
    provider = EmailImapProvider(host="imap.example", username="u", password="p")
    with pytest.raises(ToolError):
        provider.validate(action("email.read", limit=limit))


# -- WhatsApp -----------------------------------------------------------------

@pytest.fixture
def whatsapp(monkeypatch):
    provider = WhatsAppProvider(phone_number_id="123", access_token="token", max_messages_per_hour=3)
    calls: list[dict] = []

    def api(_method, _url, payload, _token):
        calls.append(payload or {})
        return {"messages": [{"id": f"wamid.{len(calls)}"}]}

    monkeypatch.setattr(provider, "_http_call", api)
    return provider, calls


def test_phase5a_whatsapp_template_and_text_routes(whatsapp):
    provider, calls = whatsapp
    provider.execute(action("whatsapp.send", to="+919876543210", template="welcome"), CTX)
    provider.execute(action("whatsapp.send", to="+919876543211", message="hello"), CTX)
    assert [call["type"] for call in calls] == ["template", "text"]


@pytest.mark.parametrize("message", [None, "", "x" * 1001, "x" * 1200])
def test_phase5a_whatsapp_message_bounds(whatsapp, message):
    provider, _calls = whatsapp
    with pytest.raises(ToolError):
        provider.validate(action("whatsapp.send", to="+919876543210", message=message))


@pytest.mark.parametrize("media_count", [6, 7, 8, 9, 10])
def test_phase5a_whatsapp_media_cap(whatsapp, media_count):
    provider, _calls = whatsapp
    media = [{"type": "image", "id": str(index)} for index in range(media_count)]
    with pytest.raises(ToolError):
        provider.validate(action("whatsapp.send", to="+919876543210", media=media))


def test_phase5a_whatsapp_webhook_hmac_and_config_fallback(whatsapp):
    provider, _calls = whatsapp
    raw = b'{"object":"whatsapp_business_account"}'
    provider._webhook_app_secret_ref = "secret"
    signature = "sha256=" + hmac.new(b"secret", raw, "sha256").hexdigest()
    assert provider.verify_webhook_signature(raw, signature)
    assert not provider.verify_webhook_signature(raw, "sha256=bad")
    with pytest.raises(ToolError) as error:
        WhatsAppProvider().execute(action("whatsapp.read", limit=1), CTX)
    assert error.value.code is ProviderErrorCode.NOT_IMPLEMENTED


# -- Booking / dual approval --------------------------------------------------

@pytest.fixture
def partner(monkeypatch):
    provider = BookingProvider(partner_api_key="key", partner_url="https://partner.example", max_amount_minor=500)
    calls: list[tuple[str, str, str | None]] = []

    def api(_method, path, _payload, _key, idempotency_key=None):
        calls.append((_method, path, idempotency_key))
        if path == "/holds":
            return {"hold_ref": "h1", "expires_at": "2030-01-01T00:00:00+00:00"}
        if path == "/confirm":
            return {"booking_ref": "b1", "amount_minor": 100, "currency": "INR"}
        if path == "/cancel":
            return {"cancellation_ref": "c1", "refund_amount_minor": 80, "currency": "INR"}
        return {"results": [{"id": "offer", "amount_minor": 100, "currency": "INR"}]}

    monkeypatch.setattr(provider, "_partner_call", api)
    return provider, calls


def test_phase5a_booking_partner_results_and_idempotency(partner):
    provider, calls = partner
    assert provider.execute(action("booking.search", origin="DEL", destination="BOM"), CTX).data["count"] == 1
    held = provider.execute(action("booking.hold", offer_ref="o", amount_minor=100, currency="INR"), CTX)
    assert held.data["hold_ref"] == "h1"
    request = action("booking.confirm", hold_ref="h1", idempotency_key="same")
    assert provider.execute(request, CTX).data == provider.execute(request, CTX).data
    assert len([call for call in calls if call[1] == "/confirm"]) == 1


@pytest.mark.parametrize("amount", [0, -1, 501, 1000, 1.1, "100", None])
def test_phase5a_booking_amounts_are_positive_minor_units(partner, amount):
    provider, _calls = partner
    with pytest.raises(ToolError):
        provider.validate(action("booking.hold", offer_ref="o", amount_minor=amount, currency="INR"))


def test_phase5a_booking_network_confirm_is_side_effect_unknown(monkeypatch):
    provider = BookingProvider(partner_api_key="key", partner_url="https://partner.example")
    monkeypatch.setattr(provider, "_partner_call", lambda *_a, **_k: (_ for _ in ()).throw(
        ToolError("offline", code=ProviderErrorCode.UNAVAILABLE)))
    with pytest.raises(ToolError) as error:
        provider.execute(action("booking.confirm", hold_ref="h"), CTX)
    assert error.value.code is ProviderErrorCode.SIDE_EFFECT_UNKNOWN


def test_phase5a_booking_dual_approval_blocks_then_dispatches(tmp_path):
    provider = BookingProvider()
    container = build_container(Settings(database_url=f"sqlite:///{tmp_path}/booking.db"),
                                providers=[provider, StubProvider(exclude=provider.action_types)])
    hold = provider.execute(action("booking.hold", trip_id="trip"), CTX)
    request = action("booking.confirm", draft_id=hold.data["draft_id"])
    pending = container.execution_service.request(request, CTX)
    assert container.execution_service.approve(pending.confirmation_id, request, CTX, pending.challenge).status == "awaiting_approval"
    container.dual_approval_service.record_approval(confirmation_id=pending.confirmation_id,
                                                    actor_id="approver", status="GRANTED")
    assert container.execution_service.approve(pending.confirmation_id, request, CTX, pending.challenge).status == "executed"


# -- Android ADB ---------------------------------------------------------------

class _Adb:
    def __init__(self, offline=False):
        self.offline = offline
        self.commands: list[list[str]] = []

    def run(self, command, *, timeout):
        self.commands.append(command)
        if self.offline:
            raise OSError("offline")
        if "screencap" in command:
            return b"\x89PNG\r\n"
        if "content://sms" in command:
            return b"Row: address=+911, body=password=secret-value\n"
        if "location" in command:
            return b"gps 28.6139, 77.2090"
        return b"ok\n"


def _device(tmp_path, **kwargs):
    return AndroidDeviceProvider(device_id="emulator-5554", pairing_token="pair", workspace_root=tmp_path,
                                 transport=_Adb(), safe_app_packages=["com.android.chrome"], **kwargs)


@pytest.mark.parametrize("command", [
    "su", "sudo id", "rm -rf /", "mount", "dd if=/dev/zero", "reboot", "setenforce 0",
    "ls; id", "cat /x | sh", "getprop $(id)", "dumpsys; reboot", "unknown",
    "", "x" * 513,
])
def test_phase5a_android_shell_reject_matrix(tmp_path, command):
    with pytest.raises(ToolError) as error:
        _device(tmp_path).validate(action("device.shell", command=command))
    assert error.value.code in {ProviderErrorCode.FORBIDDEN, ProviderErrorCode.VALIDATION}


@pytest.mark.parametrize("command", ["ls /sdcard", "cat /proc/version", "dumpsys battery", "getprop ro.product.model"])
def test_phase5a_android_shell_allowlist(tmp_path, command):
    assert _device(tmp_path).execute(action("device.shell", command=command), CTX).success


@pytest.mark.parametrize("package", ["com.bad.app", "bad", "com.android.chrome;rm", "com.android.settings"])
def test_phase5a_android_app_allowlist(tmp_path, package):
    with pytest.raises(ToolError):
        _device(tmp_path).validate(action("device.app_launch", package=package))


def test_phase5a_android_pairing_artifact_and_offline(tmp_path):
    with pytest.raises(ToolError) as error:
        AndroidDeviceProvider(device_id="d", workspace_root=tmp_path, transport=_Adb()).execute(action("device.location"), CTX)
    assert error.value.code is ProviderErrorCode.AUTH
    provider = _device(tmp_path)
    shot = provider.execute(action("device.screenshot", path="artifacts/s.png"), CTX)
    assert (tmp_path / shot.data["path"]).exists()
    assert "secret-value" not in provider.execute(action("device.sms_read", limit=1), CTX).data["messages"][0]["body_preview"]
    offline = AndroidDeviceProvider(device_id="d", pairing_token="p", workspace_root=tmp_path, transport=_Adb(offline=True))
    with pytest.raises(ToolError) as error:
        offline.execute(action("device.location"), CTX)
    assert error.value.code is ProviderErrorCode.UNAVAILABLE


def test_phase5a_android_payment_dual_approval(tmp_path):
    provider = _device(tmp_path)
    container = build_container(Settings(database_url=f"sqlite:///{tmp_path}/device.db"),
                                providers=[provider, StubProvider(exclude=provider.action_types)])
    request = action("device.payment", amount_minor=100, recipient="merchant", currency="INR")
    pending = container.execution_service.request(request, CTX)
    assert container.execution_service.approve(pending.confirmation_id, request, CTX, pending.challenge).status == "awaiting_approval"
    container.dual_approval_service.record_approval(confirmation_id=pending.confirmation_id,
                                                    actor_id="approver", status="GRANTED")
    assert container.execution_service.approve(pending.confirmation_id, request, CTX, pending.challenge).status == "executed"


# -- Registration and configuration ------------------------------------------

@pytest.mark.parametrize("exclude", [["web.search"], {"web.search"}, frozenset({"web.search"})])
def test_phase5a_stub_exclusion_is_iterable(exclude):
    assert "web.search" not in StubProvider(exclude=exclude).action_types


def test_phase5a_settings_and_registration_defaults(tmp_path):
    settings = Settings()
    assert settings.app_version == "0.9.0"
    assert settings.web_max_fetches_per_minute == 30
    web = WebProvider(workspace_root=tmp_path)
    container = build_container(Settings(database_url=f"sqlite:///{tmp_path}/registry.db"),
                                providers=[web, StubProvider(exclude=list(web.action_types))])
    assert container.registry.get("web.fetch").id == "web"
    assert container.registry.get("email.send").id == "stub"
