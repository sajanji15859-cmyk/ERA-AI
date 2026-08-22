"""Tests for WhatsApp provider (Phase 3H)."""

from __future__ import annotations

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError
from era.providers.whatsapp import WhatsAppProvider
from tests.provider_contract import assert_provider_contract


class FakeVaultResolver:
    def __init__(self, secrets: dict[str, str]):
        self.secrets = secrets

    def resolve_ref(self, ref: str, actor_id: str = "") -> str:
        if ref in self.secrets:
            return self.secrets[ref]
        raise ValueError(f"unknown vault ref: {ref}")


@pytest.fixture
def mock_whatsapp(monkeypatch):
    provider = WhatsAppProvider(
        phone_number_id="100987654321",
        access_token="test-access-token",
        api_url="https://graph.facebook.com/v20.0",
        timeout_seconds=2.0,
    )

    def fake_call(self, method, url, body, token):
        if "messages" in url and method == "POST":
            if body.get("type") == "reaction":
                return {"success": True}
            return {"messages": [{"id": "wamid.test12345"}]}
        if method == "GET":
            return {"messages": {"data": [{"id": "msg-1", "text": "Hello"}]}}
        return {}

    monkeypatch.setattr(WhatsAppProvider, "_http_call", fake_call)
    return provider


def test_whatsapp_provider_contract(mock_whatsapp):
    sample = Action(
        action_type="whatsapp.send",
        params={"to": "+919876543210", "message": "Hello from ERA"},
    )
    assert_provider_contract(mock_whatsapp, sample_action=sample)


def test_whatsapp_send_success(mock_whatsapp):
    a = Action(
        action_type="whatsapp.send",
        params={"to": "+919876543210", "message": "Test notification"},
    )
    result = mock_whatsapp.execute(a, ExecutionContext(actor_id="test"))
    assert result.success is True
    assert result.data["message_id"] == "wamid.test12345"
    assert result.data["status"] == "sent"


def test_whatsapp_react_success(mock_whatsapp):
    a = Action(
        action_type="whatsapp.react",
        params={"message_id": "wamid.test12345", "emoji": "👍", "to": "+919876543210"},
    )
    result = mock_whatsapp.execute(a, ExecutionContext(actor_id="test"))
    assert result.success is True
    assert result.data["emoji"] == "👍"
    assert result.data["status"] == "reacted"


def test_whatsapp_read_success(mock_whatsapp):
    a = Action(
        action_type="whatsapp.read",
        params={"limit": 5},
    )
    result = mock_whatsapp.execute(a, ExecutionContext(actor_id="test"))
    assert result.success is True
    assert len(result.data["messages"]) == 1


def test_whatsapp_vault_resolution():
    resolver = FakeVaultResolver({"vault:whatsapp/token": "real-decrypted-token"})
    provider = WhatsAppProvider(
        phone_number_id="12345",
        access_token="vault:whatsapp/token",
        secret_resolver=resolver,
    )
    resolved = provider._resolve(provider._access_token_ref, "WhatsApp token")
    assert resolved == "real-decrypted-token"


def test_whatsapp_validation_errors(mock_whatsapp):
    # Invalid phone
    with pytest.raises(ToolError) as exc:
        mock_whatsapp.validate(Action(action_type="whatsapp.send", params={"to": "abc", "message": "hi"}))
    assert exc.value.code == ProviderErrorCode.VALIDATION

    # Missing message/template
    with pytest.raises(ToolError) as exc:
        mock_whatsapp.validate(Action(action_type="whatsapp.send", params={"to": "+919876543210"}))
    assert exc.value.code == ProviderErrorCode.VALIDATION

    # Missing message_id for react
    with pytest.raises(ToolError) as exc:
        mock_whatsapp.validate(Action(action_type="whatsapp.react", params={"emoji": "👍"}))
    assert exc.value.code == ProviderErrorCode.VALIDATION
