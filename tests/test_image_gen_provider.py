"""Tests for ImageGenProvider (Phase 3H)."""

from __future__ import annotations

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError
from era.providers.image_gen import ImageGenProvider
from tests.provider_contract import assert_provider_contract


class FakeVaultResolver:
    def __init__(self, secrets: dict[str, str]):
        self.secrets = secrets

    def resolve_ref(self, ref: str, actor_id: str = "") -> str:
        if ref in self.secrets:
            return self.secrets[ref]
        raise ValueError(f"unknown vault ref: {ref}")


@pytest.fixture
def mock_image_gen(tmp_path, monkeypatch):
    provider = ImageGenProvider(
        api_key="test-api-key",
        workspace_root=tmp_path / "workspace",
        timeout_seconds=2.0,
    )

    # 1x1 transparent PNG base64
    tiny_png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="

    def fake_call(self, url, payload, api_key):
        return {"data": [{"b64_json": tiny_png_b64}]}

    monkeypatch.setattr(ImageGenProvider, "_http_call", fake_call)
    return provider


def test_image_gen_contract(mock_image_gen):
    sample = Action(
        action_type="image.generate",
        params={"prompt": "A sunset over mountains in watercolor style"},
    )
    assert_provider_contract(mock_image_gen, sample_action=sample)


def test_image_gen_execute_saves_file(mock_image_gen, tmp_path):
    a = Action(
        action_type="image.generate",
        params={
            "prompt": "Futuristic clean city skyline",
            "output_path": "images/city.png",
            "size": "1024x1024",
        },
    )
    result = mock_image_gen.execute(a, ExecutionContext(actor_id="test"))
    assert result.success is True
    assert result.data["path"] == "images/city.png"
    assert result.data["bytes"] > 10

    # File was written inside workspace
    saved = tmp_path / "workspace" / "images" / "city.png"
    assert saved.is_file()
    assert len(saved.read_bytes()) == result.data["bytes"]


def test_image_gen_no_key_clean_not_implemented(tmp_path):
    provider = ImageGenProvider(
        api_key="",
        workspace_root=tmp_path / "workspace",
    )
    a = Action(
        action_type="image.generate",
        params={"prompt": "A cat in space"},
    )
    with pytest.raises(ToolError) as exc:
        provider.execute(a, ExecutionContext(actor_id="test"))
    assert exc.value.code == ProviderErrorCode.NOT_IMPLEMENTED
    assert "not configured" in str(exc.value)


def test_image_gen_rejects_path_traversal(mock_image_gen):
    a = Action(
        action_type="image.generate",
        params={"prompt": "test", "output_path": "../../etc/shadow"},
    )
    with pytest.raises(ToolError) as exc:
        mock_image_gen.validate(a)
    assert exc.value.code == ProviderErrorCode.FORBIDDEN


def test_image_gen_requires_prompt(mock_image_gen):
    with pytest.raises(ToolError) as exc:
        mock_image_gen.validate(Action(action_type="image.generate", params={}))
    assert exc.value.code == ProviderErrorCode.VALIDATION


def test_image_gen_vault_resolution():
    resolver = FakeVaultResolver({"vault:image/token": "sk-real-secret-key"})
    provider = ImageGenProvider(
        api_key="vault:image/token",
        secret_resolver=resolver,
    )
    resolved = provider._resolve(provider._api_key_ref, "Image key")
    assert resolved == "sk-real-secret-key"
