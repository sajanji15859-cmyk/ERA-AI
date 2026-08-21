"""WorkspaceProvider tests — sandboxing, size caps, SPI contract (Phase 3A)."""

from __future__ import annotations

import pytest

from era.core.action import Action
from era.core.context import ExecutionContext
from era.core.result import ProviderErrorCode, ToolError
from era.providers.workspace import WorkspaceProvider

CTX = ExecutionContext(actor_id="t")


@pytest.fixture
def provider(tmp_path):
    return WorkspaceProvider(root=tmp_path / "ws", max_file_bytes=10_000)


def test_write_read_roundtrip(provider):
    provider.execute(Action(action_type="fs.write",
                           params={"path": "site/index.html", "content": "<h1>hi</h1>"}), CTX)
    result = provider.execute(Action(action_type="fs.read",
                                     params={"path": "site/index.html"}), CTX)
    assert result.success
    assert result.data["content"] == "<h1>hi</h1>"
    assert result.data["path"] == "site/index.html"


def test_list_directory(provider):
    provider.execute(Action(action_type="fs.write", params={"path": "a.txt", "content": "a"}), CTX)
    provider.execute(Action(action_type="fs.write", params={"path": "d/b.txt", "content": "b"}), CTX)
    result = provider.execute(Action(action_type="fs.list", params={"path": "."}), CTX)
    names = {e["name"] for e in result.data["entries"]}
    assert names == {"a.txt", "d"}


def test_move_within_workspace(provider):
    provider.execute(Action(action_type="fs.write", params={"path": "a.txt", "content": "a"}), CTX)
    result = provider.execute(Action(action_type="fs.move",
                                     params={"path": "a.txt", "dst": "b.txt"}), CTX)
    assert result.success
    read = provider.execute(Action(action_type="fs.read", params={"path": "b.txt"}), CTX)
    assert read.success


def test_delete_file_and_empty_dir(provider):
    provider.execute(Action(action_type="fs.write", params={"path": "x.txt", "content": "x"}), CTX)
    provider.execute(Action(action_type="fs.delete", params={"path": "x.txt"}), CTX)
    with pytest.raises(ToolError) as err:
        provider.execute(Action(action_type="fs.read", params={"path": "x.txt"}), CTX)
    assert err.value.code is ProviderErrorCode.NOT_FOUND
    # non-empty dir deletion fails cleanly
    provider.execute(Action(action_type="fs.write", params={"path": "d/f.txt", "content": "f"}), CTX)
    with pytest.raises(ToolError):
        provider.execute(Action(action_type="fs.delete", params={"path": "d"}), CTX)


def test_delete_workspace_root_forbidden(provider):
    with pytest.raises(ToolError) as err:
        provider.execute(Action(action_type="fs.delete", params={"path": "."}), CTX)
    assert err.value.code is ProviderErrorCode.FORBIDDEN


@pytest.mark.parametrize("evil_path", [
    "../escape.txt", "../../etc/passwd", "/etc/passwd",
    "sub/../../escape.txt", "..",
])
def test_path_traversal_rejected(provider, evil_path):
    with pytest.raises(ToolError) as err:
        provider.validate(Action(action_type="fs.write",
                                params={"path": evil_path, "content": "x"}))
    assert err.value.code is ProviderErrorCode.FORBIDDEN


def test_symlink_escape_rejected(provider, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (tmp_path / "ws").mkdir(exist_ok=True)
    (tmp_path / "ws" / "link").symlink_to(outside)
    with pytest.raises(ToolError) as err:
        provider.execute(Action(action_type="fs.read", params={"path": "link"}), CTX)
    assert err.value.code is ProviderErrorCode.FORBIDDEN


def test_write_size_cap(provider):
    big = "x" * 20_000
    with pytest.raises(ToolError) as err:
        provider.validate(Action(action_type="fs.write",
                                params={"path": "big.txt", "content": big}))
    assert err.value.code is ProviderErrorCode.VALIDATION


def test_read_oversize_rejected(provider):
    provider.workspace.root.joinpath("big.txt").write_text("y" * 20_000, encoding="utf-8")
    with pytest.raises(ToolError) as err:
        provider.execute(Action(action_type="fs.read", params={"path": "big.txt"}), CTX)
    assert err.value.code is ProviderErrorCode.VALIDATION


def test_validation_requires_path_and_content(provider):
    with pytest.raises(ToolError):
        provider.validate(Action(action_type="fs.read", params={}))
    with pytest.raises(ToolError):
        provider.validate(Action(action_type="fs.write", params={"path": "a.txt"}))
    with pytest.raises(ToolError):
        provider.validate(Action(action_type="fs.write",
                                params={"path": "a.txt", "content": 123}))


def test_photo_actions_map_to_files(provider):
    provider.execute(Action(action_type="photo.upload",
                           params={"path": "photos/p1.txt", "content": "img"}), CTX)
    result = provider.execute(Action(action_type="photo.view",
                                    params={"path": "photos/p1.txt"}), CTX)
    assert result.success and result.data["content"] == "img"
    provider.execute(Action(action_type="photo.edit",
                           params={"path": "photos/p1.txt", "content": "img2"}), CTX)
    assert provider.execute(Action(action_type="photo.view",
                                  params={"path": "photos/p1.txt"}), CTX).data["content"] == "img2"
    provider.execute(Action(action_type="photo.delete", params={"path": "photos/p1.txt"}), CTX)
    with pytest.raises(ToolError):
        provider.execute(Action(action_type="photo.view", params={"path": "photos/p1.txt"}), CTX)


def test_provider_contract_suite(provider):
    from tests.provider_contract import assert_provider_contract
    assert_provider_contract(provider, sample_action=Action(
        action_type="fs.write", params={"path": "contract.txt", "content": "ok"}))
