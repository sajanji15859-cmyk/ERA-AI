"""Tests for the sandboxed file tools (era.tools.files)."""

from __future__ import annotations

from pathlib import Path

import pytest
from era.tools.files import FileListTool, FileReadTool, FileWriteTool, resolve_in_sandbox


@pytest.fixture()
def sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "sandbox"
    root.mkdir()
    return root


class TestContainment:
    @pytest.mark.parametrize(
        "bad",
        ["/etc/passwd", "../outside.txt", "a/../../escape", "/"],
    )
    def test_escapes_rejected(self, sandbox: Path, bad: str) -> None:
        with pytest.raises(Exception, match=r"escape|absolute"):
            resolve_in_sandbox(sandbox, bad)

    def test_empty_path_rejected(self, sandbox: Path) -> None:
        with pytest.raises(Exception, match="non-empty"):
            resolve_in_sandbox(sandbox, "   ")

    def test_symlink_escape_rejected(self, sandbox: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        link = sandbox / "link"
        link.symlink_to(outside)
        with pytest.raises(Exception, match="escape"):
            resolve_in_sandbox(sandbox, "link")

    def test_valid_relative_path_resolves_inside(self, sandbox: Path) -> None:
        target = resolve_in_sandbox(sandbox, "sub/dir/file.txt")
        assert str(target).startswith(str(sandbox.resolve()))
        assert target == sandbox.resolve() / "sub" / "dir" / "file.txt"


class TestFileList:
    def test_list(self, sandbox: Path, capsys: pytest.CaptureFixture[str]) -> None:
        (sandbox / "b.txt").write_text("hello")
        (sandbox / "a").mkdir()
        result = FileListTool(sandbox).execute({"path": "."})
        assert result.ok
        assert "dir  a" in result.output and "file b.txt" in result.output
        assert result.data["entries"][0]["name"] == "a"

    def test_missing_directory(self, sandbox: Path) -> None:
        result = FileListTool(sandbox).execute({"path": "nope"})
        assert not result.ok and "does not exist" in result.error


class TestFileRead:
    def test_read(self, sandbox: Path) -> None:
        (sandbox / "note.md").write_text("# Title\ncontent", encoding="utf-8")
        result = FileReadTool(sandbox).execute({"path": "note.md"})
        assert result.ok and "content" in result.output

    def test_missing_file(self, sandbox: Path) -> None:
        result = FileReadTool(sandbox).execute({"path": "ghost.txt"})
        assert not result.ok and "does not exist" in result.error

    def test_directory_rejected(self, sandbox: Path) -> None:
        (sandbox / "d").mkdir()
        result = FileReadTool(sandbox).execute({"path": "d"})
        assert not result.ok and "not a file" in result.error

    def test_binary_rejected(self, sandbox: Path) -> None:
        (sandbox / "blob.bin").write_bytes(b"\x00\xff\xfe\x10")
        result = FileReadTool(sandbox).execute({"path": "blob.bin"})
        assert not result.ok and "UTF-8" in result.error

    def test_size_cap_truncates(self, sandbox: Path) -> None:
        (sandbox / "big.txt").write_text("x" * 500, encoding="utf-8")
        result = FileReadTool(sandbox, max_bytes=100).execute({"path": "big.txt"})
        assert result.ok and result.data["truncated"] is True
        assert "truncated at size cap" in result.output

    def test_user_cap_cannot_exceed_tool_cap(self, sandbox: Path) -> None:
        (sandbox / "big.txt").write_text("y" * 500, encoding="utf-8")
        result = FileReadTool(sandbox, max_bytes=100).execute({"path": "big.txt", "max_bytes": 400})
        assert result.data["bytes"] == 100


class TestFileWrite:
    def test_write_and_read_back(self, sandbox: Path) -> None:
        result = FileWriteTool(sandbox).execute({"path": "notes/a.md", "content": "hi"})
        assert result.ok, result.error
        assert (sandbox / "notes" / "a.md").read_text(encoding="utf-8") == "hi"

    def test_no_clobber_by_default(self, sandbox: Path) -> None:
        (sandbox / "f.txt").write_text("original")
        result = FileWriteTool(sandbox).execute({"path": "f.txt", "content": "new"})
        assert not result.ok and "already exists" in result.error
        assert (sandbox / "f.txt").read_text() == "original"

    def test_explicit_overwrite(self, sandbox: Path) -> None:
        (sandbox / "f.txt").write_text("original")
        result = FileWriteTool(sandbox).execute(
            {"path": "f.txt", "content": "new", "overwrite": True}
        )
        assert result.ok
        assert (sandbox / "f.txt").read_text() == "new"

    def test_write_cap(self, sandbox: Path) -> None:
        result = FileWriteTool(sandbox, max_bytes=10).execute(
            {"path": "f.txt", "content": "x" * 50}
        )
        assert not result.ok and "write cap" in result.error
        assert not (sandbox / "f.txt").exists()

    def test_escape_rejected(self, sandbox: Path) -> None:
        result = FileWriteTool(sandbox).execute({"path": "../evil.txt", "content": "x"})
        assert not result.ok and "escape" in result.error
        assert not (sandbox.parent / "evil.txt").exists()
