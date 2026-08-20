"""Tests for the tool registry (era.tools.registry)."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from era.config import Config
from era.tools.base import RiskLevel, Tool, ToolError, ToolResult
from era.tools.registry import (
    ToolRegistry,
    build_default_registry,
    describe_call,
    resolve_sandbox_root,
)


class BoomTool(Tool):
    name = "test.boom"
    description = "always fails"
    input_schema: Mapping[str, Any] = {"type": "object", "properties": {}}
    risk_level = RiskLevel.READ_ONLY

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        raise ValueError("kaboom")


class OkTool(Tool):
    name = "test.ok"
    description = "always works"
    input_schema: Mapping[str, Any] = {"type": "object", "properties": {"x": {"type": "string"}}}
    risk_level = RiskLevel.READ_ONLY

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        return ToolResult.success(f"got {args.get('x')}", tool=self.name)


class TestRegistryBasics:
    def test_register_get_list(self) -> None:
        registry = ToolRegistry()
        registry.register(OkTool())
        assert registry.get("test.ok").name == "test.ok"
        specs = registry.list_tools()
        assert [s["name"] for s in specs] == ["test.ok"]

    def test_duplicate_registration_rejected(self) -> None:
        registry = ToolRegistry()
        registry.register(OkTool())
        with pytest.raises(ToolError, match="already registered"):
            registry.register(OkTool())

    def test_unknown_tool(self) -> None:
        with pytest.raises(ToolError, match="unknown tool"):
            ToolRegistry().get("nope")

    def test_empty_name_rejected(self) -> None:
        class NoName(Tool):
            name = ""
            description = "bad tool"

            def execute(self, args: Mapping[str, Any]) -> ToolResult:
                return ToolResult.success(tool=self.name)

        with pytest.raises(ToolError, match="empty name"):
            ToolRegistry().register(NoName())


class TestRegistryExecute:
    def test_success(self) -> None:
        registry = ToolRegistry()
        registry.register(OkTool())
        result = registry.execute("test.ok", {"x": "v"})
        assert result.ok and result.output == "got v" and result.tool == "test.ok"

    def test_unknown_tool_returns_failure_result(self) -> None:
        result = ToolRegistry().execute("missing", {})
        assert not result.ok and "unknown tool" in (result.error or "")

    def test_validation_failure_contained(self) -> None:
        registry = ToolRegistry()
        registry.register(OkTool())
        result = registry.execute("test.ok", {"x": 123})  # wrong type
        assert not result.ok and "must be string" in (result.error or "")

    def test_unexpected_exception_contained(self) -> None:
        registry = ToolRegistry()
        registry.register(BoomTool())
        result = registry.execute("test.boom", {})
        assert not result.ok and "unexpected failure" in (result.error or "")


class TestDescribeCall:
    def test_content_keys_redacted(self) -> None:
        described = describe_call("fs.write", {"path": "notes.md", "content": "x" * 5000})
        assert "content=<5000 chars>" in described
        assert "x" * 100 not in described

    def test_long_strings_truncated(self) -> None:
        described = describe_call("t", {"url": "h" * 200})
        assert len(described) < 120
        assert described.endswith("...") or "..." in described

    def test_lists_summarized(self) -> None:
        described = describe_call("t", {"command": ["echo", "a", "b", "c"]})
        assert "command=[4 items]" in described

    def test_short_values_kept(self) -> None:
        assert describe_call("t", {"path": "notes.md"}) == "t(path='notes.md')"


class TestBuildDefaultRegistry:
    def test_registers_six_tools(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("ERA_SANDBOX_ROOT", str(tmp_path / "sandbox"))
        config = Config()
        registry = build_default_registry(config)
        names = [s["name"] for s in registry.list_tools()]
        assert names == [
            "fs.list",
            "fs.read",
            "fs.write",
            "shell.run",
            "web.fetch",
            "web.search",
        ]

    def test_sandbox_created(self, tmp_path: Path, monkeypatch) -> None:
        root = tmp_path / "sandbox"
        monkeypatch.setenv("ERA_SANDBOX_ROOT", str(root))
        build_default_registry(Config())
        assert root.is_dir()

    def test_sandbox_respects_era_home_default(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("ERA_HOME", str(tmp_path / "home"))
        assert resolve_sandbox_root(Config()) == tmp_path / "home" / "sandbox"

    def test_explicit_sandbox_root_wins(self, tmp_path: Path) -> None:
        from era.config import FilesToolSettings, ToolsSettings

        config = Config(tools=ToolsSettings(files=FilesToolSettings(sandbox_root=str(tmp_path))))
        assert resolve_sandbox_root(config) == tmp_path

    def test_shell_disabled_by_default(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("ERA_SANDBOX_ROOT", str(tmp_path / "sandbox"))
        registry = build_default_registry(Config())
        result = registry.execute("shell.run", {"command": ["echo", "hi"]})
        assert not result.ok and "allowlist" in (result.error or "")
