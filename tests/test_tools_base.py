"""Tests for tool base types (era.tools.base)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from era.tools.base import (
    RiskLevel,
    Tool,
    ToolError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolResult,
    ToolValidationError,
)


class EchoTool(Tool):
    name = "test.echo"
    description = "echoes the message"
    input_schema: Mapping[str, Any] = {
        "type": "object",
        "properties": {"message": {"type": "string"}},
        "required": ["message"],
        "additionalProperties": False,
    }
    risk_level = RiskLevel.READ_ONLY

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        return ToolResult.success(args["message"], tool=self.name)


class TestToolResult:
    def test_success_factory(self) -> None:
        result = ToolResult.success("out", data={"a": 1}, tool="t")
        assert (result.ok, result.output, result.tool) == (True, "out", "t")
        assert result.error is None

    def test_failure_factory(self) -> None:
        result = ToolResult.failure("boom", tool="t")
        assert not result.ok
        assert result.error == "boom"

    def test_data_excluded_from_equality(self) -> None:
        assert ToolResult.success("x", data={"a": 1}) == ToolResult.success("x", data={"b": 2})


class TestRiskLevel:
    def test_values(self) -> None:
        assert {level.value for level in RiskLevel} == {
            "READ_ONLY",
            "LOW_RISK_WRITE",
            "HIGH_RISK_WRITE",
        }


class TestErrorHierarchy:
    def test_all_derive_from_tool_error(self) -> None:
        for exc in (ToolValidationError("x"), ToolExecutionError("x"), ToolNotFoundError("x")):
            assert isinstance(exc, ToolError)


class TestToolABC:
    def test_cannot_instantiate_without_execute(self) -> None:
        class Incomplete(Tool):
            name = "bad"

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_validate_passes_and_fails(self) -> None:
        tool = EchoTool()
        tool.validate({"message": "hi"})  # no exception
        with pytest.raises(ToolValidationError, match="message"):
            tool.validate({})

    def test_validate_reports_unknown_properties(self) -> None:
        with pytest.raises(ToolValidationError, match="unknown property 'extra'"):
            EchoTool().validate({"message": "hi", "extra": 1})

    def test_default_risk_for_returns_static_level(self) -> None:
        assert EchoTool().risk_for({"message": "x"}) is RiskLevel.READ_ONLY

    def test_spec_shape(self) -> None:
        spec = EchoTool().spec()
        assert spec["name"] == "test.echo"
        assert spec["risk_level"] == "READ_ONLY"
        assert spec["input_schema"]["type"] == "object"
        assert "description" in spec
