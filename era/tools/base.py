"""Tool system core types: results, risk levels, the Tool ABC, error taxonomy."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar

from era.tools.schema import validate_schema


class RiskLevel(StrEnum):
    """Risk classification consumed by the Phase 1C permission engine.

    Defined here (next to the things being classified) so tools can carry their
    level as metadata from day one; the permission engine will import it.
    """

    READ_ONLY = "READ_ONLY"
    LOW_RISK_WRITE = "LOW_RISK_WRITE"
    HIGH_RISK_WRITE = "HIGH_RISK_WRITE"


class ToolError(RuntimeError):
    """Base class for tool-system failures."""


class ToolValidationError(ToolError):
    """Tool arguments do not match the tool's input schema."""


class ToolExecutionError(ToolError):
    """The tool ran but failed (I/O, timeout, containment violation, ...)."""


class ToolNotFoundError(ToolError):
    """No tool is registered under the requested name."""


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Uniform execution result for every tool.

    ``output`` is text meant for LLM consumption (already truncated where the
    tool applies caps). ``data`` carries structured results for programmatic
    callers. Tools never raise through the registry — failures are values.
    """

    ok: bool
    output: str = ""
    error: str | None = None
    data: Any = field(default=None, compare=False, repr=False)
    tool: str = ""

    @classmethod
    def success(cls, output: str = "", *, data: Any = None, tool: str = "") -> ToolResult:
        return cls(ok=True, output=output, data=data, tool=tool)

    @classmethod
    def failure(cls, error: str, *, tool: str = "", output: str = "") -> ToolResult:
        return cls(ok=False, output=output, error=error, tool=tool)


class Tool(ABC):
    """Base class every tool implements.

    Class attributes describe the tool for prompts, validation and (later)
    permission gating; ``execute`` performs the action and returns a
    :class:`ToolResult` (raising is allowed; the registry converts exceptions
    into failed results).
    """

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    input_schema: ClassVar[Mapping[str, Any]] = {}
    risk_level: ClassVar[RiskLevel] = RiskLevel.READ_ONLY

    def validate(self, args: Mapping[str, Any]) -> None:
        """Validate arguments against ``input_schema``.

        Raises:
            ToolValidationError: with all accumulated schema errors.
        """
        errors = validate_schema(args, self.input_schema, where=f"arguments for {self.name}")
        if errors:
            raise ToolValidationError("; ".join(errors))

    @abstractmethod
    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        """Run the tool. May raise ToolError; other exceptions are contained
        by the registry."""

    def risk_for(self, args: Mapping[str, Any]) -> RiskLevel:
        """Risk of this particular invocation (default: the static level).

        Subclasses may refine per invocation (e.g. write-with-overwrite) for
        the Phase 1C permission engine.
        """
        return self.risk_level

    def spec(self) -> dict[str, Any]:
        """Tool description for prompts and listings."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": dict(self.input_schema),
            "risk_level": self.risk_level.value,
        }
