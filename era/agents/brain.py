"""Agent brain — per-task reasoning, content generation and tool selection.

Two implementations:

* :class:`OfflineBrain` — deterministic, free, no model calls. Resolves
  ``content_from`` keys against the offline content packs, repairs failed
  writes by re-rendering with the correction note, and always proposes the
  planned action (tool selection is planner-driven offline).
* :class:`LLMBrain` — uses a real ``LLMProvider`` for open-ended content
  generation and tool selection. Falls back to the OfflineBrain on any model
  error (budget-aware), so a broken/expensive model can never stall the run.

Tool selection is validated against the action catalog by the loop: an
unregistered/unknown proposed action is rejected and the planned action is
used instead (fail closed).
"""

from __future__ import annotations

import json
from typing import Any

from era.agents.budget import AgentBudget
from era.agents.content import content_for, resolve_pack
from era.agents.memory import ShortTermMemory
from era.agents.models import Task
from era.agents.pricing import usage_stats
from era.core.llm import LLMProvider, LLMRequest, ToolCall
from era.core.result import ProviderErrorCode, ToolError

_CONTENT_PROMPT = """You generate content for a task inside a safe file-writing agent.

The user goal: {goal}
The task: {title}
The file path: {path}
Correction note (from a previous failed verification — fix it if present): {note}

Return ONLY the final file content. No explanations, no markdown fences. It must
satisfy the verification spec: {verify}"""

_TOOL_PROMPT = """You select ONE tool call for a task inside a safe agent.
Return ONLY JSON: {{"action_type": "...", "params": {{...}}}}
Available actions and their parameter shapes:
{catalog}
The task: {title}
Observations so far: {observations}
If no catalogued action fits better than the planned one, return the planned one: {planned}"""


class OfflineBrain:
    """Deterministic brain — no LLM, no cost, always available."""

    id = "offline"

    def prepare(self, task: Task, memory: ShortTermMemory) -> dict[str, Any]:
        params = dict(task.params)
        content_from = params.pop("content_from", None)
        if isinstance(content_from, str):
            params["content"] = self._render(content_from, task, memory)
        elif task.correction_note and task.action_type == "fs.write" \
                and "content" in params and "repair" not in params:
            # Re-render repairs deterministically where possible.
            pass
        return params

    def propose_tool_calls(self, task: Task, memory: ShortTermMemory,
                           prepared_params: dict[str, Any]) -> list[ToolCall]:
        return [ToolCall(id=f"{task.id}-0", action_type=task.action_type,
                         params=prepared_params)]

    # -- internals ------------------------------------------------------------
    def _render(self, content_from: str, task: Task, memory: ShortTermMemory) -> str:
        if content_from.startswith("generic:"):
            subject = content_from.partition(":")[2]
            return self._generic_report(subject, memory)
        subject = memory.recall("subject", "welding training")
        pack = resolve_pack(subject)
        try:
            content = content_for(pack, content_from)
        except KeyError:
            raise ToolError(f"offline content pack has no key {content_from!r}",
                            code=ProviderErrorCode.VALIDATION) from None
        if task.correction_note or task.params.get("repair"):
            note = task.correction_note or "repaired by the agent"
            content = f"{content}\n<!-- agent-repair: {note.replace('-->', '')} -->"
        return content

    @staticmethod
    def _generic_report(subject: str, memory: ShortTermMemory) -> str:
        lines = [f"# {subject.title()} — Report", "",
                 "Prepared by the ERA agent (offline mode).", ""]
        lines.append("## Summary")
        lines.append(f"This report covers the topic: {subject}.")
        search_notes = [
            o.get("summary", "") for o in memory.observations
            if o.get("action_type") == "web.search" and o.get("summary")
        ]
        if search_notes:
            lines.append("")
            lines.append("## Research notes")
            for note in search_notes[:5]:
                lines.append(f"- {note}")
        lines.append("")
        lines.append("## Next steps")
        lines.append("- Verify details with a live web search when connectivity is available.")
        lines.append("- Expand each section with authoritative sources.")
        return "\n".join(lines)


class LLMBrain:
    """Model-driven brain with strict output handling and offline fallback."""

    id = "llm"

    def __init__(self, llm: LLMProvider, budget: AgentBudget, max_tokens: int = 2048,
                 fallback: OfflineBrain | None = None):
        self.llm = llm
        self.budget = budget
        self.max_tokens = max_tokens
        self.fallback = fallback or OfflineBrain()
        self.model = getattr(llm, "model", None)

    def prepare(self, task: Task, memory: ShortTermMemory) -> dict[str, Any]:
        params = dict(task.params)
        content_from = params.pop("content_from", None)
        if not isinstance(content_from, str):
            return params
        if content_from.startswith("generic:"):
            return params  # deterministic report; no model needed
        prompt = _CONTENT_PROMPT.format(
            goal=memory.goal, title=task.title, path=params.get("path", ""),
            note=task.correction_note or "", verify=json.dumps(task.verify or {}),
        )
        try:
            text = self._generate_content(prompt)
            text = _strip_fences(text or "")
            if not text:
                raise ToolError("model returned empty content", code=ProviderErrorCode.PROVIDER_ERROR)
            params["content"] = text
            return params
        except ToolError:
            # Model failure -> deterministic fallback keeps the run alive.
            fallback_params = dict(task.params)
            if isinstance(fallback_params.get("content_from"), str):
                fallback_params["content"] = self.fallback._render(
                    fallback_params["content_from"], task, memory)
                fallback_params.pop("content_from", None)
            return fallback_params

    def _generate_content(self, prompt: str) -> str:
        """One bounded LLM call with budget + cost accounting."""
        reason = self.budget.can_llm_call()
        if reason is not None:
            raise ToolError(reason, code=ProviderErrorCode.UNAVAILABLE)
        response = self.llm.complete(LLMRequest(
            messages=[{"role": "user", "content": prompt}],
            model_ref="default",
            max_tokens=self.max_tokens,
        ))
        tokens, cost = usage_stats(self.model, response.usage, response.text or "")
        self.budget.record_llm_call(tokens=tokens, cost_usd=cost)
        return response.text or ""

    def propose_tool_calls(self, task: Task, memory: ShortTermMemory,
                           prepared_params: dict[str, Any]) -> list[ToolCall]:
        reason = self.budget.can_llm_call()
        if reason is not None:
            return self.fallback.propose_tool_calls(task, memory, prepared_params)
        observations = memory.observations[-6:]
        prompt = _TOOL_PROMPT.format(
            catalog=memory.recall("tool_catalog", "unknown"),
            title=task.title,
            observations=json.dumps(observations, default=str)[:3000],
            planned=json.dumps({"action_type": task.action_type, "params": prepared_params}),
        )
        try:
            response = self.llm.complete(LLMRequest(
                messages=[{"role": "user", "content": prompt}],
                model_ref="default",
                max_tokens=512,
            ))
            tokens, cost = usage_stats(self.model, response.usage, response.text or "")
            self.budget.record_llm_call(tokens=tokens, cost_usd=cost)
            doc = json.loads(_strip_fences(response.text or ""))
            action_type = str(doc.get("action_type", "")).strip()
            params = doc.get("params") if isinstance(doc.get("params"), dict) else {}
            if not action_type:
                raise ValueError("empty action_type")
            return [ToolCall(id=f"{task.id}-0", action_type=action_type, params=params)]
        except (ToolError, ValueError, TypeError, json.JSONDecodeError):
            return self.fallback.propose_tool_calls(task, memory, prepared_params)


def _strip_fences(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text
