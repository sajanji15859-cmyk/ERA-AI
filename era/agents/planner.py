"""Planner — decomposes the user goal into an actionable task plan (Phase 3A).

Two implementations:

* :class:`RulePlanner` — deterministic, offline, free. Understands a small set
  of goal patterns (currently: "build a website about X" and a generic
  research-and-report fallback). Used always as the fallback, and standalone
  when no LLM is configured.
* :class:`LLMPlanner` — asks a real model (via ``LLMProvider``) for a JSON
  plan, validates it strictly against the task schema, and falls back to the
  RulePlanner on any error (bounded by the budget's LLM-call cap).

Every planned task's ``action_type`` must be catalogued — the permission engine
DENYs unknown types, so the planner can never invent new capabilities.
"""

from __future__ import annotations

import re
from typing import Any

from era.agents.budget import AgentBudget
from era.agents.content import resolve_pack
from era.agents.models import Plan, Task
from era.core.llm import LLMProvider, LLMRequest
from era.core.result import ProviderErrorCode, ToolError

TASK_ID_RE = re.compile(r"^[a-z0-9_\-]{1,64}$")

_PLAN_PROMPT = """You are the planner of a safe, tool-using agent. Return ONLY a JSON object:
{"summary": "...", "tasks": [{"id": "...", "title": "...", "action_type": "...", "params": {...}, "verify": {...} | null, "required": true | false, "depends_on": []}]}

Rules:
- action_type MUST be one of the catalogued actions listed below (never invent one).
- fs.write/fs.read/fs.list take params {"path": "..."}; fs.write also takes {"content": "..."}.
- web.search takes {"q": "..."}.
- Prefer writing files into a directory named after the topic.
- Keep the plan under 15 tasks. Make destructive or risky steps "required": false unless essential.
- verify spec kinds: action_success, file_exists {"path","min_bytes"}, text_contains {"path","required":[...]},
  html_valid {"path","required_elements":[...],"keywords":[...]}, links_resolve {"pages":[...]}.
Catalogued actions: {actions}"""


def _slugify(subject: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in subject.lower()).strip("_") or "site"


def _extract_subject(goal: str) -> str:
    """Extract the topic from goals like "make me a welding training website"
    or "build a website about photography"."""
    lowered = goal.lower()
    for marker in ("website", "web site", "site"):
        index = lowered.find(marker)
        if index < 0:
            continue
        # "a website about photography" → subject is the tail
        tail = lowered[index + len(marker):]
        match = re.search(r"\s*(?:about|for|on)\s+(.+)", tail)
        if match:
            subject = match.group(1)
        else:
            subject = lowered[:index]
        subject = re.sub(
            r"^(please\s+)?(make|build|create|design|develop)\s+(me\s+)?(a|an|the)?\s*",
            "", subject)
        subject = re.sub(r"^(for|about|on)\s+", "", subject)
        subject = _drop_leading_filler(subject)
        subject = subject.strip(" .,!?;:'\"").strip()
        return subject or "topic"
    return goal.strip().strip(".!?") or "topic"


def _drop_leading_filler(text: str) -> str:
    """Drop leading non-ASCII filler words from Hinglish goals
    (e.g. "मेरे लिए एक welding training" → "welding training")."""
    words = text.split()
    index = 0
    while index < len(words) and not re.search(r"[a-z0-9]", words[index]):
        index += 1
    if 0 < index < len(words):
        return " ".join(words[index:])
    return text


class RulePlanner:
    """Deterministic offline planner (no LLM, no cost)."""

    id = "rule"

    def plan(self, goal: str) -> Plan:
        lowered = goal.lower()
        if "website" in lowered or "web site" in lowered or " site" in lowered:
            return self._website_plan(goal)
        return self._generic_plan(goal)

    def repair(self, failed: Task, reason: str) -> list[Task]:
        """Repair tasks for a failed task (one bounded replan)."""
        if failed.action_type == "fs.write":
            fix = Task(
                id=f"repair-{failed.id}",
                title=f"Repair: {failed.title}",
                action_type="fs.write",
                params={**failed.params, "repair": True},
                verify=failed.verify,
                correction_note=reason,
                required=failed.required,
            )
            reverify = Task(
                id=f"reverify-{failed.id}",
                title=f"Re-verify: {failed.title}",
                action_type="fs.read",
                params={"path": failed.params.get("path", "")},
                verify=failed.verify,
                depends_on=[fix.id],
                required=failed.required,
            )
            return [fix, reverify]
        return []

    # -- patterns -------------------------------------------------------------
    def _website_plan(self, goal: str) -> Plan:
        subject = _extract_subject(goal)
        pack = resolve_pack(subject)
        site_dir = pack["slug"]
        pages = list(pack["pages"].keys())
        nav_pages = list(pack["pages"].keys())

        tasks: list[Task] = [
            Task(
                id="research",
                title=f"Research: gather information about {subject}",
                action_type="web.search",
                params={"q": subject},
                required=False,
            ),
            Task(
                id="structure",
                title="Create site structure (README)",
                action_type="fs.write",
                params={"path": f"{site_dir}/README.md", "content_from": f"{site_dir}:readme"},
                verify={"kind": "file_exists", "path": f"{site_dir}/README.md", "min_bytes": 50},
            ),
        ]
        for page in pages:
            page_stem = page.replace(".html", "")
            write = Task(
                id=f"page-{page_stem}",
                title=f"Write page: {page}",
                action_type="fs.write",
                params={"path": f"{site_dir}/{page}", "content_from": f"{site_dir}:{page}"},
                verify={"kind": "file_exists", "path": f"{site_dir}/{page}", "min_bytes": 200},
                depends_on=["structure"],
            )
            check = Task(
                id=f"check-{page_stem}",
                title=f"Verify page: {page}",
                action_type="fs.read",
                params={"path": f"{site_dir}/{page}"},
                verify={
                    "kind": "html_valid",
                    "path": f"{site_dir}/{page}",
                    "required_elements": ["title", "h1", "nav", "section", "footer"],
                    # Keywords that MUST appear in the rendered page: the
                    # subject word and the page's own nav label (both are
                    # always present in a correctly rendered page).
                    "keywords": [kw for kw in {
                        _extract_keyword(subject), _nav_label(pack, page),
                    } if kw],
                },
                depends_on=[write.id],
            )
            tasks.append(write)
            tasks.append(check)
        tasks.append(Task(
            id="assets-style",
            title="Write stylesheet",
            action_type="fs.write",
            params={"path": f"{site_dir}/assets/style.css", "content_from": f"{site_dir}:style.css"},
            verify={"kind": "file_exists", "path": f"{site_dir}/assets/style.css", "min_bytes": 100},
            depends_on=["structure"],
        ))
        tasks.append(Task(
            id="assets-script",
            title="Write client script",
            action_type="fs.write",
            params={"path": f"{site_dir}/assets/app.js", "content_from": f"{site_dir}:app.js"},
            verify={"kind": "file_exists", "path": f"{site_dir}/assets/app.js", "min_bytes": 50},
            depends_on=["structure"],
        ))
        tasks.append(Task(
            id="check-links",
            title="Verify all internal links resolve",
            action_type="fs.read",
            params={"path": f"{site_dir}/index.html"},
            verify={"kind": "links_resolve", "pages": [f"{site_dir}/{p}" for p in nav_pages]},
            depends_on=[f"page-{p.replace('.html', '')}" for p in pages],
        ))
        return Plan(
            goal=goal,
            summary=f"Build a static, mobile-first website about {subject} "
                    f"({len(pages)} pages + CSS + JS), then verify structure, HTML and links.",
            tasks=tasks,
            created_by="offline",
        )

    def _generic_plan(self, goal: str) -> Plan:
        subject = _extract_subject(goal)
        slug = _slugify(subject)
        return Plan(
            goal=goal,
            summary=f"Research {subject}, write a structured report, and verify it.",
            tasks=[
                Task(id="research", title=f"Research: {subject}",
                     action_type="web.search", params={"q": subject}, required=False),
                Task(id="report", title="Write report",
                     action_type="fs.write",
                     params={"path": f"reports/{slug}.md", "content_from": f"generic:{subject}"},
                     verify={"kind": "text_contains", "path": f"reports/{slug}.md",
                             "required": [subject]},
                     depends_on=["research"]),
                Task(id="verify-report", title="Verify report",
                     action_type="fs.read", params={"path": f"reports/{slug}.md"},
                     verify={"kind": "file_exists", "path": f"reports/{slug}.md", "min_bytes": 50},
                     depends_on=["report"]),
            ],
            created_by="offline",
        )


def _extract_keyword(subject: str) -> str:
    """First ASCII word of the subject (a keyword guaranteed in the content)."""
    words = [w for w in subject.split() if re.search(r"[a-zA-Z0-9]", w)]
    if words:
        return words[0]
    return subject.split()[0] if subject else "training"


def _nav_label(pack: dict[str, Any], page: str) -> str:
    """The nav label of ``page`` — always rendered into the page's nav bar."""
    page_doc = pack.get("pages", {}).get(page, {})
    for href, label in page_doc.get("nav", []):
        if href == page:
            return label
    return ""


class LLMPlanner:
    """Model-driven planner with strict validation and offline fallback."""

    id = "llm"

    def __init__(self, llm: LLMProvider, budget: AgentBudget, fallback: RulePlanner | None = None,
                 catalog_actions: list[str] | None = None):
        self.llm = llm
        self.budget = budget
        self.fallback = fallback or RulePlanner()
        self.catalog_actions = catalog_actions or []

    def plan(self, goal: str) -> Plan:
        reason = self.budget.can_llm_call()
        if reason is not None:
            raise ToolError(reason, code=ProviderErrorCode.UNAVAILABLE)
        try:
            # NOTE: `.replace`, not `.format` — the prompt template contains
            # literal JSON braces that would break str.format.
            prompt = _PLAN_PROMPT.replace("{actions}", ", ".join(sorted(self.catalog_actions)))
            response = self.llm.complete(LLMRequest(
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": goal},
                ],
                model_ref="default",
            ))
            self.budget.record_llm_call(tokens=_usage_tokens(response.usage))
            plan = self._parse_plan(response.text, goal)
            return plan
        except (ToolError, ValueError, KeyError, TypeError):
            # Any model failure falls back to the deterministic planner.
            return self.fallback.plan(goal)

    def repair(self, failed: Task, reason: str) -> list[Task]:
        return self.fallback.repair(failed, reason)

    @staticmethod
    def _parse_plan(text: str, goal: str) -> Plan:
        import json

        text = (text or "").strip()
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("no JSON object in model output")
        doc = json.loads(text[start:end + 1])
        if not isinstance(doc, dict) or not isinstance(doc.get("tasks"), list):
            raise ValueError("malformed plan")  # noqa: TRY004 — content error
        tasks: list[Task] = []
        seen: set[str] = set()
        for raw in doc["tasks"]:
            if not isinstance(raw, dict):
                raise ValueError("malformed task")  # noqa: TRY004 — content error
            task = Task(
                id=str(raw.get("id", "")).strip(),
                title=str(raw.get("title", ""))[:200],
                action_type=str(raw.get("action_type", "")).strip(),
                params=raw.get("params") if isinstance(raw.get("params"), dict) else {},
                verify=raw.get("verify") if isinstance(raw.get("verify"), dict) else None,
                required=bool(raw.get("required", True)),
                depends_on=[str(d) for d in raw.get("depends_on", [])],
            )
            if not TASK_ID_RE.match(task.id) or task.id in seen:
                raise ValueError("invalid/duplicate task id")
            seen.add(task.id)
            tasks.append(task)
        if not tasks:
            raise ValueError("empty task list")
        return Plan(goal=goal, summary=str(doc.get("summary", ""))[:500],
                    tasks=tasks, created_by="llm")


def _usage_tokens(usage: dict[str, Any] | None) -> int:
    if not usage:
        return 0
    try:
        return int(usage.get("total_tokens", 0))
    except (TypeError, ValueError):
        return 0
