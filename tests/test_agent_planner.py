"""RulePlanner / LLMPlanner tests (Phase 3A)."""

from __future__ import annotations

from era.agents.models import Task
from era.agents.planner import LLMPlanner, RulePlanner, _extract_subject
from era.core.llm import LLMRequest, LLMResponse
from era.core.result import ProviderErrorCode, ToolError


def test_extract_subject_variants():
    assert "welding" in _extract_subject("Make me a welding training website")
    assert "welding" in _extract_subject("मेरे लिए एक welding training website बनाओ")
    assert "photography" in _extract_subject("build a website about photography")
    assert _extract_subject("just talk to me")  # non-empty fallback


def test_rule_planner_website_plan_structure():
    plan = RulePlanner().plan("Make me a welding training website")
    ids = [t.id for t in plan.tasks]
    assert plan.created_by == "offline"
    assert "research" in ids
    assert "structure" in ids
    assert "page-index" in ids and "check-index" in ids
    assert "check-links" in ids
    for task in plan.tasks:
        assert task.action_type  # every task carries a tool
    # dependencies: page writes depend on the structure task
    index_write = next(t for t in plan.tasks if t.id == "page-index")
    assert index_write.depends_on == ["structure"]
    # verification specs present on writes and checks
    assert index_write.verify["kind"] == "file_exists"
    links = next(t for t in plan.tasks if t.id == "check-links")
    assert links.verify["kind"] == "links_resolve"


def test_rule_planner_research_is_best_effort():
    plan = RulePlanner().plan("make a welding site")
    research = next(t for t in plan.tasks if t.id == "research")
    assert research.required is False


def test_rule_planner_generic_fallback():
    plan = RulePlanner().plan("Summarize the history of tea")
    assert plan.tasks
    assert all(t.action_type for t in plan.tasks)


def test_rule_planner_recognizes_url_screenshot_before_website_builder():
    plan = RulePlanner().plan("https://example.com website ka screenshot lo")
    assert [task.action_type for task in plan.tasks] == [
        "browser.navigate", "browser.screenshot",
    ]
    assert plan.tasks[0].params["url"] == "https://example.com"
    assert plan.tasks[1].depends_on == ["browser-navigate"]
    assert plan.tasks[1].verify["kind"] == "screenshot_exists"
    assert plan.tasks[1].params["path"].endswith("example-com.png")


def test_rule_planner_recognizes_dynamic_live_data_extraction():
    plan = RulePlanner().plan("example.org website se live data nikaalo")
    assert [task.action_type for task in plan.tasks] == [
        "browser.navigate", "browser.extract_dom",
    ]
    assert plan.tasks[0].params["url"] == "https://example.org"
    assert plan.tasks[1].verify == {"kind": "dom_extracted", "min_chars": 1}


def test_plain_website_creation_still_uses_builder_not_browser():
    plan = RulePlanner().plan("build a website about photography")
    assert any(task.action_type == "fs.write" for task in plan.tasks)
    assert all(not task.action_type.startswith("browser.") for task in plan.tasks)


def test_rule_planner_repair_tasks():
    failed = Task(id="page-index", title="Write page", action_type="fs.write",
                  params={"path": "site/index.html"})
    repairs = RulePlanner().repair(failed, "missing h1")
    assert [t.id for t in repairs] == ["repair-page-index", "reverify-page-index"]
    assert repairs[0].action_type == "fs.write"
    assert repairs[1].action_type == "fs.read"
    assert repairs[1].depends_on == [repairs[0].id]


class _FakeLLM:
    def __init__(self, text):
        self._text = text

    def complete(self, req: LLMRequest) -> LLMResponse:
        return LLMResponse(text=self._text, usage={"total_tokens": 42})

    def stream(self, req):
        yield self.complete(req)


def test_llm_planner_parses_valid_json_plan():
    import json
    doc = {
        "summary": "two steps",
        "tasks": [
            {"id": "t1", "title": "one", "action_type": "fs.write",
             "params": {"path": "a.txt", "content": "x"}, "required": True,
             "depends_on": []},
            {"id": "t2", "title": "two", "action_type": "fs.read",
             "params": {"path": "a.txt"}, "verify": {"kind": "file_exists",
                                                     "path": "a.txt"},
             "depends_on": ["t1"]},
        ],
    }
    planner = LLMPlanner(_FakeLLM("```json\n" + json.dumps(doc) + "\n```"),
                         _budget(), catalog_actions=["fs.write", "fs.read"])
    plan = planner.plan("test")
    assert plan.created_by == "llm"
    assert [t.id for t in plan.tasks] == ["t1", "t2"]


def test_llm_planner_falls_back_on_garbage():
    planner = LLMPlanner(_FakeLLM("sorry, no json here"), _budget(),
                         catalog_actions=["fs.write"])
    plan = planner.plan("make me a welding website")
    assert plan.created_by == "offline"  # safe fallback


def test_llm_planner_falls_back_on_llm_error():
    class Broken:
        def complete(self, req):
            raise ToolError("down", code=ProviderErrorCode.UNAVAILABLE)

        def stream(self, req):
            yield self.complete(req)

    planner = LLMPlanner(Broken(), _budget(), catalog_actions=["fs.write"])
    plan = planner.plan("make me a welding website")
    assert plan.created_by == "offline"


def _budget():
    from era.agents.budget import AgentBudget
    return AgentBudget()
