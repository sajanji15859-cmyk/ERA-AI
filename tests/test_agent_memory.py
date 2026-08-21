"""Agent memory tests (Phase 3A)."""

from __future__ import annotations

import pytest

from era.agents.memory import LongTermMemoryService, ShortTermMemory
from era.config import Settings
from era.container import build_container
from era.repositories.sqlite import SQLiteMemoryRepo


def test_short_term_memory_basics():
    mem = ShortTermMemory(goal="g")
    mem.remember("subject", "welding")
    assert mem.recall("subject") == "welding"
    assert mem.recall("missing", "dflt") == "dflt"
    mem.record_observation({"task_id": "a", "status": "executed"})
    mem.record_artifact("site/index.html")
    assert mem.artifacts == ["site/index.html"]
    assert mem.observations[0]["status"] == "executed"


def test_short_term_rebuild_from_tasks():
    from era.agents.models import Task
    task = Task(id="a", title="a", action_type="fs.write",
                observations=[{"task_id": "a", "status": "executed"}])
    mem = ShortTermMemory(goal="g")
    mem.rebuild_from_tasks([task])
    assert mem.observations[0]["status"] == "executed"


@pytest.fixture
def long_term(tmp_path):
    container = build_container(Settings(database_url=f"sqlite:///{tmp_path}/m.db"))
    yield LongTermMemoryService(container.session_factory, SQLiteMemoryRepo())
    container.engine.dispose()


def test_long_term_put_get_update_delete(long_term):
    long_term.put("actor-1", "ns", "k1", {"a": 1})
    assert long_term.get("actor-1", "ns", "k1") == {"a": 1}
    long_term.put("actor-1", "ns", "k1", {"a": 2})  # update
    assert long_term.get("actor-1", "ns", "k1") == {"a": 2}
    assert long_term.get("actor-2", "ns", "k1") is None  # actor isolation
    assert long_term.list_namespace("actor-1", "ns") == {"k1": {"a": 2}}
    assert long_term.delete("actor-1", "ns", "k1") is True
    assert long_term.get("actor-1", "ns", "k1") is None
    assert long_term.delete("actor-1", "ns", "k1") is False


def test_long_term_rejects_bad_keys_and_oversize(long_term):
    with pytest.raises(ValueError):
        long_term.put("actor-1", "ns", "", "v")
    with pytest.raises(ValueError):
        long_term.put("actor-1", "ns", "k", "x" * 300_000)


def test_long_term_namespace_cap(long_term):
    from era.agents.memory import MAX_ENTRIES_PER_NAMESPACE
    for i in range(MAX_ENTRIES_PER_NAMESPACE):
        long_term.put("actor-1", "full", f"k{i}", i)
    with pytest.raises(ValueError):
        long_term.put("actor-1", "full", "overflow", 1)
