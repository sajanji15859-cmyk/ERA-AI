"""TaskManager state-machine tests (Phase 3A)."""

from __future__ import annotations

from era.agents.models import Task, TaskStatus
from era.agents.task_manager import TaskManager


def _task(tid, **kw):
    return Task(id=tid, title=tid, action_type="stub.noop", **kw)


def test_happy_path_transitions():
    tm = TaskManager([_task("a"), _task("b")])
    t = tm.next_ready()
    assert t.id == "a"
    tm.mark_running(t)
    assert t.status is TaskStatus.RUNNING
    tm.complete(t)
    assert t.status is TaskStatus.COMPLETED
    assert tm.next_ready().id == "b"


def test_dependency_order_and_skip_on_failed_dep():
    tm = TaskManager([
        _task("base"), _task("child", depends_on=["base"]),
        _task("other", depends_on=["missing-dep"]),
    ])
    base = tm.next_ready()
    assert base.id == "base"
    tm.fail(base, "boom")
    # "child" is blocked (dep failed); "other" too (unknown dep can never be
    # satisfied — fail closed, no silent deadlock).
    blocked = {t.id for t in tm.blocked_pending()}
    assert blocked == {"child", "other"}
    for dead in tm.blocked_pending():
        tm.skip(dead, "dependency failed or unknown")
    assert not tm.has_pending()
    assert tm.next_ready() is None


def test_retry_bounded_by_max_attempts():
    task = _task("a", max_attempts=3)
    tm = TaskManager([task])
    assert tm.retry_allowed(task)
    assert tm.retry(task, "fix 1") and task.attempt == 1
    assert task.status is TaskStatus.PENDING
    assert tm.retry_allowed(task)
    assert tm.retry(task, "fix 2") and task.attempt == 2
    assert not tm.retry_allowed(task)  # cap reached: attempt+1 == max_attempts
    assert task.correction_note == "fix 2"


def test_pause_and_resolve_for_user():
    task = _task("a")
    tm = TaskManager([task])
    tm.pause_for_user(task, "conf-1")
    assert task.status is TaskStatus.WAITING_FOR_USER
    assert tm.waiting() == [task]
    tm.resolve_wait(task, "executed")
    assert task.status is TaskStatus.COMPLETED
    tm2 = TaskManager([_task("b")])
    t2 = tm2.next_ready()
    tm2.pause_for_user(t2, "conf-2")
    tm2.resolve_wait(t2, "denied", "operator said no")
    assert t2.status is TaskStatus.FAILED


def test_counts_and_snapshot():
    tm = TaskManager([_task("a"), _task("b")])
    assert tm.counts()[TaskStatus.PENDING.value] == 2
    snapshot = tm.snapshot()
    assert len(snapshot) == 2
    snapshot[0].status = TaskStatus.COMPLETED  # copies are independent
    assert tm.get("a").status is TaskStatus.PENDING


def test_add_ignores_duplicate_ids():
    tm = TaskManager([_task("a")])
    tm.add(_task("a"))
    assert len(tm.snapshot()) == 1
    tm.add(_task("b"))
    assert len(tm.snapshot()) == 2
