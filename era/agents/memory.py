"""Agent memory (Phase 3A).

Two layers:

* :class:`ShortTermMemory` — per-run working memory: observations, facts,
  artifacts. Ephemeral (survives a pause/resume through the persisted run
  record, not across runs).
* :class:`LongTermMemoryService` — per-actor, persistent key/value knowledge
  (SQLite), so later runs can reuse facts without re-researching. Values are
  JSON, size-capped, and never contain credentials (the agent layer never sees
  raw secrets — it holds only opaque references).
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from era.core.util import utcnow_iso
from era.repositories.base import MemoryRepo

MAX_SHORT_TERM_OBSERVATIONS = 200
MAX_SHORT_TERM_FACTS = 500
MAX_FACT_VALUE_CHARS = 20_000
MAX_ENTRIES_PER_NAMESPACE = 200


class ShortTermMemory:
    """Working memory for a single run."""

    def __init__(self, goal: str):
        self.goal = goal
        self.facts: dict[str, Any] = {}
        self.observations: list[dict[str, Any]] = []
        self.artifacts: list[str] = []

    def remember(self, key: str, value: Any) -> None:
        if len(self.facts) >= MAX_SHORT_TERM_FACTS and key not in self.facts:
            return
        if isinstance(value, str) and len(value) > MAX_FACT_VALUE_CHARS:
            value = value[:MAX_FACT_VALUE_CHARS] + "…"
        self.facts[key] = value

    def recall(self, key: str, default: Any = None) -> Any:
        return self.facts.get(key, default)

    def record_observation(self, observation: dict[str, Any]) -> None:
        self.observations.append(observation)
        if len(self.observations) > MAX_SHORT_TERM_OBSERVATIONS:
            self.observations = self.observations[-MAX_SHORT_TERM_OBSERVATIONS:]

    def record_artifact(self, artifact: str) -> None:
        if artifact not in self.artifacts:
            self.artifacts.append(artifact)

    def rebuild_from_tasks(self, tasks: list[Any]) -> None:
        """Rehydrate working memory from persisted tasks after a resume."""
        for task in tasks:
            for obs in getattr(task, "observations", []) or []:
                self.record_observation(obs)


class LongTermMemoryService:
    """Persistent per-actor knowledge store (exact-key; no vector search in 3A)."""

    def __init__(self, session_factory, memory_repo: MemoryRepo):
        self.session_factory = session_factory
        self.memory_repo = memory_repo

    def put(self, actor_id: str, namespace: str, key: str, value: Any) -> None:
        key = self._validate_key(key)
        if not namespace or len(namespace) > 128:
            raise ValueError("namespace must be a short non-empty string")
        blob = json.dumps(value, default=str)
        if len(blob) > 256_000:
            raise ValueError("memory value too large")
        from era.models.agent import MemoryEntry  # local import avoids model churn
        with self.session_factory() as session:
            existing = self.memory_repo.get(session, actor_id, namespace, key)
            if existing is not None:
                existing.value_json = value
                existing.updated_at = utcnow_iso()
                self.memory_repo.update(session, existing)
            else:
                count = len(self.memory_repo.list_namespace(session, actor_id, namespace))
                if count >= MAX_ENTRIES_PER_NAMESPACE:
                    raise ValueError("memory namespace full")
                entry = MemoryEntry(
                    id=uuid.uuid4().hex,
                    actor_id=actor_id,
                    namespace=namespace,
                    key=key,
                    value_json=value,
                    updated_at=utcnow_iso(),
                )
                self.memory_repo.create(session, entry)
            session.commit()

    def get(self, actor_id: str, namespace: str, key: str) -> Any:
        with self.session_factory() as session:
            entry = self.memory_repo.get(session, actor_id, namespace, key)
            return entry.value_json if entry is not None else None

    def list_namespace(self, actor_id: str, namespace: str) -> dict[str, Any]:
        with self.session_factory() as session:
            entries = self.memory_repo.list_namespace(session, actor_id, namespace)
            return {e.key: e.value_json for e in entries}

    def delete(self, actor_id: str, namespace: str, key: str) -> bool:
        with self.session_factory() as session:
            removed = self.memory_repo.delete(session, actor_id, namespace, key)
            session.commit()
            return removed

    @staticmethod
    def _validate_key(key: str) -> str:
        if not isinstance(key, str) or not key or len(key) > 128:
            raise ValueError("key must be a short non-empty string")
        return key
