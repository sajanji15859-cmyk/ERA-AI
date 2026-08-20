"""Legacy placeholder modules from the original v0.1 scaffold.

These are kept working (with their bugs fixed) until the corresponding real
subsystems land in later phases, per the Phase 0 plan:

- ``brain``    -> replaced by the planner/LLM layer (Phase 1)
- ``chat``     -> replaced by the LLM conversation manager (Phase 1)
- ``memory``   -> replaced by persistent SQLite memory (Phase 1)
- ``research`` -> replaced by the web tool family (Phase 1)
- ``agent``    -> replaced by the real execution loop (Phase 1)
"""

from __future__ import annotations

from era.legacy.agent import ERAAI
from era.legacy.brain import Brain
from era.legacy.chat import Chat
from era.legacy.memory import Memory
from era.legacy.research import Research

__all__ = ["ERAAI", "Brain", "Chat", "Memory", "Research"]
