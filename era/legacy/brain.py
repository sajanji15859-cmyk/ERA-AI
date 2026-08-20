"""Legacy "brain" placeholder: a static skill list (original scaffold behaviour).

Replaced by the planner/LLM layer in Phase 1.
"""

from __future__ import annotations


class Brain:
    """Static placeholder — prints a skill list; no logic."""

    def __init__(self) -> None:
        self.name = "ERA AI Brain"
        self.version = "0.1"
        self.skills = ["Research", "Memory", "Reasoning", "Science", "History", "AI"]

    def status(self) -> None:
        """Print a status summary (kept for backwards compatibility)."""
        print(f"🧠 {self.name}")
        print("Version:", self.version)
        print("\nSkills:")
        for skill in self.skills:
            print("✔", skill)
