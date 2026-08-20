"""Legacy in-memory "memory" placeholder (original scaffold behaviour).

Notes:
    Everything is lost when the process exits. Replaced by persistent SQLite
    memory with retrieval in Phase 1.
"""

from __future__ import annotations


class Memory:
    """A plain list of notes; no persistence, no retrieval."""

    def __init__(self) -> None:
        self.notes: list[str] = []

    def remember(self, text: str) -> None:
        """Append a note."""
        self.notes.append(text)

    def show(self) -> None:
        """Print all notes."""
        print("📚 Memory")
        if not self.notes:
            print("Memory Empty")
        else:
            for note in self.notes:
                print("-", note)
