"""Legacy "research" placeholder: a hardcoded fact dictionary (original scaffold).

Replaced by the web tool family (fetch/search) in Phase 1.
"""

from __future__ import annotations


class Research:
    """Exact-match lookup against a tiny hardcoded database; no network."""

    def __init__(self) -> None:
        self.database: dict[str, str] = {
            "tesla": "Nikola Tesla was a brilliant inventor.",
            "history": "History studies past human civilization.",
            "science": "Science explains nature using evidence.",
            "ai": "Artificial Intelligence enables machines to learn.",
            "taj mahal": "The Taj Mahal was built by Shah Jahan.",
        }

    def search(self, topic: str) -> str:
        """Return the fact for ``topic`` (case-insensitive) or a not-found message."""
        return self.database.get(topic.strip().lower(), "Information not found.")
