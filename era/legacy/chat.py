"""Legacy keyword chat placeholder (original scaffold, bug-fixed).

Fixes vs. the original: matching now uses word boundaries. The old substring
check (``"ai" in message``) made any message containing the letters "ai" —
e.g. "email", "wait", "gmail" — trigger the AI canned response.

Replaced by the LLM conversation manager in Phase 1.
"""

from __future__ import annotations

import re

_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\btesla\b", re.IGNORECASE), "⚡ Nikola Tesla एक महान आविष्कारक थे।"),
    (re.compile(r"\btaj\s+mahal\b", re.IGNORECASE), "🕌 ताजमहल का निर्माण शाहजहाँ ने करवाया था।"),
    (re.compile(r"\bhistory\b", re.IGNORECASE), "📚 इतिहास मानव सभ्यता का अध्ययन है।"),
    (re.compile(r"\bscience\b", re.IGNORECASE), "🔬 विज्ञान प्रमाण और प्रयोग पर आधारित है।"),
    (
        re.compile(r"\bai\b", re.IGNORECASE),
        "🤖 Artificial Intelligence मशीनों को सीखने की क्षमता देता है।",
    ),
)

_FALLBACK = "❌ अभी मैं इस विषय को नहीं जानता।"


class Chat:
    """Keyword-matching chat with canned bilingual replies; no state."""

    def reply(self, message: str) -> str:
        """Return the canned reply whose keyword appears in ``message``."""
        for pattern, response in _RULES:
            if pattern.search(message):
                return response
        return _FALLBACK
