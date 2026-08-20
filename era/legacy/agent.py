"""Legacy agent placeholder: a blocking REPL over the legacy keyword chat.

Fixes vs. the original scaffold: the original ``agent.py`` defined the class
``ERAAI`` twice — the second definition silently shadowed the first, leaving
the Brain/Memory/Research composition as dead code. This single class wires
everything together the way the first definition intended.

Replaced by the real execution loop in Phase 1.
"""

from __future__ import annotations

from era.legacy.brain import Brain
from era.legacy.chat import Chat
from era.legacy.memory import Memory
from era.legacy.research import Research


class ERAAI:
    """Composes the legacy placeholders and runs a chat REPL."""

    def __init__(self) -> None:
        self.brain = Brain()
        self.memory = Memory()
        self.research = Research()
        self.chat = Chat()

    def start(self) -> None:
        """Run the interactive loop until the user types 'exit'."""
        print("🤖 ERA AI Started (legacy keyword mode)")
        print("Type 'exit' to quit")
        while True:
            try:
                user = input("You: ")
            except EOFError:
                print("👋 Goodbye!")
                break
            if user.strip().lower() == "exit":
                print("👋 Goodbye!")
                break
            print("ERA AI:", self.chat.reply(user))
