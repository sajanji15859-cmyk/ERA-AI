from brain import Brain
from memory import Memory
from research import Research


class ERAAI:

    def __init__(self):
        self.brain = Brain()
        self.memory = Memory()
        self.research = Research()

    def start(self):
        print("🚀 ERA AI Started Successfully")
        print("🧠 Brain Loaded")
        print("💾 Memory Loaded")
        print("📚 Research Loaded")

from chat import Chat

class ERAAI:

    def __init__(self):
        self.chat = Chat()

    def start(self):
        print("🤖 ERA AI Started")
        print("Type 'exit' to quit")

        while True:
            user = input("You: ")

            if user.lower() == "exit":
                print("👋 Goodbye!")
                break

            reply = self.chat.reply(user)
            print("ERA AI:", reply)
