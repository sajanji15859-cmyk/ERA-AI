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
