print("================================")
print("        ERA AI v0.1")
print("================================")
print("System Starting...")
print("Brain Loaded")
print("Memory Loaded")
print("Research Loaded")
print("Logger Loaded")
print("ERA AI Ready")


from brain import Brain
from memory import Memory

def main():
    print("🚀 ERA AI Starting...\n")

    brain = Brain()
    brain.status()

    print("\n-----------------\n")

    memory = Memory()
    memory.remember("सरफराज ERA AI बना रहा है")
    memory.remember("ERA AI Professional Project")

    memory.show()

if __name__ == "__main__":
    main()

from agent import ERAAI

app = ERAAI()
app.start()
