class Brain:
    def __init__(self):
        self.name = "ERA AI Brain"
        self.version = "0.1"

        self.skills = [
            "Research",
            "Memory",
            "Reasoning",
            "Science",
            "History",
            "AI"
        ]

    def status(self):
        print("🧠", self.name)
        print("Version:", self.version)
        print("\nSkills:")

        for skill in self.skills:
            print("✔", skill)
