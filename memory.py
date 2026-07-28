class Memory:
    def __init__(self):
        self.notes = []

    def remember(self, text):
        self.notes.append(text)

    def show(self):
        print("📚 Memory")

        if len(self.notes) == 0:
            print("Memory Empty")
        else:
            for note in self.notes:
                print("-", note)
