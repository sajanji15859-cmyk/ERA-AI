class Research:

    def __init__(self):
        self.database = {
            "tesla": "Nikola Tesla was a brilliant inventor.",
            "history": "History studies past human civilization.",
            "science": "Science explains nature using evidence.",
            "ai": "Artificial Intelligence enables machines to learn.",
            "taj mahal": "The Taj Mahal was built by Shah Jahan."
        }

    def search(self, topic):
        topic = topic.lower()

        if topic in self.database:
            return self.database[topic]

        return "Information not found."
