class Chat:

    def reply(self, message):

        message = message.lower()

        if "tesla" in message:
            return "⚡ Nikola Tesla एक महान आविष्कारक थे।"

        elif "taj mahal" in message:
            return "🕌 ताजमहल का निर्माण शाहजहाँ ने करवाया था।"

        elif "history" in message:
            return "📚 इतिहास मानव सभ्यता का अध्ययन है।"

        elif "science" in message:
            return "🔬 विज्ञान प्रमाण और प्रयोग पर आधारित है।"

        elif "ai" in message:
            return "🤖 Artificial Intelligence मशीनों को सीखने की क्षमता देता है।"

        else:
            return "❌ अभी मैं इस विषय को नहीं जानता।"
