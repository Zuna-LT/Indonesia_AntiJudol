from utils.constants import KEYWORDS

class SpamDetector:
    @staticmethod
    def detect_spam(comments):
        spam_indices = []
        for i, (_, text, _) in enumerate(comments):
            if any(kw in text.lower() for kw in KEYWORDS):
                spam_indices.append(i)
        return spam_indices