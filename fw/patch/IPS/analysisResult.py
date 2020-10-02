class analysisResult:
    def __init__(self, suggestions=[]):
        self.suggestions = suggestions

    def insert_suggestion(self, suggestion):
        self.suggestions.append(suggestion)

    def __add__(self, oth):
        #assert type(self) == type(oth)
        return analysisResult(suggestions=self.suggestions + [oth])
