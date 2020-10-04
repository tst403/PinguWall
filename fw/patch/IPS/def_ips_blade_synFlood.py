from analysisResult     import analysisResult
from analysisSuggestion import analysisSuggestion
from helper.endpoint    import endpoint

def analyze(packets: list) -> analysisSuggestion:
    return analysisSuggestion(
        None,
        None,
        False,
        10,
        lambda pack: False,
        ignoreEndpoints=True
    )