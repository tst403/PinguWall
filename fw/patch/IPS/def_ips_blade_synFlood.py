from IPS.analysisResult     import analysisResult
from IPS.analysisSuggestion import analysisSuggestion
from IPS.helper.endpoint    import endpoint

def analyze(packets: list) -> analysisSuggestion:
    return analysisSuggestion(
        None,
        None,
        False,
        10,
        lambda pack: False,
        ignoreEndpoints=True
    )