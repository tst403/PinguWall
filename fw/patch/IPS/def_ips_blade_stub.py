'''
+----------------------------------------------------------------------------+
|                           Blade Stub module                                |
+----------------------------------------------------------------------------+

Input   :   This module has a primary function that takes a PACKETS LIST. The
            module gets it's data from IPS module from the WATCH obtained by
            the NAT sniffing procedure.

Process :   The module may use any on the packets to analyze them it may store
            them for further analysis if it requires more data to analyze. It
            runs on the PACKETS LIST and gives the liklihood that the target
            attack is occuring and based on the data it suggests filters to
            the FIREWALL to prevent the attacker

Output  :   The module provides an analysisSuggestion that can be combined
            with others to create an analysisResult to change the FIREWALL
            policy

------------------------------------------------------------------------------
'''


from analysisResult     import analysisResult
from analysisSuggestion import analysisSuggestion
from helper.endpoint    import endpoint


def analyze(packets: list) -> analysisSuggestion:
    if len(packets) > 1:
        return analysisSuggestion(
            endpoint(endpoint.ANY, endpoint.ANY),
            endpoint(endpoint.ANY, endpoint.ANY),
            False,
            100,
            lambda pack: True
        )
