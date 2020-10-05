from scapy.all import *
from IPS.helper.endpoint import endpoint

class analysisSuggestion:
    def __init__(self, epSource, epDestination, bidirectional, sevirity, blockFunction, ignoreEndpoints=False):
        self.ignoreEndpoints = ignoreEndpoints

        if not self.ignoreEndpoints:
            self.epSource = epSource
            self.epSource.assert_valid()

            self.epDestination = epDestination
            self.epDestination.assert_valid()

            self.bidirectional = bidirectional
        
        self.sevirity = sevirity 
        self.blockFunction = blockFunction

    def convert_static_filters(self):
        has_ip    = lambda pack: pack.haslayer(IP)
        has_ether = lambda pack: pack.haslayer(Ether)
        has_tcp   = lambda pack: pack.haslayer(TCP)

        block_by_ip_src   = lambda pack: (pack[IP] .src   == self.epSource.ip               ) if self.epSource.ip        != endpoint.ANY else True
        block_by_ip_dst   = lambda pack: (pack[IP] .dst   == self.epDestination.ip          ) if self.epDestination.ip   != endpoint.ANY else True
        block_by_port_src = lambda pack: (pack[TCP].sport == self.self.epSource.port        ) if self.epSource.port      != endpoint.ANY else True
        block_by_port_dst = lambda pack: (pack[TCP].dport == self.self.epDestination.port   ) if self.epDestination.port != endpoint.ANY else True

        return lambda pack: has_tcp(pack) and block_by_port_dst(pack) and block_by_port_src(pack) and has_ip(pack) and block_by_ip_src(pack) and block_by_ip_dst(pack) and has_ether(pack)

    def export_function(self):
        if self.ignoreEndpoints:
            return self.blockFunction

        def func(pack):
            f1 = self.convert_static_filters()
            f2 = self.blockFunction

            return f1(pack) and f2(pack)

        return func
