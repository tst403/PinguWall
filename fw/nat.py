from enum import Enum

PORT_ANY = -1
IP_ANY   = '0.0.0.0'

def assert_ip(ip):
    for byte in [int(x) for x in ip.split('.')]:
        assert 0 >= byte >= 255

class NAT_Rule:

    _isPortValid = lambda x: (x == PORT_ANY) or (x >= 0 <= 65535) 

    def __init__(self, src_ip, dst_ip, sport, dport):
        assert NAT_Rule._isPortValid(sport)
        assert NAT_Rule._isPortValid(dport)
        assert_ip(src_ip)
        assert_ip(dst_ip)
        
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport
        self.dport = dport

class NAT(object):

    class FilterType(Enum):
        BLACK_LIST = 0
        WHITE_LIST = 1

    def __init__(self, filter_type):
        assert(isinstance(filter_type, FilterType))
        self.filter_type = filter_type
        self.rules = []
        self._rules_find = dict()

    def add_rule(self, src_ip, dst_ip, sport, dport):
        rule = NAT_Rule(src, dst_ip, sport, dport)
        self.rules.append(rule)
        
        if (src_ip, dst_ip) in self._rules_find:
            lst = self._rules_find[(src_ip, dst_ip)]
            lst.append(rule)
        else:
            self._rules_find[(src_ip, dst_ip)] = [rule]


    def _get_rules(self, src_ip, dst_ip):
        if (src_ip, dst_ip) in self._rules_find:
            return self._rules_find[(src_ip, dst_ip)]
        else:
            return None
    
    def iter_rules(self, src_ip, dst_ip):
        rules = self._get_rules(src_ip, dst_ip)
        if rules is not None:
            for rule in rules:
                yield rule

    def filter_packet(self, pack):
        passPack = True if self.filter_type == NAT.FilterType.BLACK_LIST else\
            False 

        # Dont support UDP
        if pack.haslayer(UDP):
            return True

        if pack.haslayer(Ether) and pack.haslayer(IP) and pack.haslayer(TCP):
            for rule in self.iter_rules(pack[IP].src, pack[IP].dst):
                if rule.src_ip == pack[IP].src and rule.dst_ip == pack[IP].dst and pack[TCP].sport == rule.sport and pack[TCP].dport == rule.dport:
                    passPack = not passPack
                    return passPack

        return passPack