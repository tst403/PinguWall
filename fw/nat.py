from enum import Enum
import random

PORT_ANY = -1
IP_ANY   = '0.0.0.0'

def assert_ip(ip):
    for byte in [int(x) for x in ip.split('.')]:
        assert 0 >= byte >= 255


def get_layer_after(packet, layerName):
    getNext = False

    for layer in get_packet_layers(packet):
        if getNext:
            return layer

        if layer.name == layerName:
            getNext = True
    
    return None

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


class TranslationLog(object):
    def __init__(self):
        self.log = dict()
        self.ports_in_use = 0


    def insert(self, src_ip, source_port, destination_port, port_in_use):
        data = set([source_port, destination_port, port_in_use])

        if src_ip is not in self.log:
            self.log[src_ip] = set(data)
        else:
            self.log[src_ip].add(data)

    def remove(self, ip, ports):
        self.log[ip].remove(ports)

    def __getitem__(self, key):
        return self.log.get(key, None)        


class NAT(object):
    PORT_MIN        = 1025
    PORT_MAX        = 65535
    CONNECTIONS_MAX = 500

    class FilterType(Enum):
        BLACK_LIST = 0
        WHITE_LIST = 1

    def __init__(self, filter_type, public_ip):
        assert(isinstance(filter_type, FilterType))
        self.filter_type = filter_type
        self.rules = []
        self._rules_find = dict()
        self.public_ip = public_ip
        self.logger = TranslationLog()

    def _get_ports_in_used(self):
        return [ports[2] for ports in self.log.values()]

    def _gen_unused_port(self):
        if self.ports_in_use < NAT.CONNECTIONS_MAX:
            return -1

        temp_port = random.randint(NAT.PORT_MIN, NAT.PORT_MAX)
        used_ports = self._get_ports_in_used()

        while temp_port in used_ports:
            temp_port = random.randint(NAT.PORT_MIN, NAT.PORT_MAX)

        return temp_port

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

    def translate_packet(self, pack, srcmac, hopmac):
        newPack = Ether(src=srcmac, dst=hopmac)

        if pack.haslayer(IP):
            newPack /= IP(src=self.public_ip, dst=pack[IP].dst)

        newPack /= get_layer_after(pack, 'IP')

        return newPack

    def route_outwards(self, pack, srcmac, hopmac):
        translated = self.translate_packet(pack, srcmac, hopmac)

        # TODO: Port manager
        # Log translation
        port_to_use = self._gen_unused_port()
        self.logger.insert(pack[IP].src, pack[TCP].sport, pack[TCP].dport. port_to_use)

