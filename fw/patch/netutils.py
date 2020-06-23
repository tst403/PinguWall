from scapy.all import *
import os

class ARPHandler:
    __ARP_TABLE_PATH = '/proc/net/arp'
    macs = dict()

    @staticmethod
    def __ping_host(ip):
        IPPool.assert_address(ip, True)
        os.system('ping -c 1 -W 1 {0}')

    @staticmethod
    def update_macs():
        ARPHandler.macs = dict()

        fix_line = lambda line: ' '.join(line.split())

        with open(ARPHandler.__ARP_TABLE_PATH, 'r') as f:
            data = f.read()

        lines = data.split('\n')
        lines = [fix_line(line) for line in lines][1:]

        entries = [x.split() for x in lines]
        for entry in entries:
            ARPHandler.macs[entry[0]] = entry[3]

    @staticmethod
    def obtain_mac(ip, retry=True):
        if ip in ARPHandler.macs:
            mac = ARPHandler.macs[ip]
            return mac
        else:
            if retry:
                ARPHandler.__ping_host(ip)
                ARPHandler.update_macs()
                obtain_mac(ip, False)
            else:
                return None


# noinspection SpellCheckingInspection
class IPPool:
    @staticmethod
    def __convert_address_to_list(address):
        return [int(x) for x in address.split('.')]

    @staticmethod
    def __mask_address(address, mask):
        return [mask[i] & address[i] for i in range(len(mask))]

    @staticmethod
    def assert_address(address, convert=False):
        lst = address

        if convert:
            lst = IPPool.__convert_address_to_list(lst)

        assert all(0 <= x <= 255 for x in lst)

    @staticmethod
    def get_min_ip(ip, netmask):
        masks = IPPool.__convert_address_to_list(netmask)
        byts = IPPool.__convert_address_to_list(ip)

        IPPool.assert_address(masks)
        IPPool.assert_address(byts)
        assert len(masks) == len(byts)

        result = IPPool.__mask_address(byts, masks)
        return result

    def check_ip(self, ip):
        ip_byts = IPPool.__convert_address_to_list(ip)
        masked_ip = IPPool.__mask_address(ip_byts, self.__netmask)
        return all(masked_ip[i] == self.__min_ip[i] for i in range(len(self.__min_ip)))

    def __init__(self, min_ip, netmask):
        self.__netmask = IPPool.__convert_address_to_list(netmask)
        self.__min_ip = IPPool.__mask_address(IPPool.__convert_address_to_list(min_ip), self.__netmask)

    def __eq__(self, other):
        if isinstance(other, IPPool):
            return all(other.__min_ip[i] == self.__min_ip[i] and other.__netmask[i] == self.__netmask[i]
                       for i in range(len(self.__min_ip)))
        return False


class IPRoute:
    def __init__(self, ip_range, ip_route):
        assert isinstance(ip_range, IPPool)
        IPPool.assert_address(ip_route, True)

        self.ip_range = ip_range
        self.ip_route = ip_route


class RoutingTable:
    class NoRouteException(Exception):
        pass

    def __init__(self, routes=[], default=None):
        self.__routes = routes[::]
        self.__default = default

    def add_route(self, route):
        assert isinstance(route, IPRoute)
        self.__routes.append(route)

    def set_default_gateway(self, route):
        assert isinstance(route, str)
        self.__default = route

    def find_route(self, ip=None):
        if self.__default is None:
            raise RoutingTable.NoRouteException('No default route')

        if ip is None:
            return self.__default

        for route in self.__routes:
            if route.ip_range.check_ip(ip):
                return ip

        return self.__default


class NIC:
    def __init__(self, mac_address, ip_address, routing_table=None):
        assert isinstance(mac_address, str)
        assert isinstance(ip_address, str)
        #assert isinstance(routing_table, RoutingTable)

        self.mac_address = mac_address
        self.ip_address = ip_address
        self.routing_table = routing_table

    def route(self, pack):
        pack_ip = None

        if pack.haslayer(IP):
            pack_ip = pack[IP].dst

        if pack.haslayer(Ether):
            destination_ip_route = self.routing_table.find_route(pack_ip)
            destination_mac = ARPHandler.obtain_mac(destination_ip_route)

            if destination_mac is not None:
                pack[Ether].src = self.mac_address
                pack[Ether].dst = destination_mac

                sendp(pack)
                return True

        return False

    def sniff(self):
        return sniff(lfilter=lambda pack: pack.haslayer(Ether) and 
        pack[Ether].dst == self.mac_address, count=1)

def route_outwards(self, pack, srcmac, hopmac):
    translated = self.translate_packet(pack, srcmac, hopmac)

    # TODO: Port manager
    # Log translation
    port_to_use = self._gen_unused_port()
    self.logger.insert(pack[IP].src, pack[TCP].sport, pack[TCP].dport. port_to_use)


class TranslationLog(object):
    def __init__(self):
        self.log = dict()
        self.ports_in_use = 0


    def insert(self, src_ip, source_port, destination_port, port_in_use):
        data = set([source_port, destination_port, port_in_use])

        if not (src_ip in self.log):
            self.log[src_ip] = set(data)
        else:
            self.log[src_ip].add(data)

    def remove(self, ip, ports):
        self.log[ip].remove(ports)

    def get_data_by_port(self, dport):
        for item in self.log.items():
            if item[1][2] == dport:
                return item[1]
        return None

    def __getitem__(self, key):
        return self.log.get(key, None)        


class LanNIC(NIC):
    def __init__(self, mac_address, ip_address, wanNIC=None, routing_table=None):
        super().__init__(mac_address, ip_address, routing_table)
        self.wanNIC = wanNIC

    def forward_packet(self, pack):
        pack[IP].src = wanNic.ip_address
        self.wanNIC.route(pack)


class WanNIC(NIC):
    def __init__(self, mac_address, ip_address, lanNIC=None, routing_table=None):
        super().__init__(mac_address, ip_address, routing_table)
        self.lanNIC = lanNIC

    def forward_packet(self, pack):
        pack[IP].src = lanNIC.ip_address
        self.lanNIC.route(pack)


class NAT:
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

    def __init__(self, lanNIC, wanNIC):
        self.lanNIC = lanNIC
        self.wanNIC = wanNIC
        self.logger = TranslationLog()

    def run(self):
        inward_pack = self.lanNIC.sniff()
        temp_port = self._gen_unused_port()

        self.logger.insert(inward_pack[IP].src, inward_pack[TCP].sport,
        inward_pack[TCP].dport, temp_port)

        inward_pack[IP].src = self.wanNIC.ip_address
        WanNIC.route(inward_pack)

        outward_pack = self.wanNIC.sniff()
        data = self.logger.get_data_by_port(outward_pack[TCP].dport)

        outward_pack[IP].src = self.lanNIC
        outward_pack[TCP].dport = data[0]
        outward_pack[TCP].sport = data[1]

