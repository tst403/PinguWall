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

    def find_route(self, ip):
        if self.__default is None:
            raise RoutingTable.NoRouteException('No default route')

        for route in self.__routes:
            if route.ip_range.check_ip(ip):
                return ip

        return self.__default


class NIC:
    def __init__(self, mac_address, ip_address, routing_table=None):
        assert isinstance(mac_address, str)
        assert isinstance(ip_address, str)
        assert isinstance(routing_table, RoutingTable)

        self.mac_address = mac_address
        self.ip_address = ip_address
        self.routing_table = routing_table

    def route(self, pack):
        if pack.haslayer(Ether):
            destination_ip = self.routing_table.find_route()
            destination_mac = ARPHandler.obtain_mac(destination_ip)

            if destination_mac is not None:
                pack[Ether].src = self.mac_address
                pack[Ether].dst = destination_mac

                sendp(pack)
                return True

        return False


class LanNIC(NIC):
    def __init__(self, mac_address, ip_address, routing_table=None):
        super().__init__(mac_address, ip_address, routing_table)

