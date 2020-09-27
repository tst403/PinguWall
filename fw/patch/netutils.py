import random
from scapy.all import *
import os
import mocking
import queue
import threading
import TransportationTracker as tt

class ARPHandler:
    __ARP_TABLE_PATH = '/proc/net/arp'
    macs = dict()

    @staticmethod
    def __ping_host(ip):
        IPPool.assert_address(ip, True)
        os.system('ping -c 1 -W 1 {0}'.format(ip))

    @staticmethod
    def update_macs():
        ARPHandler.macs = dict()

        fix_line = lambda line: ' '.join(line.split())

        with open(ARPHandler.__ARP_TABLE_PATH, 'r') as f:
            data = f.read()

        lines = data.split('\n')
        lines = [fix_line(line) for line in lines][1:]

        entries = [x.split() for x in lines]
        entries.pop()
        for entry in entries:
            ARPHandler.macs[entry[0]] = entry[3]

    @staticmethod
    def obtain_mac(ip, retry=True):
        print('ip ----->', ip)
        if ip in ARPHandler.macs:
            mac = ARPHandler.macs[ip]
            return mac
        else:
            if retry:
                ARPHandler.__ping_host(ip)
                ARPHandler.update_macs()
                ARPHandler.obtain_mac(ip, False)
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
        self.sniffingThread = None

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
    def __init__(self, mac_address, ip_address, interface_name, routing_table=None):
        assert isinstance(mac_address, str)
        assert isinstance(ip_address, str)

        self.mac_address = mac_address
        self.ip_address = ip_address
        self.routing_table = routing_table
        self.interface_name = interface_name
        self.sniffFilter = lambda pack: pack.haslayer(Ether) and pack[Ether].dst == self.mac_address and pack.haslayer(IP) and pack[IP].src != self.ip_address

    def translate_pack_port_out(self, pack, port):
        pack[TCP].sport = port
        del pack[TCP].chksum
        #del pack[TCP].chksum
        return pack

    def route(self, pack, toPort=''):
        pack_ip = None

        if pack.haslayer(IP):
            pack_ip = pack[IP].dst
            del pack[IP].chksum

        if not pack.haslayer(Ether):
            pack = Ether() / pack


        destination_ip_route = self.routing_table.find_route(pack_ip)
        destination_mac = ARPHandler.obtain_mac(destination_ip_route)
        print('Got destination MAC address --> ' + destination_mac)

        # Change transportation layer
        # TODO: Support UDP

        if pack.haslayer(TCP) and toPort != '':
            # TODO: Assert is working(pack assignment)
            pack = self.translate_pack_port_out(pack, toPort)

        if destination_mac is not None:
            pack[Ether].src = self.mac_address
            pack[Ether].dst = destination_mac

            print('Packet to send')
            pack.show()
            sendp(pack, iface=self.interface_name)

        return False

    def sniff(self):
        return sniff(lfilter=self.sniffFilter, count=1, iface=self.interface_name)

    def async_sniffer_start(self, callback):
        def sniffer():
            sniff(lfilter=self.sniffFilter, prn=callback, iface=self.interface_name)

        self.sniffingThread = threading.Thread(target=sniffer)
        self.sniffingThread.start()

    def async_sniffer_stop(self):
        if self.sniffingThread:
            self.sniffingThread.stop()
            self.sniffingThread = None


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
    def __init__(self, mac_address, ip_address, iface, wanNIC=None, routing_table=None):
        super().__init__(mac_address, ip_address, iface, routing_table=routing_table)
        self.wanNIC = wanNIC

    def forward_packet(self, pack):
        pack[IP].src = wanNic.ip_address
        self.wanNIC.route(pack)


class WanNIC(NIC):
    def __init__(self, mac_address, ip_address, iface, lanNIC=None, routing_table=None):
        super().__init__(mac_address, ip_address, iface, routing_table=routing_table)
        self.lanNIC = lanNIC

    def forward_packet(self, pack):
        pack[IP].src = lanNIC.ip_address
        self.lanNIC.route(pack)


class PortTranslator:
    def __init__(self, minPort = 1100, maxPort=65000):
        self.minPort = minPort
        self.maxPort = maxPort
        self.__portsInUse = 0
        self.portMapIn = dict()
        self.portMapOut = dict()
        self.portUpgradeMap = dict()
        self.__NUM_OF_PORTS = 1 + maxPort - minPort

    def genUnusedPort(self):
        if self.__portsInUse > self.__NUM_OF_PORTS:
            return -1
        else:
            # Generate unused port
            tempPort = random.randint(self.minPort, self.maxPort)

            while tempPort in self.portMapOut:
                tempPort = random.randint(self.minPort, self.maxPort)
                
            return tempPort


    def assignNewPort(self, currentPort, ipAddr):
            assignedPort = self.genUnusedPort()
            if assignedPort == -1:
                return

            # Add to Ip-Ports list
            if not ipAddr in self.portMapIn:
                self.portMapIn[ipAddr] = [assignedPort]
            else:
                self.portMapIn[ipAddr].append(assignedPort)
            
            self.portMapOut[assignedPort] = ipAddr
            self.__portsInUse += 1
            self.portUpgradeMap[assignedPort] = currentPort
            return assignedPort

    def getInnerPortByPort(self, outerPort):
        return self.portUpgradeMap[outerPort]

    def releasePort(self, port):
        if self.__portsInUse > 0:
            ownerIp = self.portMapOut[port]
            del self.portMapOut[port]

            if ownerIp in self.portMapIn:
                self.portMapIn[ownerIp].remove(port)

            del self.portUpgradeMap[port]

            self.__portsInUse -= 1

    def getPortsByIp(self, ipAddr):
        return self.portMapIn.get(ipAddr)

    def getIpByPort(self, port):
        return self.portMapOut.get(port)


class NAT:

    CONNECTIONS_MAX = 100
    PORT_MIN = 1110
    PORT_MAX = 65000
    
    def __init__(self, lanNIC, wanNIC, lanIpPool, wanIpPool):
        ARPHandler.update_macs()

        self.lanNIC = lanNIC
        self.wanNIC = wanNIC
        self.logger = TranslationLog()
        self.pendingLANQueue = queue.Queue()
        self.pendingWANQueue = queue.Queue()
        self.packetHandlingDelay = 1e-3
        
        self.ports_in_use = 0 # TODO: Remove
        self.transportTracker = tt.TransportationTracker()
        self.routingThreads = []
        self.sniffingThreads = []
        self.lanIpPool, self.wanIpPool = lanIpPool, wanIpPool

    def _get_ports_in_used(self):
        return [ports[2] for ports in self.log.values()]

    def _gen_unused_port(self):
        if self.ports_in_use > NAT.CONNECTIONS_MAX:
            return -1

        temp_port = random.randint(NAT.PORT_MIN, NAT.PORT_MAX)
        used_ports = self._get_ports_in_used()

        while temp_port in used_ports:
            temp_port = random.randint(NAT.PORT_MIN, NAT.PORT_MAX)

        return temp_port

    def run2(self):
        def outwards():
            inward_pack = self.lanNIC.sniff()[0]
            print('======== Sniffed ========')
            
            # Check if first
            if True:
                temp_port = self.portTranslator.assignNewPort(inward_pack[TCP].sport ,inward_pack[IP].src)
                print('New port ====> ' + str(temp_port))
            else:
                temp_port = -1 # Get new port


    def _insert_packet(self, pack):
	
        self.packetQueue = queue(sorted(self.packetQueue, key=lambda p: p.time))

    def startSniffing(self):
        def workerIn():
            sniff(lfilter=lambda pack: pack.haslayer(Ether), prn=self._insert_packet, iface=self.lanNIC.interface_name)

        def workerOut():
            sniff(lfilter=lambda pack: pack.haslayer(Ether), prn=self._insert_packet, iface=self.wanNIC.interface_name)

        t1 = threading.Thread(target=workerIn)
        t2 = threading.Thread(target=workerIn)

        self.sniffingThreads.append(t1)
        self.sniffingThreads.append(t2)

        t1.start()
        t2.start()


    def routeAsyncWarper(self, func, pack):
        t = threading.Thread(target=func, args=(pack,))
        self.routingThreads.append(t)
        t.start()

        # Old format

        pack = outwards()[0]
        in_pack = inwards(pack)[0]
        print('======== Sucsess! ========')
        print('======== TEST ========')
        pack = sniff(iface=self.lanNIC.interface_name, lfilter = lambda x: x.haslayer(TCP) and x[TCP].dport == 4444)
        pack.show()


    def lan_sniff_handler(self, pack):
        self.pendingLANQueue.put(pack)

    def wan_sniff_handler(self, pack):
        self.pendingWANQueue.put(pack)

    def sniff_init(self):
        self.lanNIC.async_sniffer_start(self.lan_sniff_handler)
        self.wanNIC.async_sniffer_start(self.wan_sniff_handler)

    def queue_handler_init(self):
        def worker():
            p = None
        
            while 1:
                if not self.pendingLANQueue.empty():
                    p = self.pendingLANQueue.get()

                    # TODO: Make sure we arent routing packets with foreign communication that we haven't started
                    try:
                        self.serveOutwards(p)
                    except:
                        print('LAN dropped packet')
                    
                if not self.pendingWANQueue.empty():
                    p = self.pendingWANQueue.get()

                    try:
                        self.serveInwards(p)
                    except:
                        print('WAN dropped packet')

                time.sleep(self.packetHandlingDelay)

        t = threading.Thread(target=worker)
        t.start()

    def run3(self):
        self.sniff_init()
        self.queue_handler_init()

    def serveOutwards(self, inward_pack):
        assignedPort = self.transportTracker.translateOut(tt.endpoint(inward_pack[IP].src, inward_pack[TCP].sport))
        print('Assigned port ====> ' + str(assignedPort))
        print('======== --> Outwards --> ========')

        inward_pack[IP].src = self.wanNIC.ip_address
        del inward_pack[IP].chksum

        self.wanNIC.route(inward_pack, toPort=assignedPort)

    def serveInwards(self, pack):
        outerPort = pack[TCP].dport

        innerEndpoint = self.transportTracker.translateIn(outerPort)
        
        pack[TCP].dport = innerEndpoint.port
        pack[IP].dst = innerEndpoint.ip

        del pack[IP].chksum
        del pack[TCP].chksum

        print('======== <-- Inwards <-- ========')
        pack.show()
        
        # TODO: Check if toPort
        self.lanNIC.route(pack)

    # TODO: Remove all those kind of shitty functions
    def run(self):
        inward_pack = self.lanNIC.sniff()
        print('======== Sniffed ========')
        
        temp_port = mocking.get_port()

        self.logger.insert(inward_pack[IP].src, inward_pack[TCP].sport,
        inward_pack[TCP].dport, temp_port)

        inward_pack[IP].src = self.wanNIC.ip_address
        self.wanNIC.route(inward_pack, toPort=temp_port)

        outward_pack = self.wanNIC.sniff()
        data = self.logger.get_data_by_port(outward_pack[TCP].dport)

        outward_pack[IP].src = self.lanNIC
        outward_pack[TCP].dport = data[0]
        outward_pack[TCP].sport = data[1]


class SYN_Table:
    def __init__(self):
        self.__table = dict()
    
    def record(self, client_endpoint, server_endpoint):
        if client_endpoint in self.__table:
            raise Exception()
        else:
            self.__table.add(server_endpoint)
    
    def is_tracked(self, client_endpoint):
        return client_endpoint in self.__table or set([client_endpoint[1], client_endpoint[0]]) in self.__table

    def verify_stream(self, ip_couple, server_endpoint):
        return self.__table.get(ip_couple) == server_endpoint

