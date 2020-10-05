import  netutils    as      net
from    IPS.ips     import  IPS
from    fwRule      import  rule
import moduleBuilder

class Firewall:
    __STUB_FUNC = lambda pack: True


    def __init__(self):
        self.nat = None
        self.ips = None
        self.staticPolicy = rule(Firewall.__STUB_FUNC)
        self.currentIPSPolicy = None
        
        self.__packetsMod = 0
        self.__packetsModMax = 40


    def buildNAT(self):
        mb = moduleBuilder.moduleBuilder('./fw/patch/nat.conf')

        lan = mb.buildLan()
        wan = mb.buildWan()
        wan.lanNIC = lan
        lan.wanNIC = wan

        routeTableLan = net.RoutingTable()
        routeTableWan = net.RoutingTable()

        ipPoolOne, ipPoolTwo = mb.buildIPPoolLan(), mb.buildIPPoolWan()

        routeTableLan.add_route(net.IPRoute(net.IPPool(ipPoolOne[0], ipPoolOne[1]), lan.ip_address))
        routeTableWan.add_route(net.IPRoute(net.IPPool(ipPoolTwo[0], ipPoolTwo[1]), wan.ip_address))

        lan.routing_table = routeTableLan
        wan.routing_table = routeTableWan

        wan.routing_table.set_default_gateway(mb.buildDefaultGatewayWan())
        lan.routing_table.set_default_gateway(lan.ip_address)

        temp = net.NAT(lan, wan, ipPoolOne, ipPoolTwo, firewall=self)
        self.nat = temp

    def buildIPS(self):
        self.ips = IPS()
        self.ips.load_modules()


    def filter_packet(self, pack):
        if not self.staticPolicy.runChain(pack):
            return False

        if self.currentIPSPolicy:
            return self.currentIPSPolicy(pack)
        
        return True


    def onPacketReceived(self, pack):
        self.ips.notifyPacket(pack)

        if self.__packetsMod == 0:
            self.ips.run_inspection()
            self.currentIPSPolicy = self.ips.exportPolicy()

        self.__packetsMod += 1
        self.__packetsMod %= self.__packetsModMax

    def start(self):
        self.nat.run3()

# TODO: Add filtering to NAT