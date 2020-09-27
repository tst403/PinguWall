#!/usr/bin/python3

import netutils as net
import sys
import os
from scapy.all import *
from netutils import ARPHandler
import moduleBuilder

print('running...')

def elevate():
    exe = sys.executable
    cmd = sys.argv
    uid = os.getuid() 

    if uid != 0:
        os.execvp('sudo', ['sudo', exe, *cmd])    


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

nat = net.NAT(lan, wan, ipPoolOne, ipPoolTwo)


print('starting')
nat.run3()
