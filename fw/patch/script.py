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

getIpByIname = lambda iname : os.popen('ifconfig ' + iname + ' | grep inet | awk \'{$1=$1;print}\' | head -n1 | cut -d \' \' -f2 | tr -d \'\\n\'').read()
getMacByIname = lambda iname : os.popen('ifconfig ' + iname + ' | grep -i ether | awk \'{$1=$1;print}\' | cut -d \' \' -f2 | tr -d \'\\n\'').read()
    


mb = moduleBuilder.moduleBuilder('nat.conf')

lan = mb.buildLan() #buildLanNic('enp0s3')
wan = mb.buildWan() #buildWanNic('enp0s8')
wan.lanNIC = lan
lan.wanNIC = wan

nat = net.NAT(lan, wan)

routeTableLan = net.RoutingTable()
routeTableWan = net.RoutingTable()

ipPoolOne, ipPoolTwo = mb.buildIPPoolLan(), mb.buildIPPoolWan()

#routeTableLan.add_route(net.IPRoute(net.IPPool('192.168.73.0', '255.255.255.0'), lan.ip_address))
routeTableLan.add_route(net.IPRoute(net.IPPool(ipPoolOne[0], ipPoolOne[1]), lan.ip_address))
#routeTableWan.add_route(net.IPRoute(net.IPPool('10.0.3.2', '255.255.255.0'), wan.ip_address))
routeTableWan.add_route(net.IPRoute(net.IPPool(ipPoolTwo[0], ipPoolTwo[1]), wan.ip_address))

lan.routing_table = routeTableLan
wan.routing_table = routeTableWan

#wan.routing_table.set_default_gateway('10.0.0.2')
wan.routing_table.set_default_gateway(mb.buildDefaultGatewayWan())
lan.routing_table.set_default_gateway(lan.ip_address)

if True:
    nat.run2()
else:
    pack = rdpcap('/home/user/Desktop/nat/PinguWall/fw/patch/test.pcapng')[0]
    wan.route(pack)