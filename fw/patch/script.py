#!/usr/bin/python3

import netutils as net
import sys
import os
from scapy.all import *

def elevate():
    exe = sys.executable
    cmd = sys.argv
    uid = os.getuid() 

    if uid != 0:
        os.execvp('sudo', ['sudo', exe, *cmd])

lan = net.LanNIC('08:00:27:1c:fa:e0', '192.168.73.3', 'enp0s3')
wan = net.WanNIC('08:00:27:ba:71:27', '10.0.3.15', 'enp0s8', lanNIC=lan)
lan.wanNIC = wan

nat = net.NAT(lan, wan)

routeT1 = net.RoutingTable()
routeT2 = net.RoutingTable()

routeT1.add_route(net.IPRoute(net.IPPool('192.168.73.0', '255.255.255.0'), wan.ip_address))
routeT2.add_route(net.IPRoute(net.IPPool('10.0.3.0', '255.255.255.0'), lan.ip_address))

lan.routing_table = routeT1
wan.routing_table = routeT2

wan.routing_table.set_default_gateway('10.0.3.2')

if False:
    nat.run()
else:
    pack = rdpcap('/home/user/Desktop/nat/PinguWall/fw/patch/test.pcapng')[0]
    wan.route(pack)