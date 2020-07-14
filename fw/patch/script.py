#!/usr/bin/python3

import netutils as net
import sys
import os

def elevate():
    exe = sys.executable
    cmd = sys.argv
    uid = os.getuid()

    if uid != 0:
        os.execvp('sudo', ['sudo', exe, *cmd])

elevate()

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

nat.run()
