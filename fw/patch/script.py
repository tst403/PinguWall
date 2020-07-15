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

getIpByIname = lambda iname : os.popen('ifconfig ' + iname + 'enp0s3 | grep inet | awk \'{$1=$1;print}\' | head -n1 | cut -d \' \' -f2').read()
getMacByIname = lambda iname : os.popen('ifconfig ' + iname + ' | grep -i ether | awk \'{$1=$1;print}\' | cut -d \' \' -f2').read()
    

def buildLanNic(name):
    return net.LanNIC(getMacByIname(name), getIpByIname(name), name)


def buildWanNic(name):
    return net.WanNIC(getMacByIname(name), getIpByIname(name), name)


lan = buildLanNic('enp0s3')
wan = buildLanNic('enp0s8')
wan.lanNIC = lan
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