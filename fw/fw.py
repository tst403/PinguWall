#!/usr/bin/python

from scapy.all import *

import nat
import router

def foo(x):
    print 'Yes'
    return True

def get_mac():
    eth = Ether()
    return eth[Ether].src

#n = nat.NAT(nat.NAT.FilterType.BLACK_LIST)

mac = get_mac()

r = router.Router(mac, '52:54:00:12:35:02', foo)

r.run()

