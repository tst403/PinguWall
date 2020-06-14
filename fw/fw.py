#!/usr/bin/python

import nat
import router

def get_mac():
    eth = Ether()
    return eth[Ether].src

n = nat.NAT(nat.NAT.FilterType.BLACK_LIST)
r = router.Router()


