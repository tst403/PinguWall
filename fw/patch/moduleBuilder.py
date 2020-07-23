#!/usr/bin/python3

import netutils as net
import json

def buildLanNic(name):
    return net.LanNIC(getMacByIname(name), getIpByIname(name), name)


def buildWanNic(name):
    return net.WanNIC(getMacByIname(name), getIpByIname(name), name)

class moduleBuilder:
    def __init__(self, conf_name):
        self.conf_name = conf_name
        
        with open(self.conf_name, 'r') as f:
            self.jsonContent = json.loads(f.read())

    def buildLan(self):
        global buildLanNic
        return buildLanNic(self.jsonContent['lanIface'])

    def buildWan(self):
        global buildWanNic
        return buildWanNic(self.jsonContent['wanIface'])

