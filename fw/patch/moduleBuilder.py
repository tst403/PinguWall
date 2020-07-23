#!/usr/bin/python3

import netutils as net
import json

getIpByIname = lambda iname : os.popen('ifconfig ' + iname + ' | grep inet | awk \'{$1=$1;print}\' | head -n1 | cut -d \' \' -f2 | tr -d \'\\n\'').read()

getMacByIname = lambda iname : os.popen('ifconfig ' + iname + ' | grep -i ether | awk \'{$1=$1;print}\' | cut -d \' \' -f2 | tr -d \'\\n\'').read()


def buildLanNic(name):
    return net.LanNIC(getMacByIname(name), getIpByIname(name), name)


def buildWanNic(name):
    return net.WanNIC(getMacByIname(name), getIpByIname(name), name)

class moduleBuilder:
    def __init__(self, conf_name):
        self.conf_name = conf_name
        
        print(os.popen('pwd').read())
        with open(self.conf_name, 'r') as f:
            self.jsonContent = json.loads(f.read())

    def buildLan(self):
        global buildLanNic
        return buildLanNic(self.jsonContent['lanIface'])

    def buildWan(self):
        global buildWanNic
        return buildWanNic(self.jsonContent['wanIface'])

    def buildIPPoolLan(self):
        return self.jsonContent['lanIpMin'], self.jsonContent['lanIpNetmask']

    def buildIPPoolWan(self):
        return self.jsonContent['wanIpMin'], self.jsonContent['wanIpNetmask']

    def buildDefaultGatewayWan(self):
        return self.jsonContent['defualtGateway']

