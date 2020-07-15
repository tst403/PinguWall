#!/usr/bin/python3

import os
import netutils as net

CONFIG_FILE = 'interfaces.conf'

class nicInfo:
    def __init__(self, data):
        self.mac = data[0]
        self.ip = data[1]
        self.name = data[2]


class poolInfo:
    def __init__(self, data):
        self.minIp = data[0]
        self.netmask = data[1]

def parse():
    global CONFIG_FILE

    try:
        with open(CONFIG_FILE) as f:
            data = f.read()
            lines = data.split('\n')

            lan, wan = set([nicInfo(x.split()) for x in lines[0:2]])
            lanPool, wanPool = ([poolInfo(x.split()) for x in lines[2:4]])
            defualt_gw = lines[4]

            data = []

            data.append(net.LanNIC(lan.mac, lan.ip, lan.name))
            data.append(net.WanNIC(wan.mac, wan.ip, wan.name))

    except:
        print(CONFIG_FILE + ' Does not exist')
        os.exit()
