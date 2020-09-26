#!/usr/bin/python3

import random
from bidict import bidict

class endpoint:

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def __eq__(self, oth):
        if type(self) == type(oth):
            return self.ip == oth.ip and self.port == oth.port
        
        return False

    def __hash__(self):
        return ''.join([self.ip, str(self.port)]).__hash__()

class TransportationTracker:
    MIN_PORT = 1050
    MAX_PORT = 65000

    def __init__(self):
        self.translator = bidict()
        self.ongoingOuterPorts = set()
        self.usedPorts = 0

    __get_rand_num = lambda self : random.randint(TransportationTracker.MIN_PORT,
    TransportationTracker.MAX_PORT)

    # Gets an unused port, updates used ports, bidict. returns port
    def __get_unused_port(self):
        if self.usedPorts -1 == TransportationTracker.MAX_PORT - TransportationTracker.MIN_PORT:
            return -1

        temp = self.__get_rand_num()
        while temp in self.ongoingOuterPorts:
            temp = self.__get_rand_num()

        self.usedPorts += 1
        self.ongoingOuterPorts.add(temp)
        return temp

    def terminate(self, obj):
        removed = False
        isPort = type(obj) == int
        port = None

        if not isPort:
            port = self.translator[obj]

        if obj in self.translator:
            del self.translator[obj]
            removed = True
            
        if obj in self.translator.inverse:
            del self.translator.inverse[obj]
            removed = True

        if removed:
            self.usedPorts -= 1

            # if not port, convert to port
            self.ongoingOuterPorts.remove(obj if isPort else port)

    def isEmpty(self, debug_level=0):
        if debug_level > 0:
            print("Regular: " + str(len(self.translator)) + " Inverse: " + str(len(self.translator.inverse)))

        return len(self.translator) == 0 and len(self.translator.inverse) == 0 and self.usedPorts == 0 and\
        len(self.ongoingOuterPorts) == 0

    def translateOut(self, internalEp):
        if internalEp in self.translator:
            return self.translator[internalEp]
        else:
            temp = self.__get_unused_port()
            self.translator[internalEp] = temp
            return temp


    def translateIn(self, externalPort):
        return self.translator.inverse[externalPort]
 