#!/usr/bin/python3

import random

class bidict(dict):
    def __init__(self, *args, **kwargs):
        super(bidict, self).__init__(*args, **kwargs)
        self.inverse = {}
        for key, value in self.items():
            self.inverse.setdefault(value,[]).append(key) 

    def __setitem__(self, key, value):
        if key in self:
            self.inverse[self[key]].remove(key) 
        super(bidict, self).__setitem__(key, value)
        self.inverse.setdefault(value,[]).append(key)        

    def __delitem__(self, key):
        self.inverse.setdefault(self[key],[]).remove(key)
        if self[key] in self.inverse and not self.inverse[self[key]]: 
            del self.inverse[self[key]]
        super(bidict, self).__delitem__(key)


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


    def terminate(externalPort):
        # TODO: Assert work
        del self.translator[externalPort]


    def translateOut(self, internalEp):
        if internalEp in self.translator:
            return self.translator[internalEp]
        else:
            temp = self.__get_unused_port()
            self.translator[internalEp] = temp
            return temp


    def translateIn(self, externalPort):
        return self.translator[externalPort]

track = TransportationTracker()
ext = track.translateOut(endpoint('192.168.1.1', 5555))
ext = track.translateOut(endpoint('192.168.1.1', 5555))
print(track)
 