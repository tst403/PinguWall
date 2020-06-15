from threading import Thread
from time import sleep
from scapy.all import *


def get_packet_layers(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        yield layer
        counter += 1


def get_layer_after(packet, layerName):
    getNext = False

    for layer in get_packet_layers(packet):
        if getNext:
            return layer

        if layer.name == layerName:
            getNext = True
    
    return None


class Router(Thread):
    def __init__(self, mac_addr, default_gateway, handler):
        super(Thread, self).__init__()

        self.mac_addr = mac_addr
        self.default_gateway = default_gateway
        self.handler = handler
    

    def _handler_warper(self, pack):
        if self.handler(pack):
            return self.route(pack)


    def route(self, pack):
        # If frame was sent to us
        if pack.haslayer(Ether):
            if pack[Ether].dst == self.mac_addr:
                newPack = Ether(src=self.mac_addr, dst=self.default_gateway)

                # If frame has ip layer
                if pack.haslayer(IP):

                    newPack /= IP(src='192.168.2.1', dst=pack[IP].dst, ttl=pack[IP].ttl - 1)

                    if newPack[IP].ttl <= 0:
                        print('TTL Error')
                        return False

                    # Load packet after IP layer
                    newPack /= get_layer_after(pack, 'IP')

                    newPack.show()
                    
                    sendp(newPack)
                    return True

                    
    return False

    def run(self):
        sniff(filter='ip', prn=self._handler_warper)
