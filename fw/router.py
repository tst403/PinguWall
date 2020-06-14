from threading import Thread
from time import sleep

class Router(Thread):
    def __init__(self, mac_addr, default_gateway, handler):
        super().__init__()

        self.mac_addr = mac_addr
        self.default_gateway = default_gateway
        self.handler = handler
    
    def _handler_warper(self, pack):
        if self.route(pack):
            self.handler(pack)
            # TODO: handler

    def route(self, pack):
        # If frame was sent to us
        if pack.has_layer(Ether):
            if pack[Ether].dst == self.mac_addr:
                pack[Ether].src = self.mac_addr
                pack[Ether].dst = self.default_gateway

                # if frame has ip layer
                if pack.has_layer(IP):
                    pack[IP].ttl -= 1
                    
                    if pack[IP].ttl <= 0:
                        print('TTL Error')
                        return False
                    else:
                        del pack[IP].chksum
                    
                    sendp(pack)
                    return True
        return True

                    