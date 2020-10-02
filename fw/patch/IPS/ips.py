from queue import Queue as cyclicQueue
from analysisResult import analysisResult 
import def_ips_blade_stub as blade_stub
from scapy.all import *

# Pathcing queue to add insert
def insert_warp(self, x):
    try:
        self.put_nowait(x)
    except:
        self.get_nowait()
        self.put_nowait(x)

def iter_warp(self):
    while not self.empty():
        yield self.get_nowait()
    

cyclicQueue.insert = insert_warp
cyclicQueue.__iter__ = iter_warp


class IPS:
    WATCH_SIZE = 500


    def __init__(self, tolerance=0):
        self.watch      = cyclicQueue(maxsize=IPS.WATCH_SIZE)
        self.blades     = []
        self.tolerance  = tolerance


    def run_inspection(self):
        result = analysisResult()
        lst = [x for x in self.watch]
        
        for blade in self.blades:
            blade_res = blade.analyze(lst)
            
            if blade_res is None:
                continue

            if blade_res.sevirity > self.tolerance:
                result += blade_res

        return result

    def notifyPacket(self, pack):
        self.watch.insert(pack)


# TODO: Remove test
def test():
    ips = IPS()
    stub = blade_stub.stub_blade()
    ips.blades.append(stub)
    packs = rdpcap('/home/dindibo4/Desktop/syn-flood')
    
    for x in packs:
        ips.notifyPacket(x)

    res = ips.run_inspection()
    f = res.suggestions[0].export_function()
    print(f(Ether()/IP()/TCP()))
    a=2

test()

