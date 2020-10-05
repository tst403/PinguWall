from queue import Queue as cyclicQueue
from IPS.analysisResult import analysisResult 
import IPS.def_ips_blade_stub as blade_stub
from scapy.all import *
import importlib
import pkgutil

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
    WATCH_SIZE              = 500
    MODULE_PREFIX           = 'ips_blade_'
    DEFUALT_MODULE_PREFIX   = 'def_ips_blade_'
    MODULE_FUNCTION         = 'analyze'


    def __init__(self, tolerance=0):
        self.watch      = cyclicQueue(maxsize=IPS.WATCH_SIZE)
        self.blades     = []
        self.tolerance  = tolerance
        self.previousPolicy = None


    def run_inspection(self):
        result = analysisResult()
        lst = [x for x in self.watch]

        if len(lst) == 0:
            return result
        
        for blade in self.blades:
            blade_res = blade.analyze(lst)
            
            if blade_res is None:
                continue

            if blade_res.sevirity > self.tolerance:
                result += blade_res

        self.previousPolicy = result
        return result


    def notifyPacket(self, pack):
        self.watch.insert(pack)


    @staticmethod
    def __get_modules(prefix, checkForAttr):
        discovered_plugins = {
            name: importlib.import_module(name)
            for finder, name, ispkg
            in pkgutil.iter_modules()
            if name.startswith(prefix)
        }

        mods = [discovered_plugins[k] for k in discovered_plugins.keys()]
        
        for mod in mods:
            assert hasattr(mod, checkForAttr), f'Module "{str(mod)}". Has no "{checkForAttr}" attribute'

        return mods


    def load_modules(self):
        mods = IPS.__get_modules(IPS.MODULE_PREFIX, IPS.MODULE_FUNCTION)
        mods += IPS.__get_modules(IPS.DEFUALT_MODULE_PREFIX, IPS.MODULE_FUNCTION)

        self.blades = mods


    def exportPolicy(self):

        def answer(pack):
            if self.previousPolicy == None:
                return True

            for suggestion in self.previousPolicy.suggestions:
                func = suggestion.export_function()
                if not func(pack):
                    return False
            
            return True

        return answer


'''
# TODO: Remove test
def test():
    ips = IPS()
    ips.load_modules()
    packs = rdpcap('/home/dindibo4/Desktop/syn-flood')
    
    for x in packs:
        ips.notifyPacket(x)

    res = ips.run_inspection()
    f = res.suggestions[0].export_function()
    print(f(Ether()/IP()/TCP()))
    a=2

test()'''

