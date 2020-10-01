from queue import Queue as cyclicQueue

# Pathcing queue to add insert
def insert_warp(self, x):
    try:
        self.put_nowait(x)
    except:
        self.get_nowait()
        self.put_nowait(x)

cyclicQueue.insert = insert_warp


class IPS:
    WATCH_SIZE = 500

    def __init__(self):
        self.watch  = cyclicQueue(maxsize=IPS.WATCH_SIZE)
        self.blades = []

    def run_inspection(self):


    def notifyPacket(self, pack):
        self.watch.insert(pack)
