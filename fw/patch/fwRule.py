class rule:
    def __init__(self, passFunc, next=None):
        self.passFunc = passFunc
        self.next = next

    def runChain(self, obj):
        if self.next is None:
            return self.passFunc(obj)
        else:
            return self.passFunc(obj) and self.next.runChain(obj)

    def append(self, r):
        assert r.next is None

        r.next = self.next
        self.next = r