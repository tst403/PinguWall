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