from scapy.all import *

class Endpoint:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def __eq__(self, other):
        if type(other) == type(self):
            return self.ip == other.ip and self.port == other.port
        return False


class Conversation:
     def __init__(self, epClient, epServer):
         self.epClient = epClient
         self.epServer = epServer


class TransferTracker:
    def __init__(self):
        self.innerConversations = dict()
        self.activeConversations = dict()

    def obtainPort(self, convClient):
        if convClient in self.activeConversations and self.activeConversations[convClient] >= 1:
            if convClient in self.innerConversations:
                return self.innerConversations[convClient]
            else:
                raise Exception('TransferTracker: Fatal error 1')
        else:
            
