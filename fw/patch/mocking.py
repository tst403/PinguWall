from scapy.all import *
import random

def sniff_in():
    return IP(src='192.168.56.17', dst='216.58.207.78') / TCP(sport=12345, dport=80)


# TODO: fix _get_ports_in_used
def get_port():
    return random.randint(1100, 64000)