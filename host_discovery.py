from scapy.all import *
import os
import requests

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

def hosts_scan(subnet, cache_flag):
    if not cache_flag:
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

        hosts_data = get_details(hosts_live)
        print "[?] Overwrite the cache file? (y/n)"
        ans = raw_input("Answer: ")
        if ans == "y":
            create_cacheDB(hosts_data)
        return hosts_data
    else:
        hosts_data = read_cacheDB()
        return hosts_data


def create_cacheDB(hosts):
    f  = open("cacheDB.txt", "w") 
    for (ip,mac,vendor) in hosts:
        data = ip + "/" + mac + "/" + vendor + "\n"
        f.write(data)
    f.close()

def read_cacheDB():
    f = open("cacheDB.txt", "r")
    data = f.readlines()
    new_data = []
    for line in data:
        host = line.split("/")
        new_data.append(host)
    f.close()
    return new_data


