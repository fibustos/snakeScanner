# snakeScanner
Sniff and Mitm Tool

## Usage 

- Enable your Ip_forward (need root privileges)

echo 1 >  /proc/sys/net/ipv4/ip_forward

- Run snakeScann.py

sudo python snakeScann.py [interface] [subnet] [gateway_ip]

ejemplo : sudo python snakeScann.py eth0 192.168.0.0/24 192.168.0.1
