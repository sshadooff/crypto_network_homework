from scapy.all import *

# Укажите имя сетевого интерфейса
pkts = sniff(
    iface="enp0s3",
    filter="tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
    prn=lambda x: x.summary(),
)
