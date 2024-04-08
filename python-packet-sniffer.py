#!/usr/bin/python

import datetime
from scapy.all import *
import socket

def network_monitoring_for_visualization_version(pkt):
    time = datetime.datetime.now()  # Capture the current time

    # Classify packets into TCP
    if pkt.haslayer(TCP):
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print_packet_info(time, "TCP-IN", pkt, len(pkt[TCP]))

        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print_packet_info(time, "TCP-OUT", pkt, len(pkt[TCP]))

    # Classify packets into UDP
    if pkt.haslayer(UDP):
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print_packet_info(time, "UDP-OUT", pkt, len(pkt[UDP]))

        if socket.gethostbyname(socket.gethostname()) ==pkt[IP].dst:
            print_packet_info(time, "UDP-IN", pkt, len(pkt[UDP]))

    # Classify packets into ICMP
    if pkt.haslayer(ICMP):
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print_packet_info(time, "ICMP-OUT", pkt, len(pkt[ICMP]))

        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print_packet_info(time, "ICMP-IN",pkt, len(pkt[ICMP]))

def print_packet_info(time, packet_type, pkt, size):
    print(f"[{time}]  {packet_type}:{size} Bytes  "
          f"SRC-MAC: {pkt.src}  DST-MAC: {pkt.dst}  "
          f"SRC-PORT: {pkt.sport}  DST-PORT: {pkt.dport}  "
          f"SRC-IP: {pkt[IP].src}  DST-IP: {pkt[IP].dst}")

if __name__ == '__main__':
    sniff(prn=network_monitoring_for_visualization_version)
