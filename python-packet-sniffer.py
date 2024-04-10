#!/usr/bin/env python3

from scapy.all import *
import os, datetime, socket, time

def packet_callback(packet):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    src_mac = packet[Ether].src
    dst_mac = packet[Ether].dst

    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            if packet[TCP].flags == 0x12: # SYN-ACK flag
                if packet.getlayer(IP).src == "192.168.1.8": # replace with your machine's IP address
                    direction = "Outgoing"
                else:
                    direction = "Incoming"
            elif packet[TCP].flags == 0x02: # SYN flag
                if packet.getlayer(IP).dst == "192.168.1.8": # replace with your machine's IP address
                    direction = "Incoming"
                else:
                    direction = "Outgoing"
            else:
                direction = "Other"

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            if packet[UDP].sport == 53: # DNS requests
                if packet.getlayer(IP).src == "192.168.1.8": # replace with your machine's IP address
                    direction = "Outgoing"
                else:
                    direction = "Incoming"
            else:
                direction = "Other"

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            src_port = packet[ICMP].src
            dst_port = packet[ICMP].dst

            if packet[ICMP].type == 8: # Echo request
                if packet.getlayer(IP).src == "192.168.1.8": # replace with your machine's IP address
                    direction = "Outgoing"
                else:
                    direction = "Incoming"
            else:
                direction = "Other"

        else:
            protocol = "Other"
            src_port = ""
            dst_port = ""
            direction = "Other"

    else:
        protocol = "Other"
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        src_ip = "None"
        dst_ip = "None"
        src_port = ""
        dst_port = ""
        direction = "Other"

    print(f"{timestamp} | {protocol} | {src_mac} | {dst_mac} | {src_ip} | {dst_ip} | {src_port} | {dst_port} | {direction}")

    # Save packet to pcap file
    wrpcap('captured_packets.pcap', packet)

sniff(prn=packet_callback, filter="tcp or udp or icmp", store=0)
