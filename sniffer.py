#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Internship - Task 1: Basic Network Sniffer
File: sniffer.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def process_packet(packet):
    # Check if the packet has an IP layer (Layer 3)
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Identify the Protocol Name
        proto_name = "Other"
        if packet.haslayer(TCP):
            proto_name = "TCP"
        elif packet.haslayer(UDP):
            proto_name = "UDP"
        elif packet.haslayer(ICMP):
            proto_name = "ICMP"
            
        print(f"\n[+] New Packet Captured:")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")
        print(f"    Protocol       : {proto_name} (ID: {protocol})")
        
        # Display Payload data if present (up to 50 characters)
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    Payload Data   : {payload[:50]}")

def main():
    print("==================================================")
    print("      Basic Network Sniffer - CodeAlpha           ")
    print("==================================================")
    print("[*] Starting packet capture... Press Ctrl+C to stop.\n")
    
    # Start capturing packets (filters for IP traffic, captures continuously)
    # Note: Packet sniffing requires root/administrator privileges.
    sniff(prn=process_packet, filter="ip", store=False)

if __name__ == "__main__":
    main()
    
