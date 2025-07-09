#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
import datetime
from colorama import init, Fore, Style
import sys

init(autoreset=True)

COLORS = {
    "info": Fore.CYAN,
    "alert": Fore.RED + Style.BRIGHT,
    "warning": Fore.YELLOW,
    "l2": Fore.YELLOW,
    "l3": Fore.GREEN,
    "l4": Fore.BLUE,
    "app": Fore.MAGENTA,
    "payload": Fore.LIGHTBLACK_EX,
    "error": Fore.RED
}

NIDS_RULES = [
    {
        'name': "HTTP POST Request Detected",
        'protocol': 'TCP',
        'dst_port': 80,
        'payload_contains': b'POST / HTTP/1.1'
    },
    {
        'name': "DNS Query for Malicious Domain (examplemalicious.com)",
        'protocol': 'DNS',
        'keyword': 'examplemalicious.com'
    },
    {
        'name': "Telnet Connection Attempt",
        'protocol': 'TCP',
        'dst_port': 23
    },
    {
        'name': "Ping from Specific IP (192.168.1.100)",
        'protocol': 'ICMP',
        'src_ip': '192.168.1.100'
    }
]

def format_payload(payload):
    try:
        decoded_payload = payload.decode('utf-8', errors='ignore')
        if sum(1 for c in decoded_payload if c.isprintable()) < len(decoded_payload) / 2:
            return f"\n{COLORS['payload']}{scapy.hexdump(payload, dump=True)}"
        return f"\n{COLORS['payload']}{decoded_payload.strip()}"
    except Exception:
        return f"\n{COLORS['payload']}{scapy.hexdump(payload, dump=True)}"

def detect_intrusion(packet):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    alert_triggered = False

    for rule in NIDS_RULES:
        match = True
        ip_layer = None
        proto_layer = None
        payload = None

        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            if rule.get('src_ip') and ip_layer.src != rule['src_ip']:
                match = False
            if rule.get('dst_ip') and ip_layer.dst != rule['dst_ip']:
                match = False
        elif packet.haslayer(IPv6):
            ip_layer = packet.getlayer(IPv6)
            if rule.get('src_ip') and ip_layer.src != rule['src_ip']:
                match = False
            if rule.get('dst_ip') and ip_layer.dst != rule['dst_ip']:
                match = False
        
        if not match:
            continue

        if packet.haslayer(TCP):
            proto_layer = packet.getlayer(TCP)
            if rule.get('src_port') and proto_layer.sport != rule['src_port']:
                match = False
            if rule.get('dst_port') and proto_layer.dport != rule['dst_port']:
                match = False
            if match and proto_layer.payload:
                payload = bytes(proto_layer.payload)
        elif packet.haslayer(UDP):
            proto_layer = packet.getlayer(UDP)
            if rule.get('src_port') and proto_layer.sport != rule['src_port']:
                match = False
            if rule.get('dst_port') and proto_layer.dport != rule['dst_port']:
                match = False
            if match and proto_layer.payload:
                payload = bytes(proto_layer.payload)
        elif packet.haslayer(ICMP):
            proto_layer = packet.getlayer(ICMP)
        
        if not match:
            continue

        if rule.get('protocol') == 'DNS' and packet.haslayer(DNS):
            dns_layer = packet.getlayer(DNS)
            if dns_layer.qr == 0 and dns_layer.qd and rule.get('keyword'):
                query_name = dns_layer[DNSQR].qname.decode().strip('.')
                if rule['keyword'] in query_name:
                    print(f"{COLORS['alert']}[ALERT] {rule['name']}")
                    alert_triggered = True
        
        if rule.get('payload_contains') and payload:
            if rule['payload_contains'] in payload:
                print(f"{COLORS['alert']}[ALERT] {rule['name']}")
                alert_triggered = True

        if match and not rule.get('keyword') and not rule.get('src_ip') and \
           not rule.get('dst_ip') and not rule.get('src_port') and \
           not rule.get('dst_port') and not rule.get('payload_contains') and \
           not rule.get('protocol') == 'DNS':
            if (rule['protocol'] == 'ICMP' and packet.haslayer(ICMP)) or \
               (rule['protocol'] == 'TCP' and packet.haslayer(TCP) and not rule.get('dst_port')) or \
               (rule['protocol'] == 'UDP' and packet.haslayer(UDP) and not rule.get('dst_port')):
                print(f"{COLORS['alert']}[ALERT] {rule['name']}")
                alert_triggered = True
                
    print(f"\n{'-'*30} {COLORS['info']}[ {timestamp} ]{Style.RESET_ALL} {'-'*30}")

    if packet.haslayer(Ether):
        eth_layer = packet.getlayer(Ether)
        print(f"{COLORS['l2']}[L2: Ethernet] Source MAC: {eth_layer.src} -> Destination MAC: {eth_layer.dst}")
        
    if packet.haslayer(ARP):
        arp_layer = packet.getlayer(ARP)
        op_type = "Request (Who has?)" if arp_layer.op == 1 else "Reply (Is at)"
        print(f"{COLORS['l2']}[L2: ARP]        Operation: {op_type} | IP: {arp_layer.psrc} -> MAC: {arp_layer.hwsrc}")
        return

    if ip_layer:
        if packet.haslayer(IP):
            print(f"{COLORS['l3']}[L3: IPv4]     Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst} | Protocol: {ip_layer.proto} | TTL: {ip_layer.ttl}")
        elif packet.haslayer(IPv6):
            print(f"{COLORS['l3']}[L3: IPv6]     Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst} | Next Header: {ip_layer.nh}")
    else:
        return

    if proto_layer:
        if packet.haslayer(TCP):
            flags = proto_layer.flags.flagrepr()
            print(f"{COLORS['l4']}[L4: TCP]      Source Port: {proto_layer.sport} -> Destination Port: {proto_layer.dport} | Flags: {flags}")
        elif packet.haslayer(UDP):
            print(f"{COLORS['l4']}[L4: UDP]      Source Port: {proto_layer.sport} -> Destination Port: {proto_layer.dport} | Length: {proto_layer.len}")
        elif packet.haslayer(ICMP):
            print(f"{COLORS['l4']}[L4: ICMP]     Type: {proto_layer.type} | Code: {proto_layer.code}")
        
    if alert_triggered:
        if packet.haslayer(DNS):
            dns_layer = packet.getlayer(DNS)
            if dns_layer.opcode == 0 and dns_layer.qr == 0:
                query_name = dns_layer[DNSQR].qname.decode()
                print(f"{COLORS['app']}[L7: DNS]      Query: {query_name}")
            elif dns_layer.qr == 1:
                print(f"{COLORS['app']}[L7: DNS]      Answer:")
                for i in range(dns_layer.ancount):
                    dns_rr = dns_layer[DNSRR][i]
                    print(f"\t\t- {dns_rr.rrname.decode()} -> {dns_rr.rdata}")
        elif packet.haslayer(TCP) and (proto_layer.sport == 80 or proto_layer.dport == 80):
            if proto_layer.payload:
                print(f"{COLORS['app']}[L7: HTTP Data]")
                print(format_payload(bytes(proto_layer.payload)))
        
        if payload and not (packet.haslayer(DNS) or (packet.haslayer(TCP) and (proto_layer.sport == 80 or proto_layer.dport == 80))):
             print(f"{COLORS['payload']}[Payload (Raw Data)] Size: {len(payload)} bytes")
             print(scapy.hexdump(payload, dump=True))
        
    print(f"{'-'*73}")

def main():
    print(f"{COLORS['info']}### Simple Python Network Intrusion Detector Starting... ###")
    print(f"{COLORS['info']}Monitoring network traffic for suspicious activities.")
    print(f"{COLORS['info']}Press CTRL+C to stop.")
    
    try:
        if len(sys.argv) > 1:
            iface = sys.argv[1]
            print(f"{COLORS['info']}Sniffing on interface: {iface}")
        else:
            print(f"{COLORS['warning']}No network interface specified. Attempting to sniff on all available interfaces (may require specifying one, e.g., 'python3 network_intrusion_detector.py eth0').")
            iface = None

        scapy.sniff(
            prn=detect_intrusion,
            store=0,
            iface=iface
        )
    except PermissionError:
        print(f"{COLORS['error']}[ERROR] Administrator (root) privileges are required to run this script.")
        print(f"{COLORS['error']}Please run with 'sudo python3 <filename>.py' or as an administrator.")
    except Exception as e:
        print(f"{COLORS['error']}[Unexpected Error] {e}")
    finally:
        print(f"\n{COLORS['info']}### Network Intrusion Detector stopped. ###")

if __name__ == "__main__":
    main()