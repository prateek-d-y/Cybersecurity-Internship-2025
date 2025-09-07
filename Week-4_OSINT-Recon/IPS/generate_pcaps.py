#!/usr/bin/env python3
"""
PCAP generator for IPS demo (offline, safe).

Creates two pcaps by default:
- normal.pcap: benign traffic (a few TCP three-way handshakes + simple HTTP GET).
- malicious.pcap: includes ICMP echo flood, TCP SYN scan/NULL/FIN, and an HTTP GET with SQLi/XSS/LFI patterns.

This DOES NOT send any packets. It only writes PCAP files you can feed to the IPS.
"""

from scapy.all import *
from pathlib import Path
import random

def three_way_handshake(src, dst, sport, dport, isn=None):
    if isn is None:
        isn = random.randint(1, 2**32 - 1)
    pkts = []
    syn = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=isn)
    synack = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="SA", seq=1000, ack=isn+1)
    ack = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="A", seq=isn+1, ack=1001)
    pkts += [syn, synack, ack]
    return pkts

def simple_http_get(src, dst, sport, dport=80, host="example.com", path="/"):
    handshake = three_way_handshake(src, dst, sport, dport)
    get = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="PA", seq=handshake[-1][TCP].seq, ack=handshake[-1][TCP].ack)/Raw(
        load=f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Demo\r\n\r\n".encode()
    )
    http_ok = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="PA", seq=2000, ack=get[TCP].seq+len(bytes(get[Raw].load)))/Raw(
        load=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"
    )
    fin = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="FA", seq=get[TCP].seq+len(bytes(get[Raw].load)), ack=http_ok[TCP].seq+len(bytes(http_ok[Raw].load)))
    finack = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="FA", seq=http_ok[TCP].seq+len(bytes(http_ok[Raw].load)), ack=fin[TCP].seq+1)
    lastack = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="A", seq=fin[TCP].seq+1, ack=finack[TCP].seq+1)
    return handshake + [get, http_ok, fin, finack, lastack]

def icmp_echo_flood(src, dst, count=120):
    pkts = []
    for i in range(count):
        pkts.append(IP(src=src, dst=dst)/ICMP(type=8, code=0)/Raw(load=b"flood"))
    return pkts

def syn_scan(src, dst, ports, base_seq=3000):
    pkts = []
    for i, p in enumerate(ports):
        pkts.append(IP(src=src, dst=dst)/TCP(sport=40000+i, dport=p, flags="S", seq=base_seq+i))
    return pkts

def null_fin_scans(src, dst, ports):
    pkts = []
    for i, p in enumerate(ports):
        # NULL
        pkts.append(IP(src=src, dst=dst)/TCP(sport=41000+i, dport=p, flags=0))
        # FIN (no ACK/SYN)
        pkts.append(IP(src=src, dst=dst)/TCP(sport=42000+i, dport=p, flags="F"))
        # Xmas (FIN+PSH+URG)
        pkts.append(IP(src=src, dst=dst)/TCP(sport=43000+i, dport=p, flags="FPU"))
    return pkts

def http_attack_payload(src, dst, sport, dport=80, host="victim.local"):
    handshake = three_way_handshake(src, dst, sport, dport)
    payload = (
        "GET /search?q=' OR 1=1 -- &x=<script>alert(1)</script>&p=../../etc/passwd HTTP/1.1\r\n"
        f"Host: {host}\r\nUser-Agent: BadActor\r\n\r\n"
    ).encode()
    get = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="PA", seq=handshake[-1][TCP].seq, ack=handshake[-1][TCP].ack)/Raw(load=payload)
    # server RST (simulate drop)
    rst = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="R", seq=10000, ack=get[TCP].seq+len(payload))
    return handshake + [get, rst]

def save_pcap(name, packets):
    wrpcap(name, packets)
    print(f"Wrote {name} ({len(packets)} packets)")

def main():
    outdir = Path(".")
    normal = []
    normal += simple_http_get("10.0.0.2", "10.0.0.10", sport=12345, path="/")
    normal += simple_http_get("10.0.0.3", "10.0.0.10", sport=12346, path="/about")
    save_pcap(str(outdir / "normal.pcap"), normal)

    malicious = []
    # ICMP flood (trigger)
    malicious += icmp_echo_flood("192.168.1.50", "10.0.0.10", count=120)
    # SYN scan across many unique ports (trigger)
    ports = list(range(1, 60))  # 59 ports in a short window
    malicious += syn_scan("192.168.1.60", "10.0.0.10", ports)
    # NULL/FIN/Xmas flags (trigger)
    malicious += null_fin_scans("192.168.1.61", "10.0.0.10", [22, 80, 443, 445, 3389, 8080, 8443])
    # HTTP payload with bad signatures (trigger)
    malicious += http_attack_payload("192.168.1.70", "10.0.0.10", sport=12355)

    save_pcap(str(outdir / "malicious.pcap"), malicious)

if __name__ == "__main__":
    main()
