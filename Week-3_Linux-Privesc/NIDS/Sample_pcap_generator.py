from scapy.all import *
from random import randint

def generate_icmp_flood():
    packets = []
    for i in range(20):  # 20 ICMP packets
        pkt = IP(dst="192.168.1.1")/ICMP(type=8)/("X"*64)
        packets.append(pkt)
    wrpcap("icmp_flood.pcap", packets)

def generate_syn_scan():
    packets = []
    for port in range(1, 21):  # SYN to 20 ports
        pkt = IP(dst="192.168.1.1")/TCP(dport=port, flags="S")
        packets.append(pkt)
    wrpcap("syn_scan.pcap", packets)

def generate_mixed_traffic():
    packets = []
    # Normal HTTP traffic
    packets.append(IP(dst="192.168.1.1")/TCP(dport=80, flags="A")/Raw(load="GET / HTTP/1.1"))
    # Suspicious NULL scan
    packets.append(IP(dst="192.168.1.1")/TCP(dport=22, flags=""))
    # Normal DNS query
    packets.append(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")))
    # Suspicious FIN scan
    packets.append(IP(dst="192.168.1.1")/TCP(dport=3389, flags="F"))
    wrpcap("mixed_traffic.pcap", packets)

generate_icmp_flood()
generate_syn_scan()
generate_mixed_traffic()
