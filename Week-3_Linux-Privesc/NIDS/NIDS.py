#!/usr/bin/env python3
from scapy.all import *
from collections import defaultdict
import time
import argparse

class LightweightNIDS:
    def __init__(self, threshold=10, time_window=5):
        self.icmp_count = defaultdict(int)
        self.syn_count = defaultdict(lambda: defaultdict(int))
        self.scan_attempts = defaultdict(int)
        self.threshold = threshold
        self.time_window = time_window
        self.last_reset = time.time()
        
    def reset_counts(self):
        current_time = time.time()
        if current_time - self.last_reset > self.time_window:
            self.icmp_count.clear()
            self.syn_count.clear()
            self.scan_attempts.clear()
            self.last_reset = current_time
    
    def detect_icmp_flood(self, pkt):
        if ICMP in pkt and (pkt[ICMP].type == 8 or pkt[ICMP].type == 0):
            src = pkt[IP].src
            self.icmp_count[src] += 1
            
            if self.icmp_count[src] > self.threshold:
                print(f"[!] ICMP Flood detected from {src} - {self.icmp_count[src]} packets")
    
    def detect_port_scan(self, pkt):
        if TCP in pkt and pkt[TCP].flags & 0x02:  # SYN flag
            src = pkt[IP].src
            dst_port = pkt[TCP].dport
            
            self.syn_count[src][dst_port] += 1
            total_syns = sum(self.syn_count[src].values())
            
            if len(self.syn_count[src]) > self.threshold:
                print(f"[!] Port Scan detected from {src} - {len(self.syn_count[src])} ports targeted")
            elif total_syns > self.threshold * 2:
                print(f"[!] SYN Flood detected from {src} - {total_syns} SYN packets")
    
    def detect_scan_patterns(self, pkt):
        if TCP in pkt:
            flags = pkt[TCP].flags
            src = pkt[IP].src
            
            # NULL scan (no flags)
            if flags == 0:
                self.scan_attempts[src] += 1
                print(f"[!] NULL Scan detected from {src}")
            
            # FIN scan (only FIN)
            elif flags & 0x01 and not flags & 0x02:
                self.scan_attempts[src] += 1
                print(f"[!] FIN Scan detected from {src}")
    
    def process_packet(self, pkt):
        if not IP in pkt:
            return
            
        self.reset_counts()
        self.detect_icmp_flood(pkt)
        self.detect_port_scan(pkt)
        self.detect_scan_patterns(pkt)

def main():
    parser = argparse.ArgumentParser(description="Lightweight NIDS")
    parser.add_argument("-i", "--interface", help="Network interface for live capture")
    parser.add_argument("-r", "--pcap", help="PCAP file for offline analysis")
    parser.add_argument("-t", "--threshold", type=int, default=10, 
                       help="Alert threshold for suspicious activities")
    args = parser.parse_args()

    nids = LightweightNIDS(threshold=args.threshold)
    
    if args.pcap:
        print(f"[*] Analyzing PCAP file: {args.pcap}")
        sniff(offline=args.pcap, prn=nids.process_packet, store=0)
    elif args.interface:
        print(f"[*] Monitoring interface: {args.interface}")
        sniff(iface=args.interface, prn=nids.process_packet, store=0)
    else:
        print("[!] Please specify either an interface or PCAP file")
        parser.print_help()

if __name__ == "__main__":
    main()
