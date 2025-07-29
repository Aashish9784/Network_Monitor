# network_monitor.py

from scapy.all import sniff, IP, TCP, Raw
from collections import defaultdict
import time
import re

# --- IDS Variables ---
connection_tracker = defaultdict(list)
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 10

def detect_intrusion(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        current_time = time.time()

        connection_tracker[ip_src].append((dst_port, current_time))
        recent_ports = [
            port_time for port_time in connection_tracker[ip_src]
            if current_time - port_time[1] <= TIME_WINDOW
        ]
        connection_tracker[ip_src] = recent_ports

        # Port scan detection
        unique_ports = set([entry[0] for entry in recent_ports])
        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            print(f"[ALERT - IDS] Port scan from {ip_src}: ports {list(unique_ports)}")

        # SYN flood detection
        if flags == "S":
            syn_count = sum(1 for _, t in recent_ports if current_time - t <= TIME_WINDOW)
            if syn_count > PORT_SCAN_THRESHOLD * 2:
                print(f"[ALERT - IDS] SYN flood from {ip_src}")

def sniff_http_post(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors='ignore')
            if "POST" in payload:
                print("\n[INFO - SNIFFER] HTTP POST Request Detected:")
                print("-" * 60)
                print(payload)

                creds = re.findall(r"(username|user|email|login|password|pass)=([^&\s]+)", payload, re.IGNORECASE)
                if creds:
                    print("\n[*] Possible Credentials Found:")
                    for field, value in creds:
                        print(f"{field}: {value}")
                print("-" * 60)
        except Exception:
            pass  # Handle decoding issues silently

def packet_handler(packet):
    sniff_http_post(packet)     # Sniffer part
    detect_intrusion(packet)    # IDS part

def start_monitoring(interface):
    print(f"[+] Monitoring started on {interface}")
    sniff(iface=interface, filter="tcp", prn=packet_handler, store=False)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: sudo python3 network_monitor.py <interface>")
        sys.exit(1)
    interface = sys.argv[1]
    start_monitoring(interface)
