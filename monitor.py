from scapy.all import sniff, IP, TCP, Raw, ARP
from collections import defaultdict
import time
import re
import sys
import logging
from datetime import datetime

# --- Logging Setup ---
logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_alert(message):
    print(message)
    logging.info(message)

# --- IDS Variables ---
connection_tracker = defaultdict(list)
ip_mac_table = {}
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 10

# --- Intrusion Detection ---
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
            log_alert(f"[ALERT - IDS] Port scan from {ip_src}: ports {list(unique_ports)}")

        # SYN flood detection
        if flags == "S":
            syn_count = sum(1 for _, t in recent_ports if current_time - t <= TIME_WINDOW)
            if syn_count > PORT_SCAN_THRESHOLD * 2:
                log_alert(f"[ALERT - IDS] SYN flood from {ip_src}")

# --- HTTP POST Sniffer ---
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
                    log_alert(f"[ALERT - SNIFFER] Possible credentials found in HTTP POST: {creds}")
                print("-" * 60)
        except Exception:
            pass  # Handle decoding issues silently

# --- ARP Spoof Detection ---
def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in ip_mac_table:
            if ip_mac_table[ip] != mac:
                log_alert(f"[ALERT - IDS] ARP Spoofing Detected: {ip} is now at {mac} (was {ip_mac_table[ip]})")
        else:
            ip_mac_table[ip] = mac

# --- Packet Handler ---
def packet_handler(packet):
    if packet.haslayer(ARP):
        detect_arp_spoof(packet)
    elif packet.haslayer(IP) and packet.haslayer(TCP):
        sniff_http_post(packet)
        detect_intrusion(packet)

# --- Monitoring Start ---
def start_monitoring(interface):
    print(f"[+] Monitoring started on {interface}")
    sniff(iface=interface, filter="ip or arp", prn=packet_handler, store=False)

# --- Entry Point ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 network_monitor.py <interface>")
        sys.exit(1)
    interface = sys.argv[1]
    start_monitoring(interface)
