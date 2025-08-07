from scapy.all import sniff, IP, TCP
from datetime import datetime

# Define suspicious ports or IPs to flag alerts
SUSPICIOUS_PORTS = [23, 2323]  # Example: Telnet ports
SUSPICIOUS_IPS = ['192.168.1.100']  # Add known malicious IPs if needed

def analyze_packet(packet, log_callback, alert_callback):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        info = f"[{timestamp}] {src} → {dst} | Protocol: {proto}"
        log_callback(info)

        # Basic suspicious activity detection
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            if dport in SUSPICIOUS_PORTS or src in SUSPICIOUS_IPS:
                alert = f"⚠️ Suspicious traffic from {src} to port {dport}"
                alert_callback(alert)

def start_monitoring(log_callback, alert_callback=None):
    """
    Start packet sniffing. Send logs and optional alerts to callbacks.
    """
    sniff(
        prn=lambda pkt: analyze_packet(pkt, log_callback, alert_callback),
        store=False
    )

