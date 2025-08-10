from scapy.all import sniff, IP, TCP
from datetime import datetime

SUSPICIOUS_PORTS = [23, 2323]
SUSPICIOUS_IPS = ['192.168.1.100']

def analyze_packet(packet, log_callback, alert_callback):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        info = f"[{timestamp}] {src} → {dst} | Protocol: {proto}"
        log_callback(info)

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            if dport in SUSPICIOUS_PORTS or src in SUSPICIOUS_IPS:
                alert_msg = f"Suspicious traffic from {src} to port {dport}"
                if alert_callback:
                    alert_callback(alert_msg)

def start_monitoring(log_callback, alert_callback=None):
    sniff(
        prn=lambda pkt: analyze_packet(pkt, log_callback, alert_callback),
        store=False
    )
