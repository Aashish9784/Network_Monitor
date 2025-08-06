# Network_Monitor
# Network Monitor: Packet Sniffer + IDS

This tool combines a basic packet sniffer with intrusion detection in one Python script.

## ⚠️ Disclaimer
This tool is intended strictly for educational purposes on networks you own or are authorized to monitor. Unauthorized use may violate ethical and legal boundaries.



## 🚀 Features

- Capture HTTP POST data (sniffer)
- Detect port scanning
- Detect SYN flood attacks
- Print possible credentials in plain HTTP

## Future Release:
We can expand it with:
- File logging / PCAP export
- Email alerts or webhook (Discord, Slack)
- GUI (with Tkinter or web dashboard)
- ARP spoof detection

## 🔄 Update: ARP Spoof Detection & Logging (v2)
This version introduces key enhancements:

🛡️ ARP Spoof Detection: Monitors ARP replies and detects changes in IP–MAC mappings to alert for spoofing attempts.

📄 Alert Logging: All alerts (port scans, SYN floods, ARP spoofing, possible credentials) are now saved to a timestamped alerts.log file.

⚙️ Refactored Alert System: Alerts are unified through a log_alert() function that handles console output and persistent logging.

These additions strengthen the tool's capability as a lightweight IDS.

## 📦 Requirements

```bash
pip install scapy


