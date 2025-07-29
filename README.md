# Network_Monitor
# Network Monitor: Packet Sniffer + IDS

This tool combines a basic packet sniffer with intrusion detection in one Python script.

Functionality	                      Sniffer	        IDS
Capture packets	                      ✅	          ✅
Show POST data / creds	              ✅	          ❌
Detect port scan / SYN flood	        ❌	          ✅



## 🚀 Features

- Capture HTTP POST data (sniffer)
- Detect port scanning
- Detect SYN flood attacks
- Print possible credentials in plain HTTP

## 📦 Requirements

```bash
pip install scapy

**#Future Release:
We can expand it with:
- File logging / PCAP export
- Email alerts or webhook (Discord, Slack)
- GUI (with Tkinter or web dashboard)
- ARP spoof detection**
