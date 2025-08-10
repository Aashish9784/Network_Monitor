# 🛡️ Network Monitor: Packet Sniffer + Intrusion Detection (Web-Based)

This tool combines a real-time packet sniffer and basic intrusion detection system (IDS) into a Flask-powered browser interface.

---

## ⚠️ Disclaimer

This tool is intended strictly for educational purposes on networks you own or are authorized to monitor.  
**Do not run this on unauthorized networks** — misuse may be illegal.

---

## 🚀 Features

- 🌐 Web-based live dashboard (Flask + JS)
- 📡 Real-time packet sniffing using Scapy
- 🔍 Detects suspicious traffic:
  - Access to Telnet ports (23, 2323)
  - Traffic from blacklisted IPs
- 🔔 Instant alert toasts in browser with **timestamps**
- 🧠 Logs full IP/TCP traffic
- 🧪 Works locally, no external connections
- ✅ Auto-launches browser on startup

---

## 🔄 Updates in Current Version

### ✔️ Structured Alerts with Timestamps

- Alerts now include both **timestamp** and **message** for better clarity  
- Frontend toast notifications display `[timestamp] message` format  
- Backend remains lightweight while keeping real-time performance

### ✔️ TCP/IP Analysis + Web UI Integration

- Captures live packets using Scapy
- Logs source/destination IPs, protocol types, and ports
- Detects and displays alerts for suspicious patterns
- Fully integrated with browser GUI

---

## 📦 Installation

Install required Python libraries:

```bash
pip install -r requirements.txt

```

🪟 Windows Only: Install Npcap (Required for Scapy)
📥 Download: Npcap Official Site

✅ During installation, enable:

✔ Install in WinPcap API-compatible Mode

✔ Support raw 802.11 traffic

▶️ How To Run

```bash
python app.py
```
This will:

✅ Start the Flask server

✅ Open your default browser

✅ Begin monitoring packets instantly

💡 Planned Features
✅ Export logs to file or CSV

✅ Email / Slack / Discord webhook alerts

✅ Interface selector (Wi-Fi vs Ethernet)

✅ Filter/sort by IP, port, timestamp

✅ One-click .exe packaging

##👨‍💻 Built by Ashish B Sharma | Made with Flask + Scapy
