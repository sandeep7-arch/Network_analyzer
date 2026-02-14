# 🛡️ Network Traffic Analyzer & IDS

A lightweight, terminal-based network analyzer tool featuring **automated malicious packet detection**. This tool captures live traffic and runs it against **16 different security tests** to identify potential threats in real-time.

> **⚠️ System Requirements:** This tool is designed for **Linux** systems and requires **Root (Sudo)** privileges to access network interfaces.

---

## 🚀 Features
* **Real-Time Sniffing:** Live packet capture and analysis.
* **Terminal UI:** Clean dashboard powered by `curses`.
* **16+ Threat Detection Modules:**
    * DLP (Credit Card Leaks)
    * Infrastructure (Rogue DHCP, ARP Spoofing)
    * Web Attacks (SQL Injection, XSS, Bad User-Agents)
    * Scanning (SYN Scan, Xmas Scan, Null Scan)
    * Flooding (UDP Flood, ICMP Smurf)

---

## 📦 Installation

To run this tool, you need to install the necessary dependencies (`scapy` for packet handling and `curses` for the interface).

### 1. Clone the Repository
```bash
git clone [https://github.com/yourusername/your-repo-name.git](https://github.com/yourusername/your-repo-name.git)
cd your-repo-name
