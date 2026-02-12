import datetime
from scapy.all import IP, TCP, UDP, ICMP, Raw

class PacketAnalyzer:
    def __init__(self):
        self.alerts = []

    def check_packet(self, packet):
        alert_msg = None
        severity = "INFO"
        if packet.haslayer(IP):
            src, dst = packet[IP].src, packet[IP].dst
            if packet.haslayer(ICMP):
                alert_msg = f"ICMP Ping: {src} -> {dst}"
                severity = "NOTICE"
            if packet.haslayer(TCP):
                if packet[TCP].dport in [21, 22, 23, 445, 3389, 666, 4444]:
                    alert_msg = f"Sensitive Port Accessed: {packet[TCP].dport}"
                    severity = "WARNING"
            if packet.haslayer(Raw):
                try:
                    payload = bytes(packet[Raw].load).lower()
                    if b"password" in payload or b"admin" in payload:
                        alert_msg = f"Cleartext Credentials Found!"
                        severity = "CRITICAL"
                except: pass
        if alert_msg:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            entry = (timestamp, severity, alert_msg)
            if not self.alerts or self.alerts[-1][2] != alert_msg:
                self.alerts.append(entry)
            return severity, alert_msg
        return None, None

    def save_logs_to_file(self):
        if not self.alerts: return False, "No alerts to save."
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ids_log_{timestamp}.txt"
        try:
            with open(filename, "w") as f:
                f.write("--- NETWORK INTRUSION LOGS ---\n")
                for t, s, m in self.alerts: f.write(f"[{t}] [{s:<8}] {m}\n")
            return True, filename
        except Exception as e: return False, str(e)
