import datetime
import time
from collections import Counter
from scapy.all import IP, TCP, UDP, ICMP, Raw, ARP, Ether

class PacketAnalyzer:
    def __init__(self):
        # --- DATA STORAGE ---
        self.packets = []       # UI reads from here
        self.alerts = []        # Global threat feed
        self.packet_map = {}    # Specific packet alerts (Inspector Mode)

        # --- STATISTICS ---
        self.stats = {
            "protocols": Counter(),
            "src_ips": Counter(),
            "flags": Counter(),
            "pps_history": [0] * 30
        }
        self.current_sec_count = 0
        self.last_tick = time.time()

        # --- ADAPTABLE RULES ---
        self.rules = [
            self._check_icmp,
            self._check_sensitive_ports,
            self._check_cleartext_creds,
        ]

    def process_packet(self, packet):
        """Called by the Worker Thread for every packet in the Queue."""
        # 1. Update Storage (Keep last 10,000 to save RAM)
        self.packets.append(packet)
        if len(self.packets) > 10000:
            self.packets.pop(0)

        # 2. Update Stats
        self._update_stats(packet)

        # 3. Run Security Checks
        self._run_security_rules(packet)

    def _update_stats(self, packet):
        self.current_sec_count += 1

        # PPS Clock logic
        now = time.time()
        if now - self.last_tick >= 1.0:
            self.stats["pps_history"].pop(0)
            self.stats["pps_history"].append(self.current_sec_count)
            self.current_sec_count = 0
            self.last_tick = now

        # Protocol Counters
        if packet.haslayer(IP):
            self.stats["src_ips"][packet[IP].src] += 1
            if packet.haslayer(TCP):
                self.stats["protocols"]["TCP"] += 1
                self.stats["flags"][str(packet[TCP].flags)] += 1
            elif packet.haslayer(UDP):
                self.stats["protocols"]["UDP"] += 1
            elif packet.haslayer(ICMP):
                self.stats["protocols"]["ICMP"] += 1
        elif packet.haslayer(ARP):
            self.stats["protocols"]["ARP"] += 1

    def _run_security_rules(self, packet):
        pkt_id = id(packet)
        found_alerts = []

        for rule in self.rules:
            try:
                result = rule(packet)
                if result:
                    severity, msg = result
                    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                    found_alerts.append((timestamp, severity, msg))
            except: continue

        if found_alerts:
            self.packet_map[pkt_id] = found_alerts
            for entry in found_alerts:
                # Avoid spamming the global feed with duplicates
                if not self.alerts or self.alerts[-1][2] != entry[2]:
                    self.alerts.append(entry)

    # --- DETECTION RULES ---
    def _check_icmp(self, pkt):
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            return "NOTICE", f"ICMP Ping: {pkt[IP].src} -> {pkt[IP].dst}"

    def _check_sensitive_ports(self, pkt):
        if pkt.haslayer(TCP):
            ports = {21:"FTP", 22:"SSH", 23:"Telnet", 445:"SMB", 3389:"RDP", 8080:"HTTP-Alt"}
            if pkt[TCP].dport in ports:
                return "WARNING", f"Sensitive Port: {pkt[TCP].dport} ({ports[pkt[TCP].dport]})"

    def _check_cleartext_creds(self, pkt):
        if pkt.haslayer(Raw):
            try:
                load = bytes(pkt[Raw].load).lower()
                if any(x in load for x in [b"password", b"admin", b"login", b"root"]):
                    return "CRITICAL", "Cleartext Credentials Found!"
            except: pass

    # --- UTILITY ---
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
