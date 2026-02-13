import datetime
import time
from collections import Counter
from scapy.all import IP, TCP, UDP, ICMP, Raw, ARP, Ether, DNS

class PacketAnalyzer:
    def __init__(self):
        # --- DATA STORAGE ---
        self.packets = []       # UI reads from here
        self.alerts = []        # Global threat feed
        self.packet_map = {}    # Specific packet alerts {pkt_id: [alerts]}

        # --- STATISTICS ---
        self.stats = {
            "protocols": Counter(),
            "src_ips": Counter(),
            "flags": Counter(),
            "pps_history": [0] * 30
        }
        self.current_sec_count = 0
        self.last_tick = time.time()

        # --- TRACKERS (With Timestamps for Rate Limiting) ---
        self.syn_scan_tracker = {}  # {ip: {"count": X, "start": timestamp}}
        self.udp_flood_tracker = {} # {ip: {"count": X, "start": timestamp}}
        self.ip_mac_table = {}      # {ip: mac}

        # --- REGISTERED RULES ---
        self.rules = [
            self._check_icmp,
            self._check_sensitive_ports,
            self._check_cleartext_creds,
            self._check_syn_scan,
            self._check_land_attack,
            self._check_arp_spoofing,
            self._check_dns_anomaly,
            self._check_udp_flood
        ]

    def process_packet(self, packet):
        """Main entry point for packet analysis."""
        # 1. Update Storage & Prevent Memory Leaks
        self.packets.append(packet)
        if len(self.packets) > 10000:
            old_pkt = self.packets.pop(0)
            # Remove from packet_map to free RAM
            self.packet_map.pop(id(old_pkt), None)

        # 2. Update Stats
        self._update_stats(packet)

        # 3. Run Security Checks
        self._run_security_rules(packet)

    def _update_stats(self, packet):
        self.current_sec_count += 1
        now = time.time()

        # Update PPS history every second
        if now - self.last_tick >= 1.0:
            self.stats["pps_history"].pop(0)
            self.stats["pps_history"].append(self.current_sec_count)
            self.current_sec_count = 0
            self.last_tick = now

        if packet.haslayer(IP):
            src = str(packet[IP].src)
            self.stats["src_ips"][src] += 1

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
            except Exception:
                continue

        if found_alerts:
            self.packet_map[pkt_id] = found_alerts
            for entry in found_alerts:
                # Deduplication: Don't add if the last global alert was the same
                if not self.alerts or self.alerts[-1][2] != entry[2]:
                    self.alerts.append(entry)
                    if len(self.alerts) > 500: # Keep alert feed manageable
                        self.alerts.pop(0)

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
                keywords = [b"password", b"admin", b"login", b"root", b"user="]
                if any(x in load for x in keywords):
                    return "CRITICAL", "Cleartext Credentials Found!"
            except: pass

    def _check_syn_scan(self, pkt):
        """Alerts if >25 SYN packets from one IP within 10 seconds."""
        if pkt.haslayer(TCP) and pkt[TCP].flags == 0x02:
            src = str(pkt[IP].src) if pkt.haslayer(IP) else "Unknown"
            now = time.time()

            data = self.syn_scan_tracker.get(src, {"count": 0, "start": now})

            # Reset window if > 10 seconds passed
            if now - data["start"] > 10:
                data = {"count": 1, "start": now}
            else:
                data["count"] += 1

            self.syn_scan_tracker[src] = data

            if data["count"] > 25:
                self.syn_scan_tracker.pop(src, None) # Reset after alert
                return "WARNING", f"SYN Scan from {src} (>25 in 10s)"

    def _check_land_attack(self, pkt):
        """Source and Destination are identical (Loopback DoS)."""
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[IP].src == pkt[IP].dst and pkt[TCP].sport == pkt[TCP].dport:
                return "CRITICAL", "LAND Attack: Loopback DoS Detected!"

    def _check_arp_spoofing(self, pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 2: # ARP Reply
            ip, mac = str(pkt[ARP].psrc), str(pkt[ARP].hwsrc)
            if ip in self.ip_mac_table and self.ip_mac_table[ip] != mac:
                return "CRITICAL", f"ARP Spoof: {ip} moved to {mac}"
            self.ip_mac_table[ip] = mac

    def _check_udp_flood(self, pkt):
        """Alerts if >50 UDP packets from one IP within 5 seconds."""
        if pkt.haslayer(UDP) and pkt.haslayer(IP):
            src = str(pkt[IP].src)
            now = time.time()

            data = self.udp_flood_tracker.get(src, {"count": 0, "start": now})
            if now - data["start"] > 5:
                data = {"count": 1, "start": now}
            else:
                data["count"] += 1

            self.udp_flood_tracker[src] = data
            if data["count"] > 50:
                self.udp_flood_tracker.pop(src, None)
                return "HIGH", f"UDP Flood from {src}"

    def _check_dns_anomaly(self, pkt):
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0: # DNS Query
            try:
                qname = pkt[DNS].qd.qname.decode()
                if len(qname) > 65:
                    return "HIGH", f"Suspicious DNS Query: {qname[:20]}..."
            except: pass

    # --- UTILITY ---
    def save_logs_to_file(self):
        if not self.alerts: return False, "No alerts to save."
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ids_log_{timestamp}.txt"
        try:
            with open(filename, "w") as f:
                f.write(f"--- NETWORK INTRUSION LOGS ({timestamp}) ---\n")
                for t, s, m in self.alerts:
                    f.write(f"[{t}] [{s:<8}] {m}\n")
            return True, filename
        except Exception as e:
            return False, str(e)
