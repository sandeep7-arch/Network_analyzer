import datetime
import time
import re
from collections import Counter
from scapy.all import IP, TCP, UDP, ICMP, Raw, ARP, Ether, DNS, DNSQR, DNSRR , DHCP , BOOTP

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
        self.ssh_brute_tracker = {} # {ip: {"count": X, "start": timestamp}}
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
            self._check_udp_flood,

            self._check_tcp_flag_anomalies,
            self._check_web_payloads,
            self._check_smurf_attack,
            self._check_ssh_brute_force,
            self._check_dns_rebinding,
            self._check_credit_card_leak,
            self._check_bad_user_agent,
            self._check_rogue_dhcp,
            self._check_nop_sled
        ]

    def process_packet(self, packet):
        """Main entry point for packet analysis."""
        # 1. Update Storage & Prevent Memory Leaks
        self.packets.append(packet)
        if len(self.packets) > 10000:
            old_pkt = self.packets.pop(0)
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
            if now - data["start"] > 10:
                data = {"count": 1, "start": now}
            else:
                data["count"] += 1

            self.syn_scan_tracker[src] = data
            if data["count"] > 25:
                self.syn_scan_tracker.pop(src, None) # Reset after alert
                return "WARNING", f"SYN Scan from {src} (>25 in 10s)"

    def _check_land_attack(self, pkt):
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

    # --- NEW RULES ---

    def _check_tcp_flag_anomalies(self, pkt):
        """Detects Null and Xmas Scans."""
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags == 0:
                return "WARNING", f"TCP Null Scan detected from {pkt[IP].src}"
            # FIN (0x01) + PSH (0x08) + URG (0x20) = 0x29
            if (flags & 0x29) == 0x29:
                return "WARNING", f"TCP Xmas Scan detected from {pkt[IP].src}"

    def _check_web_payloads(self, pkt):
        """Checks for SQLi and XSS patterns in raw payload."""
        if pkt.haslayer(Raw):
            try:
                load = bytes(pkt[Raw].load).lower()
                sqli_sigs = [b"union select", b"or 1=1", b"drop table", b"insert into", b"--"]
                xss_sigs = [b"<script>", b"javascript:", b"onload=", b"onerror="]

                if any(x in load for x in sqli_sigs):
                    return "CRITICAL", f"Possible SQL Injection from {pkt[IP].src}"
                if any(x in load for x in xss_sigs):
                    return "CRITICAL", f"Possible XSS Attempt from {pkt[IP].src}"
            except: pass

    def _check_smurf_attack(self, pkt):
        """Detects ICMP Echo Requests to broadcast addresses."""
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            if pkt[ICMP].type == 8: # Echo Request
                dst_ip = str(pkt[IP].dst)
                if dst_ip.endswith(".255"):
                    return "HIGH", f"Smurf Attack Detected: Ping to Broadcast {dst_ip}"

    def _check_ssh_brute_force(self, pkt):
        """Alerts if > 5 connections to Port 22 in 10s."""
        if pkt.haslayer(TCP) and pkt[TCP].dport == 22 and pkt[TCP].flags == 0x02: # SYN
            src = str(pkt[IP].src)
            now = time.time()

            data = self.ssh_brute_tracker.get(src, {"count": 0, "start": now})
            if now - data["start"] > 10:
                data = {"count": 1, "start": now}
            else:
                data["count"] += 1

            self.ssh_brute_tracker[src] = data
            if data["count"] > 5:
                self.ssh_brute_tracker.pop(src, None)
                return "HIGH", f"SSH Brute Force Attempt from {src}"

    def _check_dns_rebinding(self, pkt):
        """Checks if a public domain resolves to a private IP (DNS Rebinding)."""
        if pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
            # Iterate through answers (ancount)
            for x in range(pkt[DNS].ancount):
                rr = pkt[DNS].an[x]
                if rr.type == 1: # A Record
                    ip = rr.rdata
                    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
                        try:
                            qname = pkt[DNS].qd.qname.decode().lower()
                            # Whitelist legitimate local domains if needed
                            if "local" not in qname:
                                return "CRITICAL", f"DNS Rebinding: {qname} -> {ip}"
                        except: pass

    def _check_credit_card_leak(self, pkt):
        """DLP: Checks for Visa/Mastercard patterns in cleartext."""
        if pkt.haslayer(Raw):
            try:
                load = pkt[Raw].load.decode('utf-8', errors='ignore')
                # Regex for 13-16 digit numbers (Basic check)
                # Matches: 1234-5678-1234-5678 or 1234567812345678
                if re.search(r'\b(?:\d[ -]*?){13,16}\b', load):
                    return "CRITICAL", f"Potential Credit Card Data Leaked from {pkt[IP].src}"
            except: pass

    def _check_bad_user_agent(self, pkt):
        """Detects tools like Nmap, Sqlmap, Nikto scanning your web server."""
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].dport in [80, 8080, 443]:
            try:
                load = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
                bad_agents = ["sqlmap", "nikto", "nmap", "masscan", "python-requests"]
                if "user-agent:" in load:
                    for agent in bad_agents:
                        if agent in load:
                            return "HIGH", f"Suspicious User-Agent '{agent}' from {pkt[IP].src}"
            except: pass

    def _check_rogue_dhcp(self, pkt):
        """Detects DHCP Offers. In a secure network, only your router should do this."""
        if pkt.haslayer(DHCP):
            # DHCP Message Type 2 is 'Offer' (Server to Client)
            # Scapy options is a list of tuples: [('message-type', 2), ('end', None)]
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == 'message-type' and opt[1] == 2:
                     server_ip = pkt[IP].src
                     # You could add a whitelist here: if server_ip != "192.168.1.1": return CRITICAL
                     return "WARNING", f"DHCP Offer detected from {server_ip} (Potential Rogue Server)"

    def _check_nop_sled(self, pkt):
        """Detects buffer overflow exploit attempts (Shellcode padding)."""
        if pkt.haslayer(Raw):
            try:
                load = pkt[Raw].load
                # Look for a sequence of 10+ NOP instructions (0x90)
                if b'\x90' * 10 in load:
                    return "CRITICAL", f"Possible Buffer Overflow Attack (NOP Sled) from {pkt[IP].src}"
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
