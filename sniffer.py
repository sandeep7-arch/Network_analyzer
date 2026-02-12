import threading
import time
import os
from collections import Counter
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP, ARP

class NetworkSniffer:
    def __init__(self, interface=None):
        self.interface = interface
        self.packets = []
        self.running = False
        self.paused = False
        self.stop_event = threading.Event()
        self.thread = None
        self.mode = "IDLE"

        self.stats = {
            "protocols": Counter(),
            "src_ips": Counter(),
            "flags": Counter(),
            "pps_history": [0] * 30 
        }
        self.current_sec_count = 0
        self.last_tick = time.time()

    def start_live(self):
        self.mode = "LIVE"
        self.running = True
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._sniff_loop)
        self.thread.daemon = True
        self.thread.start()

    def _sniff_loop(self):
        while not self.stop_event.is_set():
            if not self.paused:
                sniff(count=1, prn=self._process_packet, store=0, iface=self.interface, timeout=1)
                self._update_pps_clock()
            else:
                time.sleep(0.1)

    def _update_pps_clock(self):
        now = time.time()
        if now - self.last_tick >= 1.0:
            self.stats["pps_history"].pop(0)
            self.stats["pps_history"].append(self.current_sec_count)
            self.current_sec_count = 0
            self.last_tick = now

    def _process_packet(self, packet):
        self.packets.append(packet)
        self.current_sec_count += 1
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

    def load_from_file(self, filename):
        if os.path.exists(filename):
            try:
                pkts = rdpcap(filename)
                self.packets = [] # Clear existing
                for p in pkts: self._process_packet(p)
                self.mode = "FILE"
                return True, f"Loaded {len(pkts)} packets from {filename}"
            except Exception as e:
                return False, f"PCAP Error: {e}"
        return False, f"Error: File '{filename}' not found."

    def toggle_pause(self):
        self.paused = not self.paused
        return self.paused

    def save_capture(self, filename="capture.pcap"):
        if not self.packets:
            return False, "Nothing to save!"
        try:
            if not filename.endswith(".pcap"): filename += ".pcap"
            wrpcap(filename, self.packets)
            return True, f"Saved {len(self.packets)} packets to {filename}"
        except Exception as e:
            return False, f"Save Error: {e}"

    def stop(self):
        self.stop_event.set()
        self.running = False
