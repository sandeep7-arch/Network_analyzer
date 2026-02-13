import threading
import time
import os
from scapy.all import sniff, rdpcap, wrpcap

class NetworkSniffer:
    def __init__(self, packet_queue, interface=None):
        self.packet_queue = packet_queue
        self.interface = interface
        self.running = False
        self.paused = False
        self.stop_event = threading.Event()
        self.thread = None
        self.mode = "IDLE"

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
                # store=0 prevents Scapy from eating RAM
                try:
                    sniff(count=1,
                          prn=lambda x: self.packet_queue.put(x),
                          store=0,
                          iface=self.interface,
                          timeout=1)
                except:
                    pass
            else:
                time.sleep(0.1)

    def load_from_file(self, filename):
        if os.path.exists(filename):
            try:
                pkts = rdpcap(filename)
                # Feed the file packets into the queue for analysis
                for p in pkts:
                    self.packet_queue.put(p)
                self.mode = "FILE"
                return True, f"Loaded {len(pkts)} packets."
            except Exception as e:
                return False, f"PCAP Error: {e}"
        return False, f"File not found."

    def toggle_pause(self):
        self.paused = not self.paused
        return self.paused

    def save_capture(self, packets_list, filename="capture.pcap"):
        try:
            if not filename.endswith(".pcap"): filename += ".pcap"
            wrpcap(filename, packets_list)
            return True, f"Saved to {filename}"
        except Exception as e:
            return False, f"Error: {e}"

    def stop(self):
        self.stop_event.set()
        self.running = False
