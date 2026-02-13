import curses
import sys
import time
import threading
import os
from queue import Queue

from sniffer import NetworkSniffer
from analyzer import PacketAnalyzer
from ui import CursesUI

def main(stdscr):
    # 1. Create the Shared Queue
    packet_queue = Queue()

    # 2. Initialize Components
    sniffer = NetworkSniffer(packet_queue, interface=None)
    analyzer = PacketAnalyzer()

    # 3. Start the Analyzer Worker Thread
    def analyzer_worker():
        while True:
            pkt = packet_queue.get()
            analyzer.process_packet(pkt)
            packet_queue.task_done()

    worker_thread = threading.Thread(target=analyzer_worker, daemon=True)
    worker_thread.start()

    # 4. Initialize UI (Main Thread)
    ui = CursesUI(stdscr, sniffer, analyzer)

    try:
        ui.run()
    finally:
        sniffer.stop()

def sanitize_environment():
    for key, value in list(os.environ.items()):
        if '\x00' in value: os.environ[key] = value.replace('\x00', '')

if __name__ == "__main__":
    try:
        sanitize_environment()
        if 'TERM' not in os.environ: os.environ['TERM'] = 'xterm-256color'

        print("Initializing Threaded Network Tool...")
        time.sleep(0.5)

        curses.wrapper(main)

    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        curses.endwin()
        print(f"\n[CRASH LOG] {e}")
        import traceback
        traceback.print_exc()
