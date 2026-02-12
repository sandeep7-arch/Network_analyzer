import curses
import sys
import time
import os
from sniffer import NetworkSniffer
from analyzer import PacketAnalyzer
from ui import CursesUI

def main(stdscr):
    sniffer = NetworkSniffer(interface=None)
    analyzer = PacketAnalyzer()
    ui = CursesUI(stdscr, sniffer, analyzer)
    try:
        ui.run()
    finally:
        sniffer.stop()

def sanitize_environment():
    for key, value in list(os.environ.items()):
        if '\x00' in value:
            if key == 'TERM':
                os.environ['TERM'] = 'xterm-256color'
            else:
                os.environ[key] = value.replace('\x00', '')
    sys.argv = [arg.replace('\x00', '') for arg in sys.argv]

if __name__ == "__main__":
    try:
        sanitize_environment()
        if 'TERM' not in os.environ or not os.environ['TERM']:
             os.environ['TERM'] = 'xterm-256color'
        print("Initializing Network Tool...")
        time.sleep(0.5)
        curses.wrapper(main)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"\n[CRASH] {e}")
        import traceback
        traceback.print_exc()
