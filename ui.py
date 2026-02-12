import curses
import time
from scapy.all import IP, TCP, UDP, ICMP, ARP, Raw, Ether

class CursesUI:
    def __init__(self, stdscr, sniffer, analyzer):
        self.stdscr = stdscr
        self.sniffer = sniffer
        self.analyzer = analyzer
        self.scroll_offset = 0
        self.selected_idx = 0
        self.auto_scroll = True
        self.view_mode = "MENU" 
        self.status_msg = "Welcome. Press 'C' to Start."

        curses.start_color()
        curses.use_default_colors()
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        self.stdscr.keypad(True)

        curses.init_pair(1, curses.COLOR_GREEN, -1)   
        curses.init_pair(2, curses.COLOR_CYAN, -1)    
        curses.init_pair(3, curses.COLOR_MAGENTA, -1) 
        curses.init_pair(4, curses.COLOR_YELLOW, -1)  
        curses.init_pair(5, curses.COLOR_RED, -1)     
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_WHITE) 
        curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLUE)  

    def get_input(self, prompt_msg):
        self.stdscr.nodelay(False)
        curses.echo()
        curses.curs_set(1)
        h, w = self.stdscr.getmaxyx()
        win = curses.newwin(3, w//2, h//2 - 1, w//4)
        win.box()
        win.addstr(1, 1, prompt_msg)
        win.refresh()
        try:
            inp = win.getstr(1, len(prompt_msg) + 2, 30).decode('utf-8').strip()
        except: inp = ""
        curses.noecho()
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        return inp

    def _hexdump(self, src, length=16):
        """Standard hex dump: Offset | Hex | ASCII"""
        result = []
        for i in range(0, len(src), length):
            chunk = src[i:i + length]
            hexa = " ".join([f"{b:02x}" for b in chunk])
            text = "".join([chr(b) if 32 <= b <= 126 else "." for b in chunk])
            result.append(f"{i:04x}  {hexa:<{length*3}}  {text}")
        return result

    def draw_menu(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        menu_win = curses.newwin(10, 40, h//2 - 5, w//2 - 20)
        menu_win.box()
        menu_win.addstr(0, 12, " NETWORK MONITOR ", curses.A_BOLD)
        menu_win.addstr(2, 4, "[ C ] Start Live Capture")
        menu_win.addstr(3, 4, "[ L ] Load PCAP File")
        menu_win.addstr(5, 4, "[ Q ] Quit")
        self.stdscr.addstr(h-2, 2, f"Status: {self.status_msg}", curses.color_pair(4))
        self.stdscr.refresh(); menu_win.refresh()

    def draw_dashboard(self):
        h, w = self.stdscr.getmaxyx()
        # Ensure we don't try to draw if the window is too small
        if h < 10 or w < 40:
            self.stdscr.erase()
            self.stdscr.addstr(0, 0, "Terminal too small!")
            self.stdscr.refresh()
            return

        list_h = h // 2
        # Use h-1 for window heights to leave room for the footer
        self.win_list = curses.newwin(list_h, w, 0, 0)
        self.win_detail = curses.newwin(h - list_h - 2, w // 2, list_h, 0)
        self.win_alert = curses.newwin(h - list_h - 2, w // 2, list_h, w // 2)

        if self.view_mode == "LIST":
            self.update_packet_list()
        else:
            self.draw_stats_graphics()

        self.update_details()
        self.update_alerts()

        # THE FIX: Use w-1 to avoid the "Last Character" crash
        footer = f" [Q] Menu | [G] Graphs | [W] Save | [Space] Pause | {self.status_msg}"
        try:
            self.stdscr.attron(curses.A_REVERSE)
            # Writing up to w-1 prevents the addwstr() ERR
            self.stdscr.addstr(h-1, 0, footer[:w-1].ljust(w-1))
            self.stdscr.attroff(curses.A_REVERSE)
        except curses.error:
            pass # Ignore footer errors to prevent full crash

        self.stdscr.refresh()

    def update_details(self):
        self.win_detail.erase(); self.win_detail.box()
        self.win_detail.addstr(0, 2, " [ PACKET INSPECTOR ] ", curses.color_pair(7))
        h, w = self.win_detail.getmaxyx()
        if self.sniffer.packets and self.selected_idx < len(self.sniffer.packets):
            pkt = self.sniffer.packets[self.selected_idx]
            lines = []
            if pkt.haslayer(Ether): lines.append((f"Ether: {pkt[Ether].src} -> {pkt[Ether].dst}", 5))
            if pkt.haslayer(IP): lines.append((f"IP: {pkt[IP].src} -> {pkt[IP].dst} (TTL:{pkt[IP].ttl})", 4))
            if pkt.haslayer(TCP): lines.append((f"TCP: {pkt[TCP].sport} -> {pkt[TCP].dport} [{pkt[TCP].flags}]", 1))
            if pkt.haslayer(Raw):
                lines.append(("--- RAW PAYLOAD (HEX) ---", 0))
                for row in self._hexdump(bytes(pkt[Raw].load)): lines.append((row, 2))
            
            for i, (text, col) in enumerate(lines):
                if i >= h - 2: break
                self.win_detail.addstr(i+1, 2, text[:w-4], curses.color_pair(col))
        self.win_detail.refresh()

    def update_packet_list(self):
        self.win_list.erase(); h, w = self.win_list.getmaxyx()
        header = f" ID   TIME     PROT  SOURCE            DESTINATION     LEN "
        self.win_list.addstr(0, 0, header.ljust(w), curses.color_pair(7))
        pkts = self.sniffer.packets
        if not pkts: self.win_list.refresh(); return
        
        max_rows = h - 1
        if self.selected_idx >= len(pkts): self.selected_idx = len(pkts) - 1
        if self.selected_idx < self.scroll_offset: self.scroll_offset = self.selected_idx
        elif self.selected_idx >= self.scroll_offset + max_rows: self.scroll_offset = self.selected_idx - max_rows + 1

        for i in range(max_rows):
            idx = self.scroll_offset + i
            if idx >= len(pkts): break
            p = pkts[idx]
            proto = "TCP" if p.haslayer(TCP) else "UDP" if p.haslayer(UDP) else "ICMP" if p.haslayer(ICMP) else "OTH"
            src = p[IP].src if p.haslayer(IP) else "Local"
            dst = p[IP].dst if p.haslayer(IP) else "Local"
            row = f"{idx:<4} {time.strftime('%H:%M:%S', time.localtime(p.time))} {proto:<4} {src:>15} -> {dst:<15} {len(p)}"
            color = curses.color_pair(1 if proto=="TCP" else 2 if proto=="UDP" else 3)
            if idx == self.selected_idx: self.win_list.attron(curses.color_pair(6))
            else: self.win_list.attron(color)
            self.win_list.addstr(i+1, 0, row[:w-1])
            self.win_list.attroff(curses.color_pair(6) if idx == self.selected_idx else color)
            self.analyzer.check_packet(p)
        self.win_list.refresh()

    def draw_stats_graphics(self):
        self.win_list.erase(); self.win_list.box()
        self.win_list.addstr(0, 2, " [ NETWORK ANALYTICS ] ", curses.color_pair(7))
        h, w = self.win_list.getmaxyx()
        protos = self.sniffer.stats["protocols"]
        total = sum(protos.values()) or 1
        for i, (name, count) in enumerate(protos.items()):
            if i > 4: break
            bar = "█" * int((count/total)*(w//4))
            self.win_list.addstr(2+i, 2, f"{name:<6}: {bar} {count}", curses.color_pair(i%3+1))
        self.win_list.refresh()

    def update_alerts(self):
        self.win_alert.erase(); self.win_alert.box()
        self.win_alert.addstr(0, 2, " [ THREAT ALERTS ] ", curses.color_pair(7))
        recent = self.analyzer.alerts[-(self.win_alert.getmaxyx()[0]-3):]
        for i, (ts, sev, msg) in enumerate(recent):
            self.win_alert.addstr(i+1, 1, f"[{ts}] {msg}"[:self.win_alert.getmaxyx()[1]-2], curses.color_pair(5 if sev=="CRITICAL" else 4))
        self.win_alert.refresh()

    def run(self):
        while True:
            if self.view_mode == "MENU":
                self.draw_menu()
                key = self.stdscr.getch()
                if key in [ord('c'), ord('C')]: self.sniffer.start_live(); self.view_mode = "LIST"
                elif key in [ord('l'), ord('L')]:
                    fname = self.get_input("Load File:")
                    if fname:
                        success, msg = self.sniffer.load_from_file(fname)
                        self.status_msg = msg
                        if success: self.view_mode = "LIST"
                elif key in [ord('q'), ord('Q')]: break
            else:
                if self.sniffer.mode == "LIVE" and not self.sniffer.paused and self.auto_scroll:
                    if self.sniffer.packets: self.selected_idx = len(self.sniffer.packets)-1
                self.draw_dashboard()
                key = self.stdscr.getch()
                if key == ord('q'): self.view_mode = "MENU"
                elif key == ord('g'): self.view_mode = "STATS" if self.view_mode == "LIST" else "LIST"
                elif key == ord(' '): self.sniffer.toggle_pause()
                elif key == ord('w') or key == ord('W'):
                    fname = self.get_input("Save as:")
                    if fname:
                        success, msg = self.sniffer.save_capture(fname)
                        self.status_msg = msg
                elif key == curses.KEY_DOWN:
                    self.selected_idx = min(len(self.sniffer.packets)-1, self.selected_idx + 1)
                elif key == curses.KEY_UP:
                    self.selected_idx = max(0, self.selected_idx - 1); self.auto_scroll = False
            time.sleep(0.05)
