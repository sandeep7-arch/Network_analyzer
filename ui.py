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
        self.detail_offset = 0  # <--- New: Track scroll inside inspector
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
        except:
            inp = ""
        curses.noecho()
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        return inp

    def _hexdump(self, src, length=16):
        result = []
        for i in range(0, len(src), length):
            chunk = src[i:i + length]
            hexa = " ".join([f"{b:02x}" for b in chunk])
            text = "".join([chr(b) if 32 <= b <= 126 else "." for b in chunk])
            result.append(f"{i:04x}  {hexa:<{length*3}}  {text}")
        return result

    def _get_sparkline(self, data):
        if not data: return ""
        chars = [" ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        max_val = max(data) if max(data) > 0 else 1
        line = "".join([chars[int((val / max_val) * 7)] for val in data])
        return line

    def draw_menu(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        menu_win = curses.newwin(10, 40, h//2 - 5, w//2 - 20)
        menu_win.box()
        menu_win.addstr(0, 12, " NETWORK MONITOR ", curses.A_BOLD)
        menu_win.addstr(2, 4, "[ C ] Start Live Capture")
        menu_win.addstr(3, 4, "[ L ] Load PCAP File")
        menu_win.addstr(5, 4, "[ Q ] Quit")
        self.stdscr.addstr(h-2, 2, f"Status: {self.status_msg}"[:w-2], curses.color_pair(4))
        self.stdscr.refresh()
        menu_win.refresh()

    def draw_dashboard(self):
        h, w = self.stdscr.getmaxyx()
        if h < 10 or w < 40:
            self.stdscr.erase()
            self.stdscr.addstr(0, 0, "Terminal too small!")
            self.stdscr.refresh()
            return

        list_h = h // 2
        self.win_list = curses.newwin(list_h, w, 0, 0)
        self.win_detail = curses.newwin(h - list_h - 2, w // 2, list_h, 0)
        self.win_alert = curses.newwin(h - list_h - 2, w // 2, list_h, w // 2)

        if self.view_mode == "LIST":
            self.update_packet_list()
        else:
            self.draw_stats_graphics()

        self.update_details()
        self.update_alerts()

        # Status Bar Logic
        if self.sniffer.paused:
            status_text, status_col = " ○ PAUSED ", curses.color_pair(4)
        else:
            status_text, status_col = " ● LIVE   ", curses.color_pair(1)

        scroll_info = "[AUTO]" if self.auto_scroll else "[MANUAL]"
        menu_text = f" | {scroll_info} | [Q] Menu | [G] Stats | [PgUp/Dn] Inspect | {self.status_msg}"

        try:
            self.stdscr.attron(curses.A_REVERSE)
            self.stdscr.addstr(h-1, 0, " " * (w-1))
            self.stdscr.addstr(h-1, 0, status_text, status_col | curses.A_REVERSE | curses.A_BOLD)
            self.stdscr.addstr(h-1, len(status_text), menu_text[:w-len(status_text)-1])
            self.stdscr.attroff(curses.A_REVERSE)
        except curses.error: pass
        self.stdscr.refresh()

    def update_details(self):
        self.win_detail.erase()
        self.win_detail.box()
        self.win_detail.addstr(0, 2, " [ PACKET INSPECTOR ] ", curses.color_pair(7))
        h, w = self.win_detail.getmaxyx()

        if self.sniffer.packets and self.selected_idx < len(self.sniffer.packets):
            pkt = self.sniffer.packets[self.selected_idx]
            lines = []

            # 1. Summary Headers
            if pkt.haslayer(Ether): lines.append((f"Ether: {pkt[Ether].src} -> {pkt[Ether].dst}", 5))
            if pkt.haslayer(IP): lines.append((f"IP: {pkt[IP].src} -> {pkt[IP].dst} (TTL:{pkt[IP].ttl})", 4))
            if pkt.haslayer(TCP): lines.append((f"TCP: {pkt[TCP].sport} -> {pkt[TCP].dport} [{pkt[TCP].flags}]", 1))
            elif pkt.haslayer(UDP): lines.append((f"UDP: {pkt[UDP].sport} -> {pkt[UDP].dport}", 2))

            # 2. FULL Hex Dump (Wireshark Style)
            lines.append(("-" * (w-4), 0))
            lines.append(("FULL PACKET HEX DATA:", 0))
            for row in self._hexdump(bytes(pkt)):
                lines.append((row, 2))

            # 3. Draw with scrolling offset
            for i, (text, col) in enumerate(lines[self.detail_offset:]):
                if i >= h - 2: break
                try:
                    self.win_detail.addstr(i+1, 2, text[:w-4], curses.color_pair(col))
                except curses.error: pass
        self.win_detail.refresh()

    def update_packet_list(self):
        self.win_list.erase()
        h, w = self.win_list.getmaxyx()
        header = f" ID   TIME     PROT  SOURCE            DESTINATION     LEN "
        try: self.win_list.addstr(0, 0, header.ljust(w-1)[:w-1], curses.color_pair(7))
        except: pass

        pkts = self.sniffer.packets
        if not pkts:
            self.win_list.refresh()
            return

        max_rows = h - 1
        if self.selected_idx >= len(pkts): self.selected_idx = len(pkts) - 1

        # Adjust scroll window
        if self.selected_idx < self.scroll_offset:
            self.scroll_offset = self.selected_idx
        elif self.selected_idx >= self.scroll_offset + max_rows:
            self.scroll_offset = self.selected_idx - max_rows + 1

        for i in range(max_rows):
            idx = self.scroll_offset + i
            if idx >= len(pkts): break
            p = pkts[idx]

            proto = "TCP" if p.haslayer(TCP) else "UDP" if p.haslayer(UDP) else "ICMP" if p.haslayer(ICMP) else "OTH"
            src = p[IP].src if p.haslayer(IP) else "Local"
            dst = p[IP].dst if p.haslayer(IP) else "Local"

            # The float() fix for PCAP loading
            t_str = time.strftime('%H:%M:%S', time.localtime(float(p.time)))
            row = f"{idx:<4} {t_str} {proto:<4} {src:>15} -> {dst:<15} {len(p)}"

            color = curses.color_pair(1 if proto=="TCP" else 2 if proto=="UDP" else 3)
            try:
                if idx == self.selected_idx:
                    self.win_list.attron(curses.color_pair(6))
                    self.win_list.addstr(i+1, 0, row.ljust(w-1)[:w-1])
                    self.win_list.attroff(curses.color_pair(6))
                else:
                    self.win_list.attron(color)
                    self.win_list.addstr(i+1, 0, row.ljust(w-1)[:w-1])
                    self.win_list.attroff(color)
            except curses.error: pass

        self.win_list.refresh()

    def draw_stats_graphics(self):
        self.win_list.erase()
        self.win_list.box()
        self.win_list.addstr(0, 2, " [ NETWORK ANALYTICS ] ", curses.color_pair(7))
        h, w = self.win_list.getmaxyx()

        # --- 1. Traffic History ---
        pps_history = self.sniffer.stats.get("pps_history", [0]*30)
        spark = self._get_sparkline(pps_history)
        current_pps = pps_history[-1]
        self.win_list.addstr(1, 2, "Traffic Volume (PPS):", curses.A_BOLD)
        self.win_list.addstr(2, 2, f"[{spark}] {current_pps} pkts/sec", curses.color_pair(2))

        # --- 2. Protocols ---
        protos = self.sniffer.stats["protocols"]
        total = sum(protos.values()) or 1
        self.win_list.addstr(4, 2, "Protocol Distribution:", curses.A_BOLD)
        for i, (name, count) in enumerate(protos.items()):
            if i > 3: break
            bar_len = int((count/total)*(w//4))
            bar = "█" * bar_len
            self.win_list.addstr(5+i, 2, f"{name:<6}: {bar} {count}", curses.color_pair(i%3+1))

        # --- 3. Top Source IPs ---
        start_col = w // 2
        self.win_list.addstr(1, start_col, "Top Source IPs:", curses.A_BOLD)
        top_ips = self.sniffer.stats["src_ips"].most_common(5)
        for i, (ip, count) in enumerate(top_ips):
            if i > 4: break
            self.win_list.addstr(2+i, start_col, f"{ip:<15} | {count}", curses.color_pair(4))
        self.win_list.refresh()

    def update_alerts(self):
        self.win_alert.erase()
        self.win_alert.box()
        self.win_alert.addstr(0, 2, " [ THREAT ALERTS ] ", curses.color_pair(7))
        h, w = self.win_alert.getmaxyx()
        recent = self.analyzer.alerts[-(h-3):]
        for i, (ts, sev, msg) in enumerate(recent):
            try: self.win_alert.addstr(i+1, 1, f"[{ts}] {msg}"[:w-2], curses.color_pair(5 if sev=="CRITICAL" else 4))
            except: pass
        self.win_alert.refresh()

    def run(self):
        while True:
            if self.view_mode == "MENU":
                self.draw_menu()
                key = self.stdscr.getch()
                if key in [ord('c'), ord('C')]:
                    self.sniffer.start_live()
                    self.view_mode = "LIST"
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
                elif key == ord(' '):
                    is_paused = self.sniffer.toggle_pause()
                    if not is_paused: self.auto_scroll = True

                # --- Detail Scrolling (Page Up/Down) ---
                elif key == curses.KEY_NPAGE: # Page Down
                    self.detail_offset += 5
                elif key == curses.KEY_PPAGE: # Page Up
                    self.detail_offset = max(0, self.detail_offset - 5)

                elif key == curses.KEY_DOWN:
                    if self.sniffer.packets:
                        self.selected_idx = min(len(self.sniffer.packets)-1, self.selected_idx + 1)
                        self.detail_offset = 0 # Reset hex view on move
                        if self.selected_idx == len(self.sniffer.packets) - 1: self.auto_scroll = True

                elif key == curses.KEY_UP:
                    if self.sniffer.packets:
                        self.selected_idx = max(0, self.selected_idx - 1)
                        self.detail_offset = 0 # Reset hex view on move
                        self.auto_scroll = False

                elif key in [ord('w'), ord('W')]:
                    fname = self.get_input("Save as:")
                    if fname: self.status_msg = self.sniffer.save_capture(fname)[1]

            time.sleep(0.05)
