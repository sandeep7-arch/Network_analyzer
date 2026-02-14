THIS IS A NETWORK_ANALYZER , with automated malicious packet detection with 16 different malicios detection tests.
NEEDS A LINUX SYSTEM TO RUN!!
Clone the repository into your computer , 
simply run main.py on sudo with all other files together in one folder.
you might need to install these libraries and you can install them by these commands : 


a ) scapy (for caputuring the packets and for also analyzing packets):

🟢 Debian / Ubuntu / Kali / Linux Mint / Pop!_OS
Bash
sudo apt update
sudo apt install python3-scapy
🔵 Arch Linux / Manjaro / EndeavourOS
Bash
sudo pacman -S python-scapy
🔴 Fedora / RHEL / CentOS / AlmaLinux
Bash
sudo dnf install python3-scapy
🦎 OpenSUSE (Leap & Tumbleweed)
Bash
sudo zypper install python3-scapy
🏔️ Alpine Linux
Bash
sudo apk add scapy
🟣 Gentoo
Bash
sudo emerge -av net-analyzer/scapy
⚫ Void Linux
Bash
sudo xbps-install -S python3-scapy


b ) curses (for terminal ui): 

🟢 Debian / Ubuntu / Kali / Linux Mint
Bash
sudo apt update
sudo apt install python3-scapy python3-curses
🔵 Arch Linux / Manjaro / EndeavourOS
Bash
sudo pacman -S python-scapy ncurses
🔴 Fedora / RHEL / CentOS
Bash
sudo dnf install python3-scapy ncurses-compat-libs
🦎 OpenSUSE
Bash
sudo zypper install python3-scapy ncurses-devel
🏔️ Alpine Linux
Bash
sudo apk add scapy py3-curses
