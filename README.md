# JackKnife
JackKnife is a versatile red teaming and pentest CLI toolkit featuring 30+ tools for scanning, spoofing, exploitation, wireless attacks, and recon—packed into one sleek script. Built for speed, stealth, and on-the-fly ops.



# 🗡️ JackKnife Toolkit

**JackKnife** is a powerful, all-in-one red team and network assessment CLI toolkit inspired by cyberpunk aesthetics. Designed for speed, stealth, and simplicity, JackKnife gives ethical hackers and sysadmins a Swiss Army knife of tools for scanning, spoofing, sniffing, hijacking, and exploiting — all from a single Python script.

---

## 🔧 Features

| Category         | Tools Included                                                                 |
|------------------|---------------------------------------------------------------------------------|
| 🕸️ Network Recon | ARP Scan, Nmap Scanner, Traceroute, WHOIS Lookup, Packet Sniffer                |
| 🎭 Spoofing       | ARP Spoofing (MITM), ARP Kick (Disconnect Devices)                             |
| 💻 Local Tools    | MAC Changer, Bandwidth Monitor (iftop), Hidden File Finder                     |
| 🔐 Attack Tools   | WPS Pixie Attack (via Reaver), Bluetooth Scanner, Clipboard Hijacker           |
| 🧰 Utilities      | Wordlist Builder, CVE-Free Usage                                                |

---

## 📦 Requirements

JackKnife runs on **Linux** and requires root privileges.

### Dependencies:
Install with:

```bash
sudo apt install python3 python3-pip nmap net-tools aircrack-ng macchanger tcpdump iftop whois hostapd dnsmasq bluez xclip -y
pip3 install scapy

🚀 Usage

sudo python3 jackknife.py

You’ll be presented with a clean, menu-driven terminal UI where you can pick from over a dozen tools.

⸻

🧠 Why JackKnife?
	•	🪛 All-in-One — Stop juggling 10 different scripts
	•	⚡ Fast & Lightweight — CLI-based, no bloat
	•	🧪 Red Team Ready — Tools for scanning, spoofing, kicking, jamming
	•	🧩 Modular — Easy to expand and hack on
	•	💻 Offline Capable — No cloud dependency
	•	💾 Remembers ARP scan results across modules

⸻

⚠️ Legal Disclaimer

This tool is for authorized educational and ethical testing only.
You are fully responsible for how you use JackKnife.
Use it only on networks and systems you own or have permission to test.

⸻

✨ Credits

Created by Niko DeRuise
Inspired by classic tools like Aircrack-ng, Reaver, Netdiscover, and Nmap.

🔄 Future Ideas
	•	CVE Scanner + Exploit Auto-Launcher
	•	Log Exporter and Session Reports
	•	CLI-to-GUI toggle
	•	Evil Twin AP (Headless version)

⸻

📫 Contributions Welcome!

Got a module idea or fix? Fork and submit a PR, or open an issue.




