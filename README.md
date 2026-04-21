# VIGIL - Virtual Interface for Gateway Inspection & Listening 🛡️

![Version](https://img.shields.io/badge/version-1.2-green)
![Python](https://img.shields.io/badge/python-3.x-blue)
![License](https://img.shields.io/badge/license-MIT-important)

**VIGIL** is a Python-based network reconnaissance tool focused on practical security assessment workflows: target scanning, LAN discovery, traffic monitoring, and lightweight CVE enrichment.

---

## 📋 Table of Contents
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Usage & Parameters](#-usage--parameters)
- [Examples](#-examples)
- [Ethical Disclaimer](#-ethical-disclaimer)

---

## 🚀 Features

- **Flexible Targets**: Accepts IPv4 address, hostname, or URL and resolves it before scanning.
- **Threaded TCP Port Scanner**: Supports full scan or custom selection (`single`, `list`, `range`).
- **ARP Network Discovery**: Identifies active hosts in a local subnet.
- **Vigilant Mode**: Live packet summary monitoring on a selected interface.
- **Verbose Banner Grabbing**: Attempts service/banner extraction from open ports.
- **Basic CVE Lookup**: Uses `nvdlib` to fetch matching CVEs from service banners.
- **Result Exporting**: Save findings to `.txt`.

---

## ⚙️ How It Works

VIGIL operates on three practical layers:
1. **Layer 2 (ARP Discovery)**: Broadcast ARP requests to detect active hosts in local networks.
2. **Layer 4 (TCP Connect Scan)**: Multi-threaded `socket.connect_ex()` checks open ports.
3. **Application Layer (Verbose Mode)**: Sends simple probes (for example HTTP `HEAD`) to collect service banners and enrich output with CVE references.

---

## 🛠️ Installation

### 1. Prerequisites
- **Python 3.x**
- **Npcap** or **WinPcap** (Required for Windows users to handle raw packets).

### 2. Setup
```bash
# Clone the repository
git clone https://github.com/ForwardEcho/VIGIL.git
cd VIGIL

# Install required libraries
pip install scapy nvdlib
```

---

## 📖 Usage & Parameters

Basic usage:
```bash
python vigil.py [options]
```

Available flags:
- `-t`, `--target`: Target for port scan (IP / hostname / URL).
- `-p`, `--ports`: Port selection (`80`, `22,80,443`, `1-1024`, `22,80-90`).
- `-w`, `--threads`: Number of threads (default: `30`).
- `-vv`, `--verbose`: Enable banner grabbing and extra scan details.
- `-o`, `--output`: Save scan output to file.
- `-d`, `--discover`: Discover active hosts in CIDR network (for example `192.168.1.0/24`).
- `-i`, `--interface`: Network interface to use.
- `-si`, `--show-interfaces`: Show available interfaces.
- `-v`, `--vigilant`: Enable live packet monitoring mode.

---

## 💡 Examples

### Discover active devices on local network
```bash
python vigil.py --discover 192.168.1.0/24 -i "Wi-Fi"
```

### Scan top web/security ports on hostname
```bash
python vigil.py --target scanme.nmap.org --ports 22,80,443,8080 -w 80 -vv
```

### Scan using URL target format
```bash
python vigil.py --target https://example.com --ports 80,443
```

### Full port scan and export to file
```bash
python vigil.py --target 10.10.10.5 -w 150 -o scan_results.txt
```

### List your network cards (for Windows names)
```bash
python vigil.py --show-interfaces
```

---

## 🤝 Contributing
VIGIL is an **Open Source** project. Contributions are welcome! If you have a fix or a new feature (like a Stealth SYN Scan), feel free to fork the repo and submit a Pull Request.

---

## 👨‍💻 Created by
**ForwardEcho** | [GitHub Profile](https://github.com/ForwardEcho)

---

## ⚠️ Ethical Disclaimer
VIGIL is intended for educational purposes and authorized security auditing only. Unauthorized scanning of networks you do not own is illegal. Use responsibly.
