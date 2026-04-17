# VIGIL - Virtual Interface for Gateway Inspection & Listening 🛡️

![Version](https://img.shields.io/badge/version-1.1-green)
![Python](https://img.shields.io/badge/python-3.x-blue)
![License](https://img.shields.io/badge/license-MIT-important)

**VIGIL** is a professional-grade network reconnaissance tool developed in Python. It is designed to be fast, accurate, and easy to use for both local network mapping and remote server auditing.

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

- **Multi-Threaded Engine**: Scans thousands of ports simultaneously using parallel processing.
- **ARP Network Discovery**: High-precision host detection that bypasses typical ICMP/Ping blocks.
- **Banner Grabbing**: Extracts service metadata (versions, OS hints) directly from open ports.
- **Auto-Help System**: Dynamic help menu with usage examples.
- **Interface Control**: Manually specify which network adapter to use.
- **Result Exporting**: Save all findings to a clean, structured `.txt` file.

---

## ⚙️ How It Works

VIGIL operates on three core technical layers:
1. **Layer 2 (ARP)**: During device discovery, it sends ARP requests to the broadcast address. Any device that responds is marked as active, regardless of firewall settings.
2. **Layer 4 (TCP)**: During port scanning, it uses a multi-threaded TCP connect method to verify if a port is in a "Listening" state.
3. **Application Layer**: After a successful connection, it listens for a service handshake to "grab" the banner and identify the software version.

---

## 🛠️ Installation

### 1. Prerequisites
- **Python 3.x**
- **Npcap** or **WinPcap** (Required for Windows users to handle raw packets).

### 2. Setup
```bash
# Clone the repository
git clone https://github.com/ForwardEcho/vigil.git
cd vigil

# Install required library
pip install scapy
```

---

## 📖 Usage & Parameters

Execute VIGIL using the following flags:

| Flag | Long Name | Description |
| :--- | :--- | :--- |
| `-t` | `--target` | The target IP address or hostname to scan. |
| `-d` | `--discover` | The network range (CIDR) to discover (e.g., `192.168.1.0/24`). |
| `-i` | `--interface` | The network adapter to use (use `-si` to find yours). |
| `-si`| `--show-interfaces` | List all available network adapters on your system. |
| `-w` | `--threads` | Number of simultaneous threads (Default: 100). |
| `-o` | `--output` | Filename to save the scan results. |

---

## 💡 Examples

### Identify active devices on your WiFi
```bash
python vigil.py --discover 192.168.1.0/24 -i "Wi-Fi"
```

### Deep scan a server and save results
```bash
python vigil.py --target 10.10.10.5 -w 300 -o scan_results.txt
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
