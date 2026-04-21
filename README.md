# VIGIL - Virtual Interface for Gateway Inspection & Listening

![Version](https://img.shields.io/badge/version-1.4-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-important)

VIGIL is a practical Python recon tool for authorized security testing.  
It combines:
- fast multi-threaded TCP port scanning,
- service banner grabbing,
- optional CVE enrichment,
- heuristic risk scoring,
- ARP host discovery,
- and live packet monitoring (Vigilant mode).

---

## Table of Contents
- [1. Feature Overview](#1-feature-overview)
- [2. Installation](#2-installation)
- [3. Quick Start](#3-quick-start)
- [4. Detailed CLI Reference](#4-detailed-cli-reference)
- [5. Scan Output Format](#5-scan-output-format)
- [6. Usage Scenarios](#6-usage-scenarios)
- [7. Vigilant Mode Guide](#7-vigilant-mode-guide)
- [8. Performance Tuning](#8-performance-tuning)
- [9. Troubleshooting](#9-troubleshooting)
- [10. Ethical Use](#10-ethical-use)

---

## 1. Feature Overview

### Core Recon
- Target input supports IPv4, hostname, and URL.
- Port selection supports single port, list, and range.
- Full-range scanning supported (`1-65535` by default when `--ports` is omitted).
- Multi-threaded socket connect scan.

### Enrichment
- Banner grabbing for HTTP, HTTPS (TLS-aware), and SSH.
- CVE lookup from banner keywords via `nvdlib`.
- Per-port heuristic risk scoring:
  - HTTP header posture checks (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, TRACE behavior),
  - TLS posture checks (legacy protocol acceptance, certificate hints),
  - basic port behavior checks.

### Monitoring
- ARP discovery for active LAN host mapping.
- Vigilant mode for live packet monitoring.
- Vigilant alerting for:
  - possible SYN burst,
  - possible port scan behavior,
  - possible ARP spoof indication.

### Output
- Rich live table output (if `rich` is installed).
- Plain fallback output if `rich` is not available.
- Optional export to text report via `--output`.

---

## 2. Installation

### Requirements
- Python `3.10+`
- Windows users: Npcap/WinPcap recommended for scapy capture features.

### Setup
```bash
git clone https://github.com/ForwardEcho/VIGIL.git
cd VIGIL
pip install scapy nvdlib rich
```

### Verify
```bash
python vigil.py -h
```

---

## 3. Quick Start

### Fastest recon (speed-focused)
```bash
python vigil.py --target example.com --fast
```

### Balanced recon (with risks + CVE)
```bash
python vigil.py --target example.com --ports 22,80,443 -w 120 -vv
```

### LAN host discovery
```bash
python vigil.py --discover 192.168.1.0/24 -i "Wi-Fi"
```

### Vigilant packet monitoring
```bash
python vigil.py --vigilant --interface "Wi-Fi" --bpf tcp
```

---

## 4. Detailed CLI Reference

## Targeting and Port Scan

- `-t`, `--target`
  - Target to scan.
  - Accepts:
    - IP: `192.168.1.10`
    - Hostname: `scanme.nmap.org`
    - URL: `https://example.com/path`

- `-p`, `--ports`
  - Port selection.
  - Formats:
    - single: `80`
    - list: `22,80,443`
    - range: `1-1024`
    - mixed: `22,80-90,443`
  - If omitted, VIGIL scans all ports (`1-65535`).

- `-w`, `--threads`
  - Number of worker threads.
  - Default: `100`.
  - Higher = faster but more resource usage/noise.

- `--timeout`
  - Socket timeout in seconds.
  - Default: `0.5`.
  - Lower value can speed up scans on noisy targets, but may miss slow responses.

## Scan Modes and Enrichment

- `-vv`, `--verbose`
  - Enables banner-grabbing probes and extra debug details.

- `--fast`
  - Speed mode.
  - Automatically:
    - lowers timeout ceiling,
    - disables verbose probe behavior,
    - disables CVE lookup,
    - disables heuristic scoring.
  - Best for quick reconnaissance pass.

- `--no-cve`
  - Disable CVE lookup only.

- `--no-heuristic`
  - Disable heuristic checks only.

- `-o`, `--output`
  - Save scan result to text file.

## Discovery and Interface

- `-d`, `--discover`
  - Discover active hosts in CIDR range (ARP-based).
  - Example: `192.168.1.0/24`.

- `-i`, `--interface`
  - Network interface to use.

- `-si`, `--show-interfaces`
  - Show available interfaces.

## Vigilant Mode

- `-v`, `--vigilant`
  - Enable continuous packet monitoring mode.

- `--bpf`
  - Optional BPF capture filter (e.g., `tcp`, `arp`, `tcp port 443`).

- `--alert-threshold`
  - Threshold for SYN burst and scan-behavior alerts.
  - Default: `25`.

- `--vigilant-output`
  - Append vigilant packet logs to a file.

---

## 5. Scan Output Format

During scan, VIGIL prints a live table with:
- `Port`
- `Service`
- `Risk`
- `Score`
- `Banner`
- `CVE`

Notes:
- `Risk`/`Score` depend on heuristic checks. If heuristics are disabled, values are minimal/default.
- `CVE` field is populated when a banner is detected and CVE lookup is enabled.
- Very long `Banner`/`CVE` strings are truncated for readability in terminal width.

---

## 6. Usage Scenarios

### A. Fast internet-facing baseline
```bash
python vigil.py --target example.com --ports 1-2000 --fast
```

### B. Focused web service assessment
```bash
python vigil.py --target https://example.com --ports 80,443,8080,8443 -vv --output web_scan.txt
```

### C. SSH + admin port review
```bash
python vigil.py --target 10.10.10.5 --ports 22,2222,3389,5900 -w 150 --no-cve
```

### D. Full scan with balanced speed
```bash
python vigil.py --target scanme.nmap.org -w 150 --timeout 0.35 --no-cve
```

### E. Host discovery before scanning
```bash
python vigil.py --discover 192.168.1.0/24 --interface "Ethernet"
```

---

## 7. Vigilant Mode Guide

### Basic
```bash
python vigil.py --vigilant --interface "Wi-Fi"
```

### TCP-only monitoring
```bash
python vigil.py --vigilant --interface "Wi-Fi" --bpf tcp
```

### ARP-focused monitoring with log export
```bash
python vigil.py --vigilant --interface "Wi-Fi" --bpf arp --vigilant-output vigilant.log
```

### Higher sensitivity alerts
```bash
python vigil.py --vigilant --interface "Wi-Fi" --alert-threshold 15
```

---

## 8. Performance Tuning

If scan feels slow:
- start with `--fast`,
- increase `--threads` gradually (`120`, `150`, `200`),
- lower `--timeout` carefully (`0.5` -> `0.35` -> `0.25`),
- disable heavy enrichments (`--no-cve`, `--no-heuristic`),
- narrow ports (`--ports 1-2000` or targeted sets).

Suggested presets:
- **Fast recon:** `--fast`
- **Balanced:** `-w 120 --timeout 0.35 --no-cve`
- **Detailed:** `-vv` with selected ports

---

## 9. Troubleshooting

### No banner appears
- Service may hide or suppress banner.
- Try `-vv` and focused ports (`22,80,443`).
- HTTPS banner depends on TLS/Server header behavior.

### CVE column is empty (`-`)
- No usable banner detected, or
- lookup disabled (`--no-cve` / `--fast`), or
- no direct keyword match in NVD search.

### Scan feels stuck
- Full port scans can take time on high-latency targets.
- Use `--ports` to narrow scope.
- Use lower timeout and/or more threads.

### Permission errors in discovery/vigilant mode
- Run shell with required privileges.
- Ensure packet capture driver (Npcap/WinPcap) is installed on Windows.

### Table output not styled
- Install `rich`:
```bash
pip install rich
```

---

## 10. Ethical Use

VIGIL is for educational use and authorized security testing only.
- Scan only systems you own or have explicit permission to test.
- Unauthorized scanning may violate law and policy.
- You are responsible for your own usage.

---

## Contributing

Contributions are welcome. Improvements that are highly useful:
- better service fingerprinting,
- structured export formats (JSON/CSV),
- automated tests,
- performance and detection tuning.

---

## Author

ForwardEcho - [GitHub](https://github.com/ForwardEcho)
