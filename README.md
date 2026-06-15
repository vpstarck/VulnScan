<div align="center">

```
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**A lightweight GUI-based vulnerability scanner built with Python & Tkinter**

![Python](https://img.shields.io/badge/Python-3.8+-00d4aa?style=flat-square&logo=python&logoColor=white)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-00d4aa?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-30363d?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-f0a500?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-3fb950?style=flat-square)

</div>

---

## What it does

VulnScan detects common vulnerabilities in web applications and local networks — no external libraries, no setup headaches. Just run the script and scan.

```
Target: 192.168.1.1   Ports: 1–1024
────────────────────────────────────────
[HIGH] Port    21 (FTP)    — OPEN
         ⚠ FTP transmits credentials in plaintext.
[ LOW] Port    22 (SSH)    — OPEN
         Banner: OpenSSH_7.9p1 Ubuntu
[HIGH] Port   445 (SMB)    — OPEN
         ⚠ SMB exposed — risk of ransomware / lateral movement.
────────────────────────────────────────
Open ports: 3   |   High-risk: 2   |   Duration: 4.2s
```

---

## Features

| Module | Description |
|--------|-------------|
| 🔍 **Port Scanner** | Scans any port range with configurable timeout |
| 🏷️ **Banner Grabbing** | Pulls service banners via HTTP HEAD requests |
| 🧓 **Version Detection** | Regex-based check for outdated OpenSSH, Apache, nginx, vsftpd |
| 📡 **Ping / Reachability** | Cross-platform ICMP check before scanning |
| ⚠️ **Risk Rating** | Flags HIGH-risk ports (FTP, Telnet, SMB, RDP, Redis, MongoDB) |
| 📄 **Report Export** | Saves a `.txt` vulnerability report with all findings |

---

## Screenshots

> *Dark glassmorphic GUI — scan output color-coded by severity*

```
┌─────────────────────────────────────────────────────────────┐
│ ⚡ VulnScan          Vulnerability Scanner — Mini Project  ● │
├──────────────┬──────────────────────────────────────────────┤
│ TARGET       │  SCAN OUTPUT                                  │
│ 127.0.0.1    │                                               │
│              │  [HIGH] Port 21 (FTP) — OPEN          (red)  │
│ PORT RANGE   │         ⚠ FTP sends creds in plaintext       │
│ 1  ──►  1024 │                                               │
│              │  [ LOW] Port 22 (SSH) — OPEN         (blue)  │
│ MODULES      │         Banner: OpenSSH_8.2p1                 │
│ ☑ Ports      │                                               │
│ ☑ Banners    │  [HIGH] Port 445 (SMB) — OPEN         (red)  │
│ ☑ Ping       │         ⚠ SMB exposed to network             │
│ ☑ Versions   │                                               │
│              ├──────────────────────────────────────────────┤
│ STATS        │  ▶ Start Scan  ■ Stop  📄 Save Report        │
│ Open:  3     │                          [██████░░░░] 62%     │
│ Vulns: 2     │                                               │
│ Time:  4.2s  │                                               │
└──────────────┴──────────────────────────────────────────────┘
```

---

## Getting Started

### Prerequisites

- Python 3.8 or higher
- `tkinter` — comes pre-installed with Python (no pip needed)

### Run

```bash
git clone https://github.com/yourusername/vulnscan.git
cd vulnscan
python vuln_scanner.py
```

That's it. No `pip install`, no virtual env.

---

## Usage

1. Enter the **target host** (IP address or hostname)
2. Set the **port range** to scan (default: 1–1024)
3. Toggle scan **modules** as needed
4. Adjust **connection timeout** using the slider
5. Hit **▶ Start Scan**
6. View color-coded results in the output panel
7. Click **📄 Save Report** to export findings as `.txt`

---

## Risk Classification

| Level | Color | Ports |
|-------|-------|-------|
| 🔴 **HIGH** | Red | FTP (21), Telnet (23), SMB (445), RDP (3389), Redis (6379), MongoDB (27017) |
| 🔵 **LOW** | Blue | SSH (22), HTTP (80), HTTPS (443), DNS (53), and others |

---

## Outdated Version Detection

The scanner checks banners against known vulnerable version patterns:

| Service | Flagged versions |
|---------|-----------------|
| OpenSSH | < 7.x |
| Apache  | < 2.x |
| nginx   | < 1.x |
| vsftpd  | < 2.2 |

---

## Project Structure

```
vulnscan/
├── vuln_scanner.py     # Main script — GUI + all scan logic
└── README.md
```

Single-file design — intentional. Easy to submit, easy to demo.

---

## How It Works

```
User Input
    │
    ▼
┌─────────┐     ┌──────────────┐     ┌─────────────────┐
│  Ping   │────►│  Port Scan   │────►│  Banner Grab    │
│  Check  │     │  (threaded)  │     │  + Version Det. │
└─────────┘     └──────────────┘     └────────┬────────┘
                                               │
                                    ┌──────────▼────────┐
                                    │   Risk Rating +   │
                                    │   GUI Log Output  │
                                    └──────────┬────────┘
                                               │
                                    ┌──────────▼────────┐
                                    │   .txt Report     │
                                    └───────────────────┘
```

---

## Disclaimer

> ⚠️ **For educational purposes only.**  
> Only scan systems you own or have explicit written permission to test.  
> Unauthorized port scanning may be illegal in your jurisdiction.

---

## Tech Stack

- **Python 3** — core language
- **tkinter** — GUI (built-in, no install)
- **socket** — port scanning & banner grabbing
- **subprocess** — ping via OS command
- **threading** — non-blocking scan (GUI stays responsive)
- **re** — version pattern matching

---

## Author

Made with love by vpstarck

---

<div align="center">

*If this helped you, drop a ⭐ on the repo!*

</div>
