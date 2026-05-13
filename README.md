<img width="1181" height="857" alt="AutoPwn Scanner Banner" src="https://github.com/user-attachments/assets/93d82d4d-0cf9-435b-ba1f-dcc66d9bb72f" />

# 🔍 AutoPwn Scanner

> **Automated vulnerability scanning and exploitation pipeline for authorized lab environments**

<div align="center">

[![C++](https://img.shields.io/badge/C%2B%2B-17-blue?style=flat-square&logo=cplusplus)](https://en.wikipedia.org/wiki/C%2B%2B)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green?style=flat-square&logo=python)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()

**C++ CLI** • **Python Logic** • **Metasploit RPC** • **SQLite Reporting**

</div>

---

## ⚠️ Legal Disclaimer

**ETHICAL AND LEGAL USE ONLY**

This tool is designed exclusively for:
- ✅ Academic lab environments
- ✅ CTF (Capture The Flag) competitions  
- ✅ Authorized penetration testing on networks you own or have explicit written permission to test

**Unauthorized access to computer systems is illegal.** The authors accept no responsibility for misuse or damages resulting from improper use of this tool.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [Workspaces](#workspaces)
- [Session Monitor](#session-monitor)
- [Export & Reporting](#export--reporting)
- [Database Schema](#database-schema)
- [Sample Output](#sample-output)
- [Extending the Tool](#extending-the-tool)

---

## 🎯 Overview

**AutoPwn Scanner** is an offensive security automation framework that orchestrates three industry-standard penetration testing tools into a seamless, interactive workflow. Built with a C++ CLI inspired by Metasploit's interface, it streamlines vulnerability discovery and exploitation.

### The Pipeline

| Phase | Tool | Purpose |
|-------|------|---------|
| **0** | `ping` / `whois` | Pre-scan reachability check and reconnaissance |
| **1** | `Nmap` | Port scanning and service version detection |
| **2** | `Searchsploit` | Public exploit lookup for discovered services |
| **3** | `Metasploit RPC` | Automatic exploitation with session tracking |

### What's New in v3

| Feature | v1 | v2 | v3 |
|---------|----|----|-----|
| Interactive CLI | Menu-based | Metasploit-style | ✅ Full readline support |
| ASCII Banners | ❌ | 6 banners | ✅ 6 dynamic banners |
| Tab Autocomplete | ❌ | ✅ | ✅ Enhanced |
| Command History | ❌ | ✅ | ✅ readline integration |
| Progress Bars | ❌ | ✅ | ✅ Animated |
| Session Monitoring | ❌ | ✅ | ✅ Background daemon |
| Workspace Isolation | ✅ | ✅ | ✅ Multi-target support |

---

## 🌟 Key Features

✨ **Interactive CLI** with readline support (Tab autocomplete, command history)  
🎨 **Colored output** with severity indicators (CRITICAL/MEDIUM/LOW)  
🔄 **Automated workflow** from reconnaissance to exploitation  
💾 **Multi-workspace isolation** for parallel testing scenarios  
📊 **Real-time session monitoring** with Meterpreter banner notifications  
📈 **Comprehensive reporting** (CSV, HTML, SQLite)  
⚙️ **Highly configurable** without code recompilation  
🛠️ **Extensible architecture** for custom modules and integrations  

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    scanner_runner (C++ v3)                    │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  Interactive CLI  —  autopwn (workspace/target) >        │ │
│  │  readline: Tab autocomplete · ↑↓ history · SIGINT guard  │ │
│  └──────────┬──────────────────────────────────┬────────────┘ │
│             │                                  │               │
│   ┌─────────▼──────────┐           ┌──────────▼──────────┐   │
│   │  Recon             │           │  Configuration      │   │
│   │  ping · whois      │           │  set · show · config│   │
│   └────────────────────┘           │  workspace · history│   │
│                                    │  status · export    │   │
│   ┌────────────────────┐           └─────────────────────┘   │
│   │  NmapRunner        │                                       │
│   │  progress bar      │──▶ scan_<IP>.xml                     │
│   │  elapsed timer     │                                       │
│   └─────────┬──────────┘                                       │
│             │                                                   │
│   ┌─────────▼──────────┐                                       │
│   │  SearchsploitRunner│──▶ searchsploit_results.json          │
│   │  severity colors   │    CRIT red · MED yellow · LOW grey   │
│   └─────────┬──────────┘                                       │
│             │                                                   │
└─────────────┼────────────────────────────────────────────────┘
              │
┌─────────────▼────────────────────────────────────────────────┐
│                      logic_mapper.py                         │
│                                                              │
│  NmapParser · SearchsploitFilter · MetasploitManager        │
│                        │                                    │
│             ┌──────────▼──────────┐                         │
│             │  MeterpreterMonitor │ ← background thread    │
│             │  ★ banner on session│                         │
│             └──────────┬──────────┘                         │
│                        │                                    │
│             ┌──────────▼──────────┐                         │
│             │     SQLite DB        │                         │
│             │  Targets             │                         │
│             │  Vulnerabilities     │──▶ export CSV/HTML     │
│             │  Exploits_Found      │                         │
│             └─────────────────────┘                         │
└────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
autopwn-scanner/
├── scanner_runner.cpp        # C++ CLI — interaction and orchestration
├── logic_mapper.py           # Python core — XML parsing, MSF RPC, monitoring
├── db_report.py              # Terminal report generation
├── start_msfrpcd.sh          # Helper script to launch Metasploit RPC daemon
├── config.ini.example        # Configuration template (config.ini in .gitignore)
├── requirements.txt          # Python dependencies
├── .gitignore                # Excludes config.ini, results/, logs/
├── README.md
└── results/                  # Created at runtime (excluded from git)
    └── ws_<workspace>/
        ├── scan_<IP>.xml
        ├── searchsploit_results.json
        ├── export_<timestamp>.csv
        └── export_<timestamp>.html

logs/
└── session_<timestamp>.log
```

---

## 📦 Requirements

| Dependency | Min Version | Notes |
|------------|------------|-------|
| **OS** | Any | Kali Linux, Parrot OS, or Arch Linux recommended |
| **Python** | 3.10+ | Required for type hints (`list[dict]`) |
| **GCC/G++** | 9+ | Must support C++17 standard |
| **Nmap** | 7.80+ | With `vulners` NSE script enabled |
| **Metasploit** | 6.0+ | RPC daemon required (PostgreSQL backend) |
| **libreadline-dev** | 8.0+ | Optional—enables Tab autocomplete and history |

---

## 🚀 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/PIXELQUADRO07/AutoPwn-Scanner.git
cd AutoPwn-Scanner
```

### Step 2: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Compile the C++ CLI

#### Option A: Basic Compilation (No Tab Autocomplete)

```bash
g++ -o scanner_runner scanner_runner.cpp -std=c++17
```

#### Option B: With Readline Support (Recommended)

**Install readline library:**

```bash
# Arch / Kali
sudo pacman -S readline

# Debian / Ubuntu / Kali apt
sudo apt install libreadline-dev
```

**Compile with readline:**

```bash
g++ -o scanner_runner scanner_runner.cpp -std=c++17 -lreadline
```

### Step 4: Configure Settings

```bash
cp config.ini.example config.ini
nano config.ini    # Edit with your Metasploit RPC password and paths
```

---

## ⚙️ Configuration

All settings are stored in `config.ini` (never committed to Git for security).

```ini
[metasploit]
msf_password        = change_this_password
msf_host            = 127.0.0.1
msf_port            = 55553

[scanner]
output_dir          = ./results
monitor_interval    = 5      # seconds between session polls
post_pipeline_wait  = 10     # extra wait after pipeline for slow payloads

[timeouts]
timeout_nmap        = 600    # seconds; 0 = unlimited
timeout_searchsploit= 60
timeout_msf         = 120

[database]
db_path             = ./results/scanner.db

[workspace]
workspace           = default
log_dir             = ./logs
```

### Live Configuration

Change any option without restarting:

```
autopwn (default) > set timeout_nmap 300
autopwn (default) > set workspace lab_01
autopwn (default) > show
```

---

## 🖥️ CLI Reference

### Starting the Scanner

```bash
# Interactive mode (recommended)
./scanner_runner

# Direct (non-interactive) mode
./scanner_runner <command> [args]

# Flags
./scanner_runner --quiet      # Suppress verbose output
./scanner_runner --version    # Print version and exit
./scanner_runner help         # Show command reference
```

### Command Reference

| Command | Arguments | Description |
|---------|-----------|-------------|
| `ping` | `<target>` | Check host reachability before scanning |
| `whois` | `<target>` | Domain and IP reconnaissance |
| `scan` | `<target>` | Full pipeline: Nmap → Searchsploit → Metasploit |
| `nmap` | `<target>` | Run Nmap scan only |
| `searchsploit` | `<target>` | Run Searchsploit lookup only |
| `sessions` | — | List active Meterpreter sessions |
| `export` | `csv` \| `html` | Export results to CSV or HTML |
| `report` | — | Display terminal report from database |
| `workspace` | `new` \| `list` \| `use` \| `delete` | Manage workspaces |
| `set` | `<option>` `<value>` | Change configuration live |
| `show` | — | Display current configuration |
| `history` | — | Show command history with timestamps |
| `status` | — | Display scanner and MSF connection status |
| `config` | — | Show full configuration |
| `clear` | — | Clear screen |
| `help` | — | Print command reference |
| `exit` | — | Exit the scanner |

### Typical Workflow

```
autopwn (default) > ping 192.168.1.50
autopwn (default) > workspace new lab_metasploitable
autopwn (lab_metasploitable) > scan 192.168.1.50
autopwn (lab_metasploitable/192.168.1.50) > sessions
autopwn (lab_metasploitable/192.168.1.50) > export html
autopwn (lab_metasploitable/192.168.1.50) > report
```

---

## 🗂️ Workspaces

Every scan is isolated in a workspace folder to prevent data mixing when testing multiple targets.

```bash
autopwn > workspace new lab_01        # Create and switch to new workspace
autopwn > workspace list              # List all workspaces with status
autopwn > workspace use lab_02        # Switch to existing workspace
autopwn > workspace delete lab_01     # Delete workspace (cannot delete 'default')
```

Each workspace stores its own files under `results/ws_<name>/`:
- `scan_<IP>.xml` — Raw Nmap output
- `searchsploit_results.json` — Exploit database results
- `export_<timestamp>.csv` — Tabular report
- `export_<timestamp>.html` — Interactive HTML report

---

## 👁️ Session Monitor

The `MeterpreterMonitor` daemon runs as a background thread during the exploitation phase. When a new session opens, it displays a formatted banner:

```
╔══════════════════════════════════════════════╗
║  ★  METERPRETER SESSION                      ║
╠══════════════════════════════════════════════╣
║  Session ID : 1                              ║
║  Target     : 192.168.1.50                   ║
║  Type       : meterpreter                    ║
║  Platform   : linux / x86_64                 ║
║  User       : root                           ║
║  Module     : exploits/unix/ftp/vsftpd_234   ║
║  Time       : 14:32:07                       ║
╚══════════════════════════════════════════════╝
```

| Session Type | Icon | Color |
|--------------|------|-------|
| meterpreter  | ★ | Green |
| shell | ✓ | Yellow |
| other | ~ | Cyan |

Sessions are recorded in the database even if not initiated by the pipeline. The monitor waits an additional `post_pipeline_wait` seconds (default: 10s) to capture slow staged payloads before shutting down.

---

## 📊 Export & Reporting

### Terminal Report

Display results directly in the terminal:

```bash
autopwn > report

# Or run directly:
python3 db_report.py ./results/scanner.db
```

### CSV Export

Export results as a spreadsheet:

```bash
autopwn > export csv
```

Creates `results/ws_<name>/export_<timestamp>.csv` with columns:
```
ip, hostname, port, service, version, exploit_name, has_msf, success
```

### HTML Export

Export results as an interactive report:

```bash
autopwn > export html
```

Generates a self-contained dark-themed HTML page with:
- ✅ Sortable vulnerability table
- 🟢 Green highlighting for MSF-compatible exploits
- 📱 Mobile-responsive design
- 🎨 Professional dark theme

Open the HTML file in any modern browser.

---

## 🗄️ Database Schema

```sql
Targets
  ├── id          (PRIMARY KEY)
  ├── ip          (VARCHAR)
  ├── hostname    (VARCHAR)
  ├── os_info     (TEXT)
  └── scan_time   (TIMESTAMP)

Vulnerabilities
  ├── id          (PRIMARY KEY)
  ├── target_id   (FOREIGN KEY → Targets)
  ├── port        (INTEGER)
  ├── protocol    (VARCHAR)
  ├── service     (VARCHAR)
  ├── version     (VARCHAR)
  ├── exploit_name(VARCHAR)
  ├── exploit_path(VARCHAR)
  ├── has_msf     (BOOLEAN)
  └── found_time  (TIMESTAMP)

Exploits_Found
  ├── id          (PRIMARY KEY)
  ├── vuln_id     (FOREIGN KEY → Vulnerabilities)
  ├── msf_module  (VARCHAR)
  ├── rhost       (VARCHAR)
  ├── rport       (INTEGER)
  ├── session_id  (INTEGER)
  ├── success     (BOOLEAN)
  └── attempt_time(TIMESTAMP)
```

### Quick Queries

```bash
# List all successful exploits
sqlite3 results/scanner.db \
  "SELECT rhost, msf_module, session_id FROM Exploits_Found WHERE success=1;"

# Show all MSF-ready vulnerabilities
sqlite3 results/scanner.db \
  "SELECT t.ip, v.port, v.service, v.exploit_name
   FROM Vulnerabilities v JOIN Targets t ON v.target_id=t.id
   WHERE v.has_msf=1;"

# Count vulnerabilities by severity
sqlite3 results/scanner.db \
  "SELECT severity, COUNT(*) as count
   FROM Vulnerabilities GROUP BY severity;"
```

---

## 📺 Sample Output

```
  ██████╗  ██╗    ██╗███╗   ██╗
  ██╔══██╗ ██║    ██║████╗  ██║
  ███████║ ██║ █╗ ██║██╔██╗ ██║
  ██╔══██║ ██║███╗██║██║╚██╗██║
  ██║  ██║ ╚███╔███╔╝██║ ╚████║
  ╚═╝  ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝

  [ Nmap · Searchsploit · Metasploit RPC · v3 ]
  workspace: lab01  |  msf: 127.0.0.1:55553  |  v3.0.0

  Type 'help' for commands. Ctrl+C interrupts running tools.
  Tab autocomplete and ↑↓ history enabled.

autopwn (lab01) > ping 192.168.1.50

  ┌─ PING ────────────────────────────────────────────┐
[*] Testing reachability: 192.168.1.50
  ────────────────────────────────────────────────────
  PING 192.168.1.50: 4 packets transmitted, 4 received
  Completed in 4s
  ────────────────────────────────────────────────────
[+] 192.168.1.50 is reachable.

autopwn (lab01) > scan 192.168.1.50

  ┌─ NMAP SCAN ───────────────────────────────────────┐
[*] Target    : 192.168.1.50
[*] Timeout   : 600s
  ────────────────────────────────────────────────────

  Scanning 192.168.1.50  [████████████████████████░░░░░░░░░░░░░░] 63%  ⠹

  ... (nmap output continues) ...

  Scanning 192.168.1.50  [████████████████████████████████████████] DONE
  Completed in 1m 48s
[+] Scan complete → ./results/ws_lab01/scan_192.168.1.50.xml

  ┌─ SEARCHSPLOIT ────────────────────────────────────┐
  Querying exploitdb       [████████████████████████████████████████] DONE

[CRIT]  vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)
[MED]   ProFTPd 1.3.3c - Compromised Source Packages
[LOW]   ProFTPd IAC 1.3.x - Remote DoS
  Completed in 3s
[+] Results → ./results/ws_lab01/searchsploit_results.json

  ┌─ LOGIC MAPPER ────────────────────────────────────┐
[*] MSF RPC: 127.0.0.1:55553
[MONITOR] Started. Polling every 5s.
  → Attempting: exploits/unix/ftp/vsftpd_234_backdoor

╔══════════════════════════════════════════════╗
║  ★  METERPRETER SESSION                      ║
║  Session ID : 1   Target: 192.168.1.50       ║
╚══════════════════════════════════════════════╝

[+] Logic mapper completed.  Completed in 12s

autopwn (lab01/192.168.1.50) > export html
[+] HTML exported → ./results/ws_lab01/export_20260513_143207.html

autopwn (lab01/192.168.1.50) > history

  ╔═══╦══════════╦══════════════════════════════╗
  ║ # ║ Time     ║ Command                      ║
  ╠═══╬══════════╬══════════════════════════════╣
  ║ 1 ║ 14:28:01 ║ ping 192.168.1.50            ║
  ║ 2 ║ 14:28:07 ║ scan 192.168.1.50            ║
  ║ 3 ║ 14:32:10 ║ export html                  ║
  ╚═══╩══════════╩══════════════════════════════╝
```

---

## 🛠️ Extending the Tool

### Custom Nmap Flags

Edit `NmapRunner::run()` in `scanner_runner.cpp`:

```cpp
// Full port scan with OS detection and service fingerprinting
"nmap -A -p- --script=vulners -oX " + xml + " " + target
```

### Different Metasploit Payload

Edit `MetasploitManager::run_exploit()` in `logic_mapper.py`:

```python
payload = self.client.modules.use("payload", "windows/x64/meterpreter_reverse_tcp")
```

### Slack / Webhook Notifications

Extend `MeterpreterMonitor._notify()` in `logic_mapper.py`:

```python
import requests

def notify_slack(self, message):
    requests.post(
        "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        json={"text": f"🔴 AutoPwn Alert: {message}"}
    )
```

### Add a New CLI Command

Add a branch in `dispatch()` in `scanner_runner.cpp`:

```cpp
if (cmd == "mycommand") {
    my_custom_function(arg1, config, logger);
    return 0;
}
```

---

## 📄 License

This project is provided "as-is" for educational and authorized security testing purposes only.

---

## 🤝 Contributing

Found a bug? Have a feature request?

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

---

## 📞 Support & Feedback

For issues, questions, or suggestions, please open an [GitHub Issue](https://github.com/PIXELQUADRO07/AutoPwn-Scanner/issues).

---

<div align="center">

**⚡ Built with C++ | Powered by Metasploit | Designed for Security Professionals**

Made with ❤️ by [PIXELQUADRO07](https://github.com/PIXELQUADRO07)

</div>
