<img width="1181" height="857" alt="AutoPwn Scanner Banner" src="https://github.com/user-attachments/assets/93d82d4d-0cf9-435b-ba1f-dcc66d9bb72f" />
<img width="1918" height="1117" alt="Screenshot_20260529_195731" src="https://github.com/user-attachments/assets/e91350c2-e1b5-4c7e-ad3b-d1d969ea9e01" />


# 🔍 AutoPwn-Scanner (v2.0 - Web Edition)

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/UI-Cyberpunk%20Red-black?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Backend-Node.js%20%2F%20Express-green?style=for-the-badge&logo=node.js" />
  <img src="https://img.shields.io/badge/Core-C%2B%2B-blue?style=for-the-badge&logo=c%2B%2B" />
</p>

**AutoPwn-Scanner** has evolved. Moving away from a strict command-line interface, version 2.0 introduces a complete, self-hosted **Web UI** that emulates a futuristic hacker console. You can now orchestrate scans, execute shell commands, and analyze network/exploit data directly from your browser.

> ⚠️ **Disclaimer:** This tool is developed strictly for educational purposes and authorized penetration testing environments. Always obtain proper permission before scanning networks.

---

## 💎 Key Upgrades (v1.0 CLI vs v2.0 Web UI)

| Feature | Old Version (v1.0) | New Version (v2.0) |
| :--- | :--- | :--- |
| **Interface** | Strict CLI / Terminal Only | CLI + Interactive Web UI |
| **Input / Output** | Disk files and raw terminal output | Browser UI + Live File Upload & Parsing |
| **Command Execution** | Manual direct triggers | Scanner automation + Native Shell Proxy |
| **Data Visualization** | Raw XML / JSON text | Structured Exploit Tables, Host Lists & Port Summaries |
| **UI Theme** | None (Default Terminal) | Cyberpunk Dark Mode (Neon Red & Black) |
| **Architecture** | Single terminal pipeline | Decoupled Frontend + Node.js Backend |

---

## 🛠️ System Architecture & Components

The tool now runs on a split architecture, leveraging the speed of **C++** for core scanning and the flexibility of **Node.js** for the web dashboard.

### 🏢 Core Backend (C++)
* `scanner_runner.cpp`: The main orchestrator that manages `Nmap`, `SearchSploit`, and `Metasploit` pipelines.
* `logic_mapper.py`: Handles XML/JSON data structures and reporting pipelines.

### 🌐 Web UI Dashboard (`/web-ui`)
* `server.js` (Express Backend): Features a `POST /api/execute` endpoint acting as a local proxy to run `scanner_runner` and handle standard terminal commands via a custom `shell:` wrapper.
* `index.html`: The main user interface, featuring a browser-based terminal simulator, command inputs, a dedicated **Shell Mode toggle**, and dynamic file upload areas.
* `src/main.js`: The frontend engine. It streams terminal outputs, parses Nmap XMLs / SearchSploit JSONs on the fly, and renders detailed graphical summary tables.
* `src/style.css`: A customized, high-contrast **cyberpunk red/black neon theme** for an immersive terminal experience.

---

## 🚀 Getting Started

### Prerequisites
Make sure you have the following tools installed on your local testing environment:
* `node` (v16+ recommended) and `npm`
* `nmap` and `searchsploit` (configured in your system PATH)
* A C++ compiler (`g++`) to build the core runner.

### Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/PIXELQUADRO07/AutoPwn-Scanner.git](https://github.com/PIXELQUADRO07/AutoPwn-Scanner.git)
   cd AutoPwn-Scanner
Build the C++ Core:

Bash
g++ -O3 scanner_runner.cpp -o scanner_runner
Install Web UI Dependencies:

Bash
cd web-ui
npm install
Launch the Local Web Server:

Bash
npm start
The application will verify backend/frontend syntax integrity (node --check) and spin up the server. Open your browser and navigate to http://localhost:3000 (or the port specified in your terminal).

🎮 How to Use the Web UI
Running Scans: Type your traditional target parameters into the web console input box to trigger the automated scanner_runner pipeline.

Shell Proxy Mode: Toggle the Shell Mode switch or use the shell: <command> syntax to run native system terminal operations directly through the web manager.

Log & Report Parsing: Drag and drop your generated scan_*.xml or searchsploit_results.json files right into the browser dashboard to immediately generate clear visual grids showing hosts, open ports, and potential matching exploits.

📈 Future Roadmaps
[ ] Persistent web database to store past scan histories.

[ ] Live web-socket stream for real-time msfconsole interactive sessions.

[ ] Multi-user session management with secure JWT authentication.
