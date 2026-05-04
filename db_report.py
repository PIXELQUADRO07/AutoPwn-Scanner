#!/usr/bin/env python3
"""
db_report.py
────────────────────────────────────────────────
Interroga il database SQLite e stampa un report
leggibile dei risultati della scansione.
Uso: python3 db_report.py [percorso_db]
"""

import sqlite3
import sys
from pathlib import Path

DB_PATH = "./results/scanner.db"

def print_section(title: str):
    print(f"\n{'═'*55}")
    print(f"  {title}")
    print('═'*55)

def report(db_path: str):
    if not Path(db_path).exists():
        print(f"[ERROR] Database non trovato: {db_path}")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # ── Targets ──────────────────────────────────────
    print_section("TARGET SCANSIONATI")
    cur.execute("SELECT * FROM Targets ORDER BY scan_time")
    rows = cur.fetchall()
    if not rows:
        print("  Nessun target trovato.")
    for r in rows:
        print(f"  [{r['id']}] {r['ip']:<18} {r['hostname'] or '':<25} "
              f"OS: {r['os_info'] or 'n/a'}")
        print(f"       Scansione: {r['scan_time']}")

    # ── Vulnerabilities ───────────────────────────────
    print_section("VULNERABILITÀ TROVATE")
    cur.execute("""
        SELECT v.*, t.ip
        FROM Vulnerabilities v
        JOIN Targets t ON v.target_id = t.id
        ORDER BY t.ip, v.port
    """)
    rows = cur.fetchall()
    if not rows:
        print("  Nessuna vulnerabilità trovata.")
    current_ip = None
    for r in rows:
        if r['ip'] != current_ip:
            current_ip = r['ip']
            print(f"\n  ▶ {current_ip}")
        msf_flag = "✓ MSF" if r['has_msf'] else "  ---"
        print(f"    Port {r['port']:>5}/{r['protocol']:<4} "
              f"{r['service']:<12} {r['version'] or '':<30} "
              f"[{msf_flag}]")
        print(f"           Exploit: {r['exploit_name']}")

    # ── Exploits ──────────────────────────────────────
    print_section("TENTATIVI DI EXPLOIT")
    cur.execute("""
        SELECT e.*, v.exploit_name
        FROM Exploits_Found e
        JOIN Vulnerabilities v ON e.vuln_id = v.id
        ORDER BY e.attempt_time
    """)
    rows = cur.fetchall()
    if not rows:
        print("  Nessun tentativo registrato.")
    for r in rows:
        status = "✓ SUCCESSO" if r['success'] else "✗ Fallito"
        print(f"  {status} | {r['rhost']}:{r['rport']} | "
              f"Modulo: {r['msf_module']}")
        if r['session_id']:
            print(f"           Session ID: {r['session_id']}")

    # ── Sommario ─────────────────────────────────────
    print_section("SOMMARIO")
    cur.execute("SELECT COUNT(*) FROM Targets")
    n_targets = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM Vulnerabilities")
    n_vulns = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM Vulnerabilities WHERE has_msf=1")
    n_msf = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM Exploits_Found WHERE success=1")
    n_success = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM Exploits_Found")
    n_attempts = cur.fetchone()[0]

    print(f"  Target scansionati : {n_targets}")
    print(f"  Vulnerabilità totali: {n_vulns}")
    print(f"  Con modulo MSF     : {n_msf}")
    print(f"  Tentativi exploit  : {n_attempts}")
    print(f"  Sessioni aperte    : {n_success}")

    conn.close()
    print()

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DB_PATH
    report(path)
