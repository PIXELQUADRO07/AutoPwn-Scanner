#!/usr/bin/env python3
import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path


def to_dict(row):
    return {k: row[k] for k in row.keys()}


def build_filters(args):
    filters = []
    params = []
    if args.host:
        filters.append("(t.ip LIKE ? OR t.hostname LIKE ?)")
        params.extend([f"%{args.host}%", f"%{args.host}%"])
    if args.port:
        filters.append("v.port = ?")
        params.append(args.port)
    if args.cve:
        filters.append("v.cve_ids LIKE ?")
        params.append(f"%{args.cve.upper()}%")
    if args.workspace:
        filters.append("t.workspace LIKE ?")
        params.append(f"%{args.workspace}%")
    if args.session:
        filters.append("s.name LIKE ?")
        params.append(f"%{args.session}%")
    return filters, params


def query_data(conn, args):
    cur = conn.cursor()
    filters, params = build_filters(args)
    where = f"WHERE {' AND '.join(filters)}" if filters else ''

    cur.execute(
        f"SELECT t.* FROM Targets t LEFT JOIN Sessions s ON t.session_id = s.id {where} ORDER BY t.scan_time DESC LIMIT ?",
        (*params, args.limit)
    )
    targets = [to_dict(r) for r in cur.fetchall()]

    cur.execute(
        f"SELECT v.* FROM Vulnerabilities v JOIN Targets t ON v.target_id = t.id LEFT JOIN Sessions s ON t.session_id = s.id {where} ORDER BY v.found_time DESC LIMIT ?",
        (*params, args.limit)
    )
    vulnerabilities = [to_dict(r) for r in cur.fetchall()]

    cur.execute(
        f"SELECT e.* FROM Exploits_Found e JOIN Vulnerabilities v ON e.vuln_id = v.id JOIN Targets t ON v.target_id = t.id LEFT JOIN Sessions s ON t.session_id = s.id {where} ORDER BY e.attempt_time DESC LIMIT ?",
        (*params, args.limit)
    )
    exploits = [to_dict(r) for r in cur.fetchall()]

    cur.execute(
        "SELECT s.id, s.name, s.workspace, s.scan_path, s.created_at, COUNT(t.id) AS host_count "
        "FROM Sessions s LEFT JOIN Targets t ON t.session_id = s.id "
        "GROUP BY s.id ORDER BY s.created_at DESC LIMIT ?",
        (args.limit,)
    )
    sessions = [to_dict(r) for r in cur.fetchall()]

    cur.execute("SELECT COUNT(*) AS total_targets FROM Targets")
    total_targets = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) AS total_vulns FROM Vulnerabilities")
    total_vulns = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) AS msf_vulns FROM Vulnerabilities WHERE has_msf=1")
    msf_vulns = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) AS success_exploits FROM Exploits_Found WHERE success=1")
    success_exploits = cur.fetchone()[0]

    cur.execute("SELECT cve_ids FROM Vulnerabilities WHERE cve_ids IS NOT NULL AND cve_ids != ''")
    cve_texts = [row[0] for row in cur.fetchall() if row[0]]
    cve_counts = {}
    for text in cve_texts:
        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text.upper()):
            cve_counts[cve] = cve_counts.get(cve, 0) + 1
    top_cves = sorted(cve_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

    return {
        'summary': {
            'total_targets': total_targets,
            'total_vulns': total_vulns,
            'msf_vulns': msf_vulns,
            'success_exploits': success_exploits,
        },
        'top_cves': [{'cve': cve, 'count': count} for cve, count in top_cves],
        'sessions': sessions,
        'targets': targets,
        'vulnerabilities': vulnerabilities,
        'exploits': exploits,
    }


def main():
    parser = argparse.ArgumentParser(description='Query SQLite scan history and export JSON for the web UI.')
    parser.add_argument('--db', default='./results/scanner.db', help='SQLite database path')
    parser.add_argument('--host', help='Filter by host IP or hostname')
    parser.add_argument('--port', type=int, help='Filter by port number')
    parser.add_argument('--cve', help='Filter by CVE ID')
    parser.add_argument('--workspace', help='Filter by workspace name')
    parser.add_argument('--session', help='Filter by scan session name')
    parser.add_argument('--limit', type=int, default=200, help='Maximum number of rows per section')
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(json.dumps({'error': f'Database not found: {db_path}'}))
        sys.exit(1)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    data = query_data(conn, args)
    print(json.dumps(data, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
