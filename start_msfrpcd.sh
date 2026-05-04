#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# start_msfrpcd.sh
# Avvia il demone RPC di Metasploit in background.
# Uso: bash start_msfrpcd.sh [password]
# ─────────────────────────────────────────────────────────────────

PASSWORD="${1:-iltuopassword}"
PORT=55553

echo "[RPC] Avvio msfrpcd sulla porta $PORT..."
echo "[RPC] Password: $PASSWORD"

# -P  password
# -n  disabilita SSL (opzionale, più semplice in lab)
# -f  esegue in foreground (rimuovi per background)
# -a  bind solo su localhost
msfrpcd -P "$PASSWORD" -n -f -a 127.0.0.1 -p $PORT

# Per avviarlo in background:
# msfrpcd -P "$PASSWORD" -n -a 127.0.0.1 -p $PORT &
# echo "[RPC] PID: $!"
