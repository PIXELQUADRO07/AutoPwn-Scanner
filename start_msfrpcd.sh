#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# start_msfrpcd.sh
# Starts the Metasploit RPC daemon in background.
# Usage: bash start_msfrpcd.sh [password]
# ─────────────────────────────────────────────────────────────────

PASSWORD="${1:-iltuopassword}"
PORT=55553

echo "[RPC] Starting msfrpcd on port $PORT..."
echo "[RPC] Password: $PASSWORD"

# -P  password
# -n  disable SSL (optional, simpler in lab)
# -f  run in foreground (remove for background)
# -a  bind only to localhost
msfrpcd -P "$PASSWORD" -n -f -a 127.0.0.1 -p $PORT

# To start it in background:
# msfrpcd -P "$PASSWORD" -n -a 127.0.0.1 -p $PORT &
# echo "[RPC] PID: $!"
