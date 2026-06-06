#!/usr/bin/env bash
# start_web.sh — AutoPwn Scanner Web UI launcher
# Uso:
#   bash start_web.sh        → dev (Vite 4173 + node 4174)
#   bash start_web.sh prod   → produzione (solo node 4174)
#   bash start_web.sh build  → build statica Vite

MODE="${1:-dev}"
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
WEB_DIR="$REPO_ROOT/web-ui"

R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'
D='\033[2m';  B='\033[1m';  RST='\033[0m'

echo ""
echo -e "${C}${B}  AutoPwn Scanner — Web UI${RST}"
echo -e "${D}  ─────────────────────────────────────${RST}"

# ── Compila scanner_runner se mancante ───────────────────────────
if [ ! -f "$REPO_ROOT/scanner_runner" ]; then
  echo -e "${Y}  [!]${RST} scanner_runner not found — compiling..."
  g++ -o "$REPO_ROOT/scanner_runner" "$REPO_ROOT/scanner_runner.cpp" \
      -std=c++17 -lreadline 2>/dev/null \
    || g++ -o "$REPO_ROOT/scanner_runner" "$REPO_ROOT/scanner_runner.cpp" -std=c++17
  [ $? -eq 0 ] && echo -e "${G}  [+]${RST} scanner_runner compiled" \
               || { echo -e "${R}  [-]${RST} Compilation failed"; exit 1; }
else
  echo -e "${G}  [+]${RST} scanner_runner found"
fi

# ── Installa dipendenze Node se mancanti ─────────────────────────
if [ ! -d "$WEB_DIR/node_modules" ]; then
  echo -e "${Y}  [!]${RST} Installing node_modules..."
  cd "$WEB_DIR" && npm install --silent
  [ $? -ne 0 ] && { echo -e "${R}  [-]${RST} npm install failed"; exit 1; }
  echo -e "${G}  [+]${RST} Dependencies installed"
fi

cd "$WEB_DIR"

case "$MODE" in
  prod|production)
    echo -e "${G}  [+]${RST} Starting production server on ${C}http://localhost:4174${RST}"
    echo -e "${D}      Ctrl+C to stop${RST}\n"
    node server.js
    ;;

  build)
    echo -e "${C}  [*]${RST} Building static assets..."
    npm run build && echo -e "${G}  [+]${RST} Build complete → web-ui/dist/"
    ;;

  dev|*)
    # Avvia node server.js in background, poi Vite in foreground
    echo -e "${G}  [+]${RST} Starting backend  → ${C}http://localhost:4174${RST} ${D}(node server.js)${RST}"
    node server.js &
    NODE_PID=$!
    echo -e "${G}  [+]${RST} Backend PID: $NODE_PID"

    # Aspetta che il backend sia pronto
    sleep 1
    if ! kill -0 $NODE_PID 2>/dev/null; then
      echo -e "${R}  [-]${RST} Backend failed to start — check node server.js manually"
      exit 1
    fi

    echo -e "${G}  [+]${RST} Starting frontend → ${C}http://localhost:4173${RST} ${D}(Vite)${RST}"
    echo -e "${D}      Ctrl+C stops both processes${RST}\n"

    # Trap per killare entrambi alla chiusura
    trap "echo ''; echo -e '${Y}  [!]${RST} Stopping...'; kill $NODE_PID 2>/dev/null; exit 0" INT TERM

    npm run dev

    # Se Vite termina, killa anche il backend
    kill $NODE_PID 2>/dev/null
    ;;
esac
