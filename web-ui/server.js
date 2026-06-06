/**
 * server.js — AutoPwn Scanner Web UI Backend
 * Porta: 4174 (produzione)
 * Il frontend Vite (porta 4173) fa proxy di /api → qui.
 *
 * FIXES v2:
 *  - Percorso scanner_runner robusto con fallback
 *  - Logging degli errori dettagliato invece di 500 generico
 *  - Auto-detect: se il token sembra IP/CIDR → prepende 'scan'
 *  - Nmap/ping/whois trovati via PATH senza bisogno di scanner_runner
 *  - Gestione shell mode corretta
 *  - SSE streaming live
 *  - /api/kill funzionante
 */
import express   from 'express';
import cors      from 'cors';
import { spawn } from 'child_process';
import path      from 'path';
import fs        from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// ── Path resolution ────────────────────────────────────────────
// server.js è in web-ui/, scanner_runner è nella root del repo
const REPO_ROOT    = path.resolve(__dirname, '..');
const SCANNER_BIN  = path.join(REPO_ROOT, 'scanner_runner');
const SCANNER_EXISTS = fs.existsSync(SCANNER_BIN) &&
                       fs.statSync(SCANNER_BIN).mode & 0o111;

const app  = express();
const PORT = process.env.PORT || 4174;

let activeChild = null;

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// In produzione serve anche i file statici della web-ui
app.use(express.static(__dirname));

// ── Utility: cerca eseguibile nel PATH ─────────────────────────
function findInPath(name) {
  const dirs = (process.env.PATH || '').split(path.delimiter);
  for (const dir of dirs) {
    const full = path.join(dir, name);
    try {
      fs.accessSync(full, fs.constants.X_OK);
      return full;
    } catch {}
  }
  return null;
}

// ── Utility: riconosce IP o CIDR ──────────────────────────────
function looksLikeTarget(s) {
  return /^[\d.]+(?:\/\d+)?$/.test(s) || /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(s);
}

// ── /api/execute — SSE streaming ─────────────────────────────
app.post('/api/execute', (req, res) => {
  const rawCommand = String(req.body?.command || '').trim();
  const shellMode  = Boolean(req.body?.shell);
  const timeoutMs  = Number(req.body?.timeout) || 300_000;

  if (!rawCommand) {
    return res.status(400).json({ error: 'No command provided.' });
  }

  // SSE headers
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Accel-Buffering', 'no');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const sse = (obj) => {
    if (!res.writableEnded) res.write(`data: ${JSON.stringify(obj)}\n\n`);
  };
  const sseOut  = (text) => sse({ type: 'out',  text });
  const sseErr  = (text) => sse({ type: 'err',  text });
  const sseDone = (code) => { sse({ type: 'done', exitCode: code }); res.end(); };

  let exec, args;

  try {
    if (shellMode) {
      exec = 'sh'; args = ['-lc', rawCommand];
    } else {
      let tokens = rawCommand.split(/\s+/).filter(Boolean);

      // Auto-detect: IP/CIDR senza comando → prepende 'scan'
      if (looksLikeTarget(tokens[0])) {
        sseOut(`[*] Auto-detected target — running: scan ${rawCommand}`);
        tokens = ['scan', ...tokens];
      }

      const cmd0 = tokens[0].toLowerCase();

      // Comandi che vanno a scanner_runner
      const scannerCmds = new Set([
        'scan','nmap','sessions','kill','cleanup','report',
        'status','history','show','set','workspace','banner',
        'help','version','loot'
      ]);

      if (scannerCmds.has(cmd0)) {
        if (!SCANNER_EXISTS) {
          sseErr(`scanner_runner not found or not executable at: ${SCANNER_BIN}`);
          sseErr(`Run: g++ -o scanner_runner scanner_runner.cpp -std=c++17`);
          return sseDone(1);
        }
        exec = SCANNER_BIN;
        args = tokens; // ['scan', '192.168.1.0/24'] — dispatch() in C++ legge argv[1]

      } else if (cmd0 === 'ping') {
        exec = findInPath('ping') || 'ping';
        args = ['-c', '4', '-W', '2', ...tokens.slice(1)];

      } else if (cmd0 === 'whois') {
        exec = findInPath('whois') || 'whois';
        args = tokens.slice(1);

      } else {
        // Fallback generico: cerca nel PATH
        const found = findInPath(tokens[0]);
        if (!found) {
          sseErr(`Command not found: ${tokens[0]}`);
          sseErr(`Type 'help' to see available commands.`);
          return sseDone(1);
        }
        exec = found; args = tokens.slice(1);
      }
    }
  } catch (buildErr) {
    sseErr(`Internal error building command: ${buildErr.message}`);
    return sseDone(1);
  }

  // Avvia il processo
  sseOut(`$ ${exec} ${args.join(' ')}`);

  let child;
  try {
    child = spawn(exec, args, {
      cwd:   REPO_ROOT,
      shell: false,
      env:   { ...process.env, TERM: 'xterm-256color' },
    });
  } catch (spawnErr) {
    sseErr(`Spawn error: ${spawnErr.message}`);
    return sseDone(1);
  }

  activeChild = child;

  const killTimer = setTimeout(() => {
    sseErr(`[!] Timeout after ${timeoutMs / 1000}s`);
    child.kill('SIGKILL');
  }, timeoutMs);

  const emit = (chunk) => {
    for (const line of chunk.toString().split('\n')) {
      if (line.trim()) sseOut(line);
    }
  };

  child.stdout.on('data', emit);
  child.stderr.on('data', emit);

  child.on('error', (err) => {
    clearTimeout(killTimer);
    sseErr(`Process error: ${err.message}`);
    sseDone(-1);
    activeChild = null;
  });

  child.on('close', (code) => {
    clearTimeout(killTimer);
    sseDone(code ?? 0);
    activeChild = null;
  });

  req.on('close', () => {
    clearTimeout(killTimer);
    activeChild?.kill('SIGKILL');
    activeChild = null;
  });
});

// ── /api/kill ──────────────────────────────────────────────────
app.post('/api/kill', (req, res) => {
  if (activeChild) {
    activeChild.kill('SIGKILL');
    activeChild = null;
    res.json({ killed: true });
  } else {
    res.json({ killed: false, message: 'No active process.' });
  }
});

// ── /api/db ────────────────────────────────────────────────────
app.get('/api/db', (req, res) => {
  const dbPath = path.join(REPO_ROOT, 'results', 'scanner.db');
  if (!fs.existsSync(dbPath)) {
    return res.status(404).json({ error: 'No database found. Run a scan first.' });
  }
  const child = spawn('python3', ['./db_report.py', dbPath], { cwd: REPO_ROOT });
  let out = '';
  child.stdout.on('data', d => out += d);
  child.stderr.on('data', d => out += d);
  child.on('close', () => res.json({ output: out }));
  child.on('error', e => res.status(500).json({ error: e.message }));
});

// ── /api/history ─────────────────────────────────────────────────
app.get('/api/history', (req, res) => {
  const dbPath = path.join(REPO_ROOT, 'results', 'scanner.db');
  if (!fs.existsSync(dbPath)) {
    return res.status(404).json({ error: 'No database found. Run a scan first.' });
  }

  const args = ['./db_api.py', '--db', dbPath];
  if (req.query.host) args.push('--host', String(req.query.host));
  if (req.query.port) args.push('--port', String(req.query.port));
  if (req.query.cve) args.push('--cve', String(req.query.cve));
  if (req.query.workspace) args.push('--workspace', String(req.query.workspace));
  if (req.query.session) args.push('--session', String(req.query.session));
  if (req.query.limit) args.push('--limit', String(req.query.limit));

  const child = spawn('python3', args, { cwd: REPO_ROOT });
  let out = '';
  let err = '';

  child.stdout.on('data', d => out += d);
  child.stderr.on('data', d => err += d);

  child.on('close', (code) => {
    if (code !== 0) {
      return res.status(500).json({ error: err || 'Failed to read history.' });
    }
    try {
      return res.json(JSON.parse(out));
    } catch (parseErr) {
      return res.status(500).json({ error: 'Failed to parse history JSON.' });
    }
  });

  child.on('error', e => res.status(500).json({ error: e.message }));
});

// ── /api/status ────────────────────────────────────────────────
app.get('/api/status', (req, res) => {
  res.json({
    scannerReady: SCANNER_EXISTS,
    scannerPath:  SCANNER_BIN,
    repoRoot:     REPO_ROOT,
    port:         PORT,
  });
});

// ── Error handler ──────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[server error]', err);
  if (!res.headersSent)
    res.status(500).json({ error: err.message || 'Internal server error' });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`\x1b[92m[+]\x1b[0m AutoPwn Web backend → http://127.0.0.1:${PORT}`);
  console.log(`\x1b[96m[*]\x1b[0m scanner_runner: ${SCANNER_EXISTS ? '\x1b[92m✓ found\x1b[0m' : '\x1b[91m✗ NOT FOUND\x1b[0m'} (${SCANNER_BIN})`);
  console.log(`\x1b[96m[*]\x1b[0m repo root: ${REPO_ROOT}`);
});
