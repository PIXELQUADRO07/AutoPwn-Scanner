import express from 'express';
import cors from 'cors';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs/promises';
import { constants } from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const port = process.env.PORT || 4174;
const repoRoot = path.join(__dirname, '..');
const scannerPath = path.join(repoRoot, 'scanner_runner');
const fallbackNmap = 'nmap';

async function findExecutable(executable) {
  if (path.isAbsolute(executable) || executable.includes('/')) {
    await fs.access(executable, constants.X_OK);
    return executable;
  }
  const envPath = process.env.PATH || '';
  for (const dir of envPath.split(path.delimiter)) {
    const candidate = path.join(dir, executable);
    try {
      await fs.access(candidate, constants.X_OK);
      return candidate;
    } catch {
      continue;
    }
  }
  throw new Error(`${executable} not found in PATH`);
}

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

app.post('/api/execute', async (req, res) => {
  const command = String(req.body.command || '').trim();
  const shellMode = Boolean(req.body.shell);

  if (!command) {
    return res.status(400).json({ error: 'No command provided.' });
  }

  const cwd = repoRoot;
  let exec = '';
  let args = [];
  let useScannerRunner = true;

  if (shellMode) {
    exec = 'sh';
    args = ['-lc', command];
  } else {
    const tokens = command.split(/\s+/).filter(Boolean);
    if (tokens.length === 0) {
      return res.status(400).json({ error: 'Command is empty.' });
    }
    // Run through the local scanner_runner binary when possible.
    if (tokens[0] === './scanner_runner') {
      tokens.shift();
      exec = scannerPath;
      args = tokens;
    } else if (tokens[0] === 'scanner_runner') {
      tokens.shift();
      exec = scannerPath;
      args = tokens;
    } else if (tokens[0] === 'nmap') {
      if (tokens.length === 1) {
        return res.status(400).json({ error: 'Usage: nmap <target> [options]' });
      }
      exec = fallbackNmap;
      args = tokens.slice(1);
      useScannerRunner = false;
    } else {
      exec = scannerPath;
      args = tokens;
    }
  }

  if (!shellMode) {
    if (useScannerRunner) {
      try {
        await fs.access(scannerPath, constants.X_OK);
      } catch (err) {
        return res.status(500).json({ error: `Local scanner_runner not found or not executable at ${scannerPath}.` });
      }
    } else {
      try {
        exec = await findExecutable(fallbackNmap);
      } catch (err) {
        return res.status(500).json({ error: `Local nmap not found or not executable: ${err.message}` });
      }
    }
  }

  let responded = false;
  const child = spawn(exec, args, {
    cwd,
    shell: false,
  });

  let output = '';
  child.stdout.on('data', (chunk) => {
    output += chunk.toString();
  });
  child.stderr.on('data', (chunk) => {
    output += chunk.toString();
  });

  const sendJson = (status, payload) => {
    if (responded) return;
    responded = true;
    res.status(status).json(payload);
  };

  child.on('error', (err) => {
    sendJson(500, { error: err.message, output });
  });

  child.on('close', (code) => {
    sendJson(200, { output, exitCode: code });
  });

  req.on('close', () => {
    if (!responded) {
      child.kill('SIGKILL');
    }
  });
});

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Invalid JSON payload.', details: err.message });
  }
  console.error('Unhandled server error:', err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(port, () => {
  console.log(`AutoPwn Web UI server listening on http://localhost:${port}`);
});
