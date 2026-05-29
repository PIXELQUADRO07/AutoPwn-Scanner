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
    } else {
      exec = scannerPath;
      args = tokens;
    }
  }

  if (!shellMode) {
    try {
      await fs.access(scannerPath, constants.X_OK);
    } catch (err) {
      return res.status(500).json({ error: `Local scanner_runner not found or not executable at ${scannerPath}.` });
    }
  }

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

  child.on('error', (err) => {
    res.status(500).json({ error: err.message });
  });

  child.on('close', (code) => {
    res.json({ output, exitCode: code });
  });
});

app.listen(port, () => {
  console.log(`AutoPwn Web UI server listening on http://localhost:${port}`);
});
