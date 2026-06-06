/**
 * main.js — AutoPwn Scanner Web UI Frontend
 *
 * BUGS FIXED:
 *  1. parseNmapXml: querySelectorAll('port[state=open]') → WRONG selector
 *     Fixed: filter ports by child <state state="open"> element
 *  2. handleCommand: setTerminalLoading(false) missing in catch block
 *     Fixed: moved to finally block
 *  3. Summary innerHTML with unescaped topCves data
 *     Fixed: all dynamic content through escapeHtml()
 *  4. Terminal: no history navigation (↑↓ arrows)
 *     Fixed: added full history navigation
 *  5. SSE streaming: was using fetch+buffer, now consumes SSE live
 *  6. No kill button wiring
 *     Fixed: kill button calls /api/kill
 */

// ── DOM refs ─────────────────────────────────────────────────────
const jsonInput        = document.getElementById('json-file');
const xmlInput         = document.getElementById('xml-file');
const summaryEl        = document.getElementById('summary');
const resultsSection   = document.getElementById('results-section');
const hostsSection     = document.getElementById('hosts-section');
const resultsEl        = document.getElementById('results');
const hostsEl          = document.getElementById('hosts');
const commandInput     = document.getElementById('command-input');
const executeButton    = document.getElementById('execute-button');
const killButton       = document.getElementById('kill-button');
const shellToggle      = document.getElementById('shell-toggle');
const terminalOutput   = document.getElementById('terminal-output');
const scanTypeSelect   = document.getElementById('scan-type-select');
const applyPresetButton= document.getElementById('apply-preset-button');
const refreshHistoryButton = document.getElementById('refresh-history');
const exportCsvButton = document.getElementById('export-csv');
const exportHtmlButton = document.getElementById('export-html');
const filterHostInput = document.getElementById('filter-host');
const filterPortInput = document.getElementById('filter-port');
const filterCveInput = document.getElementById('filter-cve');
const filterWorkspaceInput = document.getElementById('filter-workspace');
const filterSessionInput = document.getElementById('filter-session');
const historyOutput = document.getElementById('history-output');
const animatedCards    = document.querySelectorAll('.card');

let jsonData = null;
let nmapData = null;
let historyData = null;
let terminalHistory = [];
let histIdx = -1;
let activeSSE = null;

// ── Card entrance animation ───────────────────────────────────────
const cardObserver = new IntersectionObserver((entries) => {
  entries.forEach((e) => {
    if (e.isIntersecting) { e.target.classList.add('visible'); cardObserver.unobserve(e.target); }
  });
}, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });

document.addEventListener('DOMContentLoaded', () => {
  document.body.classList.add('js-loaded');
  animatedCards.forEach((card, i) => {
    card.style.setProperty('--enter-delay', `${i * 80}ms`);
    cardObserver.observe(card);
  });
  loadHistory();
});

// ── File loaders ──────────────────────────────────────────────────
jsonInput.addEventListener('change', async (e) => {
  const file = e.target.files?.[0]; if (!file) return;
  try {
    jsonData = parseSearchsploitJson(await file.text());
    render();
    appendLine(`✓ Loaded: ${file.name}  (${jsonData.exploits.length} entries)`, 'ok');
  } catch (err) {
    appendLine(`✗ JSON parse error: ${err.message}`, 'err');
  }
});

xmlInput.addEventListener('change', async (e) => {
  const file = e.target.files?.[0]; if (!file) return;
  try {
    nmapData = parseNmapXml(await file.text());
    render();
    appendLine(`✓ Loaded: ${file.name}  (${nmapData.hosts.length} hosts, ${nmapData.openPorts} open ports)`, 'ok');
  } catch (err) {
    appendLine(`✗ XML parse error: ${err.message}`, 'err');
  }
});

// ── Terminal: command execution ───────────────────────────────────
executeButton.addEventListener('click', handleCommand);
killButton?.addEventListener('click', killProcess);
applyPresetButton.addEventListener('click', () => {
  commandInput.value = scanTypeSelect.value;
  handleCommand();
});
refreshHistoryButton?.addEventListener('click', () => loadHistory(true));
exportCsvButton?.addEventListener('click', exportHistoryCsv);
exportHtmlButton?.addEventListener('click', exportHistoryHtml);
filterHostInput?.addEventListener('input', () => loadHistory(true));
filterPortInput?.addEventListener('input', () => loadHistory(true));
filterCveInput?.addEventListener('input', () => loadHistory(true));
filterWorkspaceInput?.addEventListener('input', () => loadHistory(true));
filterSessionInput?.addEventListener('input', () => loadHistory(true));

commandInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); handleCommand(); return; }
  // History navigation
  if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (histIdx < terminalHistory.length - 1) {
      histIdx++;
      commandInput.value = terminalHistory[terminalHistory.length - 1 - histIdx];
    }
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (histIdx > 0) { histIdx--; commandInput.value = terminalHistory[terminalHistory.length - 1 - histIdx]; }
    else { histIdx = -1; commandInput.value = ''; }
  }
});

async function handleCommand() {
  let cmd = commandInput.value.trim();
  if (!cmd) return;

  let useShell = shellToggle.checked;
  if (/^shell:\s*/i.test(cmd)) {
    useShell = true;
    cmd = cmd.replace(/^shell:\s*/i, '');
  }

  terminalHistory.push(cmd);
  histIdx = -1;
  commandInput.value = '';
  appendLine(`\nautopwn > ${cmd}`, 'cmd');
  setLoading(true);

  // FIX: use SSE streaming instead of buffered fetch
  try {
    // Abort any previous SSE
    if (activeSSE) { activeSSE.abort(); activeSSE = null; }

    const ctrl = new AbortController();
    activeSSE = ctrl;

    const resp = await fetch('/api/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: cmd, shell: useShell }),
      signal: ctrl.signal,
    });

    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      appendLine(`✗ Error: ${data.error || resp.statusText}`, 'err');
      setLoading(false);
      return;
    }

    // Read SSE stream
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split('\n\n');
      buffer = parts.pop(); // incomplete chunk
      for (const part of parts) {
        const line = part.replace(/^data:\s*/, '').trim();
        if (!line) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.type === 'out')  appendLine(msg.text, classifyLine(msg.text));
          if (msg.type === 'err')  appendLine(msg.text, 'err');
          if (msg.type === 'done') {
            const ok = msg.exitCode === 0;
            appendLine(`\n[exit ${msg.exitCode}]`, ok ? 'ok' : 'err');
            setLoading(false);
            if (/^(scan|nmap)\s/i.test(cmd))
              appendLine('Tip: reload XML/JSON files to update summary.', 'info');
          }
        } catch {}
      }
    }
  } catch (err) {
    if (err.name !== 'AbortError')
      appendLine(`✗ Network error: ${err.message}`, 'err');
  } finally {
    setLoading(false);
    activeSSE = null;
  }
}

async function killProcess() {
  if (activeSSE) { activeSSE.abort(); activeSSE = null; }
  try {
    const r = await fetch('/api/kill', { method: 'POST' });
    const d = await r.json();
    appendLine(d.killed ? '[!] Process killed.' : '[!] No active process.', 'warn');
  } catch { appendLine('[!] Kill request failed.', 'err'); }
  setLoading(false);
}

// ── Terminal helpers ──────────────────────────────────────────────
function appendLine(text, cls = 'plain') {
  const div = document.createElement('div');
  div.textContent = text;
  div.className = `terminal-line ${cls}`;
  terminalOutput.appendChild(div);
  // Limit DOM size
  while (terminalOutput.children.length > 2000)
    terminalOutput.removeChild(terminalOutput.firstChild);
  terminalOutput.scrollTo({ top: terminalOutput.scrollHeight, behavior: 'smooth' });
}

function setLoading(on) {
  executeButton.disabled = on;
  executeButton.textContent = on ? 'Running…' : 'Run';
  if (killButton) killButton.disabled = !on;
}

function classifyLine(text) {
  const lo = text.toLowerCase();
  if (/\[+\]|✓|success|opened|session|★/.test(lo)) return 'ok';
  if (/-\]|error|fail|traceback/.test(lo))           return 'err';
  if (/\[!\]|warn|timeout|skip/.test(lo))            return 'warn';
  if (/\[*\]|\[»\]|starting|scanning|launching/.test(lo)) return 'info';
  if (text.startsWith('$') || text.startsWith('autopwn'))  return 'cmd';
  return 'plain';
}

// ── Summary ───────────────────────────────────────────────────────
function render() {
  if (!jsonData && !nmapData) { summaryEl.textContent = 'No data loaded yet.'; return; }
  const lines = [];
  if (jsonData) {
    lines.push(`<strong>SearchSploit entries:</strong> ${jsonData.exploits.length}`);
    lines.push(`<strong>Unique hosts:</strong> ${jsonData.hostCount}`);
    lines.push(`<strong>Official MSF matches:</strong> ${jsonData.officialCount}`);
    // FIX: escape topCves before inserting
    if (jsonData.topCves.length)
      lines.push(`<strong>Top CVEs:</strong> ${jsonData.topCves.map(escapeHtml).join(', ')}`);
  }
  if (nmapData) {
    lines.push(`<strong>Nmap hosts:</strong> ${nmapData.hosts.length}`);
    lines.push(`<strong>Open ports:</strong> ${nmapData.openPorts}`);
  }
  summaryEl.innerHTML = `<div class="summary-grid">${lines.map(l => `<div>${l}</div>`).join('')}</div>`;

  if (jsonData) {
    resultsSection.classList.replace('hidden','visible') || resultsSection.classList.remove('hidden');
    resultsSection.classList.add('visible');
    resultsEl.innerHTML = renderSearchsploitTable(jsonData.exploits);
  } else {
    resultsSection.classList.add('hidden'); resultsSection.classList.remove('visible');
  }
  if (nmapData) {
    hostsSection.classList.remove('hidden'); hostsSection.classList.add('visible');
    hostsEl.innerHTML = renderHostsTable(nmapData.hosts);
  } else {
    hostsSection.classList.add('hidden'); hostsSection.classList.remove('visible');
  }
}

async function loadHistory() {
  if (!historyOutput) return;
  historyOutput.innerHTML = '<p class="summary-empty">Loading history…</p>';
  try {
    const query = new URLSearchParams();
    if (filterHostInput?.value.trim()) query.set('host', filterHostInput.value.trim());
    if (filterPortInput?.value.trim()) query.set('port', filterPortInput.value.trim());
    if (filterCveInput?.value.trim()) query.set('cve', filterCveInput.value.trim());
    if (filterWorkspaceInput?.value.trim()) query.set('workspace', filterWorkspaceInput.value.trim());
    if (filterSessionInput?.value.trim()) query.set('session', filterSessionInput.value.trim());
    query.set('limit', '200');

    const resp = await fetch(`/api/history?${query.toString()}`);
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      historyOutput.innerHTML = `<p class="summary-empty">History error: ${escapeHtml(err.error || resp.statusText)}</p>`;
      appendLine(`✗ History failed: ${err.error || resp.statusText}`, 'err');
      return;
    }

    historyData = await resp.json();
    renderHistory();
    appendLine('✓ Scan history loaded.', 'ok');
  } catch (err) {
    historyOutput.innerHTML = `<p class="summary-empty">History load failed.</p>`;
    appendLine(`✗ History fetch error: ${err.message}`, 'err');
  }
}

function applyHistoryFilters(items) {
  if (!historyData) return items;
  const host = filterHostInput?.value.trim().toLowerCase();
  const port = filterPortInput?.value.trim();
  const cve = filterCveInput?.value.trim().toUpperCase();
  const workspace = filterWorkspaceInput?.value.trim().toLowerCase();
  const session = filterSessionInput?.value.trim().toLowerCase();
  const sessionMap = new Map((historyData.sessions || []).map(s => [s.id, s]));
  return items.filter((item) => {
    const target = historyData.targets.find(t => t.id === item.target_id) || {};
    const session = sessionMap.get(target.session_id) || {};
    let ok = true;
    if (host) ok = ok && ((target.ip || target.hostname || '').toLowerCase().includes(host) || (item.service || '').toLowerCase().includes(host));
    if (port) ok = ok && String(item.port || '').includes(port);
    if (cve) ok = ok && String(item.cve_ids || '').toUpperCase().includes(cve);
    if (workspace) ok = ok && ((target.workspace || '').toLowerCase().includes(workspace) || (session.workspace || '').toLowerCase().includes(workspace));
    if (session) ok = ok && (String(session.name || '').toLowerCase().includes(session) || String(target.workspace || '').toLowerCase().includes(session));
    return ok;
  });
}

function renderHistory() {
  if (!historyData) {
    historyOutput.innerHTML = '<p class="summary-empty">No history available.</p>';
    return;
  }

  const targetMap = new Map(historyData.targets.map(t => [t.id, t]));
  const sessionMap = new Map((historyData.sessions || []).map(s => [s.id, s]));
  const vulnerabilities = applyHistoryFilters(historyData.vulnerabilities || []);
  const summaryLines = [];
  const topCves = historyData.top_cves || [];

  summaryLines.push(`<strong>Total targets:</strong> ${historyData.summary.total_targets}`);
  summaryLines.push(`<strong>Total vulnerabilities:</strong> ${historyData.summary.total_vulns}`);
  summaryLines.push(`<strong>MSF matches:</strong> ${historyData.summary.msf_vulns}`);
  summaryLines.push(`<strong>Successful exploits:</strong> ${historyData.summary.success_exploits}`);
  if (topCves.length) {
    summaryLines.push(`<strong>Top CVEs:</strong> ${topCves.map(c => `${escapeHtml(c.cve)} (${c.count})`).join(', ')}`);
  }
  if (historyData.sessions?.length) {
    summaryLines.push(`<strong>Sessions:</strong> ${historyData.sessions.length}`);
  }

  const summaryHtml = `<div class="summary-grid">${summaryLines.map(l => `<div>${l}</div>`).join('')}</div>`;
  const tableHtml = vulnerabilities.length
    ? `<table><thead><tr><th>Host</th><th>Workspace</th><th>Session</th><th>Port</th><th>Service</th><th>Exploit</th><th>MSF</th><th>CVEs</th><th>Found</th></tr></thead><tbody>${vulnerabilities.map(v => {
        const target = targetMap.get(v.target_id) || {};
        const session = sessionMap.get(target.session_id) || {};
        return `<tr><td>${escapeHtml(target.ip || 'unknown')}</td><td>${escapeHtml(target.workspace || session.workspace || '')}</td><td>${escapeHtml(session.name || '')}</td><td>${escapeHtml(String(v.port || ''))}</td><td>${escapeHtml(v.service || '')}</td><td title="${escapeHtml(v.exploit_path || '')}">${escapeHtml(v.exploit_name || '')}</td><td class="${v.has_msf?'msf-yes':'msf-no'}">${v.has_msf ? '✓' : '✗'}</td><td>${escapeHtml(v.cve_ids || '')}</td><td>${escapeHtml(v.found_time || '')}</td></tr>`;
      }).join('')}</tbody></table>`
    : '<p class="summary-empty">No vulnerabilities match the current filters.</p>';

  historyOutput.innerHTML = `${summaryHtml}${tableHtml}`;
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function exportHistoryCsv() {
  if (!historyData) {
    appendLine('✗ Load history before exporting.', 'warn');
    return;
  }
  const targetMap = new Map(historyData.targets.map(t => [t.id, t]));
  const rows = ['Host,Hostname,Workspace,Session,Port,Protocol,Service,Version,Exploit,MSF,CVEs,Found'];
  for (const v of historyData.vulnerabilities || []) {
    const target = targetMap.get(v.target_id) || {};
    const session = sessionMap.get(target.session_id) || {};
    const values = [target.ip || '', target.hostname || '', target.workspace || session.workspace || '', session.name || '', v.port || '', v.protocol || '', v.service || '', v.version || '', v.exploit_name || '', v.has_msf ? 'YES' : 'NO', v.cve_ids || '', v.found_time || ''];
    rows.push(values.map(value => `"${String(value).replace(/"/g, '""')}"`).join(','));
  }
  downloadFile(`autopwn_history_${new Date().toISOString().slice(0,10)}.csv`, rows.join('\n'), 'text/csv;charset=utf-8;');
  appendLine('✓ History exported as CSV.', 'ok');
}

function exportHistoryHtml() {
  if (!historyData) {
    appendLine('✗ Load history before exporting.', 'warn');
    return;
  }
  const targetMap = new Map(historyData.targets.map(t => [t.id, t]));
  const rows = (historyData.vulnerabilities || []).map(v => {
    const target = targetMap.get(v.target_id) || {};
    const session = sessionMap.get(target.session_id) || {};
    return `<tr><td>${escapeHtml(target.ip || '')}</td><td>${escapeHtml(target.hostname || '')}</td><td>${escapeHtml(target.workspace || session.workspace || '')}</td><td>${escapeHtml(session.name || '')}</td><td>${escapeHtml(String(v.port || ''))}</td><td>${escapeHtml(v.protocol || '')}</td><td>${escapeHtml(v.service || '')}</td><td>${escapeHtml(v.version || '')}</td><td>${escapeHtml(v.exploit_name || '')}</td><td>${escapeHtml(v.has_msf ? 'YES' : 'NO')}</td><td>${escapeHtml(v.cve_ids || '')}</td><td>${escapeHtml(v.found_time || '')}</td></tr>`;
  }).join('');
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>AutoPwn Scan History</title><style>body{font-family:system-ui;line-height:1.4;background:#111;color:#eee;padding:20px;}table{border-collapse:collapse;width:100%;}th,td{padding:8px;border:1px solid #444;}th{background:#222;}</style></head><body><h1>AutoPwn Scan History</h1><table><thead><tr><th>Host</th><th>Hostname</th><th>Port</th><th>Proto</th><th>Service</th><th>Version</th><th>Exploit</th><th>MSF</th><th>CVEs</th><th>Found</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
  downloadFile(`autopwn_history_${new Date().toISOString().slice(0,10)}.html`, html, 'text/html;charset=utf-8;');
  appendLine('✓ History exported as HTML.', 'ok');
}

// ── Parsers ───────────────────────────────────────────────────────
function parseSearchsploitJson(text) {
  const data = JSON.parse(text);
  const exploits = [];
  const CVE = /CVE-\d{4}-\d{4,7}/gi;
  for (const [ip, items] of Object.entries(data)) {
    if (!Array.isArray(items)) continue;
    for (const item of items) {
      const title    = String(item.Title || '');
      const filePath = String(item.Path  || '');
      const type     = String(item.Type  || '');
      const cves     = [...new Set([...(title.match(CVE)||[]), ...(filePath.match(CVE)||[])])];
      const official = /\/modules\//i.test(filePath);
      exploits.push({ ip, title, path: filePath, type, cves, official });
    }
  }
  const hosts       = new Set(exploits.map(e => e.ip));
  const topCves     = countTop(exploits.flatMap(e => e.cves));
  const officialCount = exploits.filter(e => e.official).length;
  return { exploits, hostCount: hosts.size, topCves, officialCount };
}

function parseNmapXml(text) {
  const parser = new DOMParser();
  const xml    = parser.parseFromString(text, 'application/xml');
  if (xml.querySelector('parsererror')) throw new Error('Invalid XML.');
  const hosts  = [];
  xml.querySelectorAll('host').forEach(hostNode => {
    const addr = hostNode.querySelector('address[addrtype="ipv4"], address[addrtype="ipv6"]');
    if (!addr) return;
    const ip   = addr.getAttribute('addr') || 'unknown';
    const ports= [];
    // FIX: 'state' is a CHILD element of <port>, not an attribute
    // Correct selector: find all <port> then check child <state state="open">
    hostNode.querySelectorAll('port').forEach(portNode => {
      const stateEl = portNode.querySelector('state');
      if (!stateEl || stateEl.getAttribute('state') !== 'open') return;
      const portId   = portNode.getAttribute('portid')  || '?';
      const protocol = portNode.getAttribute('protocol') || '?';
      const svcEl    = portNode.querySelector('service');
      const service  = svcEl?.getAttribute('name')    || 'unknown';
      const version  = [svcEl?.getAttribute('product'), svcEl?.getAttribute('version')]
                         .filter(Boolean).join(' ') || '';
      ports.push({ portId, protocol, service, version });
    });
    hosts.push({ ip, ports });
  });
  const openPorts = hosts.reduce((s, h) => s + h.ports.length, 0);
  return { hosts, openPorts };
}

// ── Table renderers ───────────────────────────────────────────────
function renderSearchsploitTable(exploits) {
  if (!exploits.length) return '<p>No exploit records found.</p>';
  return `<table>
    <thead><tr>
      <th>Host</th><th>Title</th><th>Type</th><th>CVEs</th><th>Official MSF</th>
    </tr></thead>
    <tbody>
      ${exploits.map(e => `<tr>
        <td>${escapeHtml(e.ip)}</td>
        <td title="${escapeHtml(e.path)}">${escapeHtml(e.title)}</td>
        <td>${escapeHtml(e.type)}</td>
        <td>${e.cves.map(c => `<span class="cve-tag">${escapeHtml(c)}</span>`).join(' ')}</td>
        <td class="${e.official?'msf-yes':'msf-no'}">${e.official?'✓ Yes':'✗ No'}</td>
      </tr>`).join('')}
    </tbody></table>`;
}

function renderHostsTable(hosts) {
  if (!hosts.length) return '<p>No hosts found.</p>';
  return `<table>
    <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th></tr></thead>
    <tbody>
      ${hosts.flatMap(h =>
        h.ports.length === 0
          ? [`<tr><td>${escapeHtml(h.ip)}</td><td colspan="3" class="dim">no open ports</td></tr>`]
          : h.ports.map((p, i) => `<tr>
              ${i===0 ? `<td rowspan="${h.ports.length}">${escapeHtml(h.ip)}</td>` : ''}
              <td>${escapeHtml(p.protocol)}/${escapeHtml(p.portId)}</td>
              <td>${escapeHtml(p.service)}</td>
              <td class="dim">${escapeHtml(p.version)}</td>
            </tr>`)
      ).join('')}
    </tbody></table>`;
}

// ── Utilities ─────────────────────────────────────────────────────
function countTop(items, n = 5) {
  const counts = {};
  for (const v of items) counts[v] = (counts[v] || 0) + 1;
  return Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,n).map(([v])=>v);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}
