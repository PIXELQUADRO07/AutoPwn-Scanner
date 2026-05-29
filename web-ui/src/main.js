const jsonInput = document.getElementById('json-file');
const xmlInput = document.getElementById('xml-file');
const summaryEl = document.getElementById('summary');
const resultsSection = document.getElementById('results-section');
const hostsSection = document.getElementById('hosts-section');
const resultsEl = document.getElementById('results');
const hostsEl = document.getElementById('hosts');
const commandInput = document.getElementById('command-input');
const executeButton = document.getElementById('execute-button');
const shellToggle = document.getElementById('shell-toggle');
const terminalOutput = document.getElementById('terminal-output');

let jsonData = null;
let nmapData = null;
let terminalHistory = [];

jsonInput.addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    jsonData = await parseSearchsploitJson(await file.text());
    render();
    appendTerminalOutput('Loaded SearchSploit JSON.');
  } catch (error) {
    summaryEl.innerHTML = `<p class="error">Errore caricamento JSON: ${error.message}</p>`;
  }
});

xmlInput.addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    nmapData = parseNmapXml(await file.text());
    render();
  } catch (error) {
    summaryEl.innerHTML = `<p class="error">Errore caricamento XML: ${error.message}</p>`;
  }
});

executeButton.addEventListener('click', handleCommand);
commandInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    handleCommand();
  }
});

async function handleCommand() {
  let cmd = commandInput.value.trim();
  if (!cmd) return;

  let useShell = shellToggle.checked;
  if (/^shell:\s*/i.test(cmd)) {
    useShell = true;
    cmd = cmd.replace(/^shell:\s*/i, '').trim();
  }

  appendTerminalOutput(`$ ${useShell ? 'shell: ' + cmd : cmd}`);
  setTerminalLoading(true);
  try {
    const response = await fetch('/api/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: cmd, shell: useShell })
    });
    const data = await response.json();
    if (response.ok) {
      appendTerminalOutput(data.output || '[no output]');
      appendTerminalOutput(`Exit code: ${data.exitCode}`);
    } else {
      appendTerminalOutput(`Error: ${data.error || 'Unknown error'}`);
    }
    if (/^(scan\s+|nmap\s+|searchsploit\b)/i.test(cmd) && !useShell) {
      appendTerminalOutput('If files were generated, reload them to update summary.');
    }
  } catch (error) {
    appendTerminalOutput(`Network error: ${error.message}`);
  } finally {
    setTerminalLoading(false);
    terminalHistory.push(cmd);
    commandInput.value = '';
  }
}

function appendTerminalOutput(text) {
  const entry = document.createElement('div');
  entry.textContent = text;
  terminalOutput.appendChild(entry);
  terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

function setTerminalLoading(isLoading) {
  executeButton.disabled = isLoading;
  executeButton.textContent = isLoading ? 'Running...' : 'Run';
}

function render() {
  if (!jsonData && !nmapData) {
    summaryEl.textContent = 'No data loaded yet.';
    return;
  }

  const lines = [];
  if (jsonData) {
    lines.push(`<strong>SearchSploit entries:</strong> ${jsonData.exploits.length}`);
    lines.push(`<strong>Unique hosts:</strong> ${jsonData.hostCount}`);
    lines.push(`<strong>Official MSF matches:</strong> ${jsonData.officialCount}`);
    if (jsonData.topCves.length) {
      lines.push(`<strong>Top CVEs:</strong> ${jsonData.topCves.join(', ')}`);
    }
  }
  if (nmapData) {
    lines.push(`<strong>Nmap hosts:</strong> ${nmapData.hosts.length}`);
    lines.push(`<strong>Total open services:</strong> ${nmapData.openPorts}</strong>`);
  }

  summaryEl.innerHTML = `<div class="summary-grid">${lines.map((line) => `<div>${line}</div>`).join('')}</div>`;

  if (jsonData) {
    resultsSection.classList.remove('hidden');
    resultsEl.innerHTML = renderSearchsploitTable(jsonData.exploits);
  } else {
    resultsSection.classList.add('hidden');
  }

  if (nmapData) {
    hostsSection.classList.remove('hidden');
    hostsEl.innerHTML = renderHostsTable(nmapData.hosts);
  } else {
    hostsSection.classList.add('hidden');
  }
}

function parseSearchsploitJson(text) {
  const data = JSON.parse(text);
  const exploits = [];
  const cveRegex = /CVE-\d{4}-\d{4,7}/gi;

  for (const [ip, items] of Object.entries(data)) {
    if (!Array.isArray(items)) continue;
    for (const item of items) {
      const title = String(item.Title || '');
      const path = String(item.Path || '');
      const type = String(item.Type || '');
      const cves = Array.from(new Set([...(title.match(cveRegex) || []), ...(path.match(cveRegex) || [])]));
      const official = /\/modules\//i.test(path);
      exploits.push({ ip, title, path, type, cves, official });
    }
  }

  const hostSet = new Set(exploits.map((item) => item.ip));
  const topCves = countTopItems(exploits.flatMap((item) => item.cves));
  const officialCount = exploits.filter((item) => item.official).length;
  return { exploits, hostCount: hostSet.size, topCves, officialCount };
}

function parseNmapXml(text) {
  const parser = new DOMParser();
  const xml = parser.parseFromString(text, 'application/xml');
  const parseError = xml.querySelector('parsererror');
  if (parseError) throw new Error('Invalid XML file.');

  const hosts = [];
  xml.querySelectorAll('host').forEach((hostNode) => {
    const addr = hostNode.querySelector('address[type="ipv4"], address[type="ipv6"]');
    if (!addr) return;
    const ip = addr.getAttribute('addr') || 'unknown';
    const ports = [];
    hostNode.querySelectorAll('port[state=open]').forEach((portNode) => {
      const portId = portNode.getAttribute('portid') || '?';
      const protocol = portNode.getAttribute('protocol') || '?';
      const service = portNode.querySelector('service')?.getAttribute('name') || 'unknown';
      ports.push({ portId, protocol, service });
    });
    hosts.push({ ip, ports });
  });

  const openPorts = hosts.reduce((sum, host) => sum + host.ports.length, 0);
  return { hosts, openPorts };
}

function renderSearchsploitTable(exploits) {
  if (!exploits.length) return '<p>No exploit records found.</p>';
  return `
    <table>
      <thead>
        <tr><th>Host</th><th>Title</th><th>Type</th><th>Path</th><th>CVEs</th><th>Official</th></tr>
      </thead>
      <tbody>
        ${exploits
          .map(
            (item) => `
              <tr>
                <td>${item.ip}</td>
                <td>${escapeHtml(item.title)}</td>
                <td>${escapeHtml(item.type)}</td>
                <td>${escapeHtml(item.path)}</td>
                <td>${item.cves.join(', ')}</td>
                <td>${item.official ? 'Yes' : 'No'}</td>
              </tr>
            `,
          )
          .join('')}
      </tbody>
    </table>
  `;
}

function renderHostsTable(hosts) {
  if (!hosts.length) return '<p>No hosts found.</p>';
  return `
    <table>
      <thead>
        <tr><th>Host</th><th>Open ports</th><th>Services</th></tr>
      </thead>
      <tbody>
        ${hosts
          .map(
            (host) => `
              <tr>
                <td>${escapeHtml(host.ip)}</td>
                <td>${host.ports.length}</td>
                <td>${escapeHtml(host.ports.map((p) => `${p.protocol}/${p.portId}:${p.service}`).join(', '))}</td>
              </tr>
            `,
          )
          .join('')}
      </tbody>
    </table>
  `;
}

function countTopItems(items) {
  const counts = items.reduce((acc, value) => {
    acc[value] = (acc[value] || 0) + 1;
    return acc;
  }, {});
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([value]) => value);
}

function escapeHtml(raw) {
  return raw.replace(/[&<>"']/g, (match) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[match]);
}
