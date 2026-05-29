# AutoPwn Scanner Web UI

This is a starter web interface for AutoPwn Scanner results.
It is a static browser UI that can visualize searchsploit JSON and Nmap XML output from the scanner pipeline.

## Setup

```bash
cd web-ui
npm install
npm run dev
```

Then open the local URL shown by Vite.

To run the full UI with local command execution:

```bash
cd web-ui
npm install
npm start
```

To develop with live reload and the local backend proxy:

```bash
cd web-ui
npm install
npm run dev
```

The Vite dev server runs on `http://localhost:4173` and proxies `/api` to the backend server on `http://localhost:4174`.

## Nmap command support

The UI supports direct `nmap` commands such as `nmap -A <target>`, `nmap -sV <target>`, `nmap --script=vuln <target>`, `nmap -O <target>`, `nmap -p- <target>`, and all other standard Nmap scan types.

## Usage

1. Run a scan with `./scanner_runner` in the AutoPwn-Scanner folder.
2. Upload the generated `searchsploit_results.json` and optional `scan_*.xml` files.
3. Inspect the table and summary cards.

## Notes

- This UI is intentionally simple and framework-free.
- It is a starting point for a proper web dashboard.
