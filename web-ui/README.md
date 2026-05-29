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

The server will listen on `http://localhost:4174` and expose a safe command proxy to the local `scanner_runner` tool.

## Usage

1. Run a scan with `./scanner_runner` in the AutoPwn-Scanner folder.
2. Upload the generated `searchsploit_results.json` and optional `scan_*.xml` files.
3. Inspect the table and summary cards.

## Notes

- This UI is intentionally simple and framework-free.
- It is a starting point for a proper web dashboard.
