# Nightwatch — Nmap Report Viewer

A lightweight, responsive dashboard for inspecting Nmap scan output. Everything runs in the browser: scan text is parsed locally and is not uploaded to a service.

## Run locally

1. On Windows, double-click `Launch Nightwatch.bat` to open the dashboard in Chrome (or Edge if Chrome is not installed). You can also open `index.html` directly, or serve this folder with any static file server.
2. Choose a `.txt`, `.nmap`, `.gnmap`, or `.xml` scan file, or drag it onto the drop area.
3. Use the left navigation to review the report. Export summary saves a compact text summary.

For example, from this folder you can run `python -m http.server 8000` and open `http://localhost:8000`.

## Supported input

- Nmap normal output (`-oN`, including terminal output copied with `tee`)
- Nmap grepable output (`-oG`)
- Nmap XML output (`-oX`)

The format adapters live in `parser.js` and normalize into hosts, ports, scripts, findings, and unclassified lines. Add another parser adapter there and return that shared report shape to extend format support.

## Evidence and severity

- A vulnerability finding is shown as explicit only when script output contains a recognizable `VULNERABLE`, `VULNERABILITY`, CVE identifier, or `EXPLOITABLE` label. Severity reflects an explicit severity word in that same output; otherwise it is informational.
- Service banners and versions are listed as version-associated observations. They are not treated as proof that a vulnerability exists.
- Unrecognized lines remain visible under Raw output. The parser does not determine whether a host is secure.

The parser intentionally does not execute scans, fetch external vulnerability databases, or make network requests.
