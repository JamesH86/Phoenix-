# Phoenix Guardian Authenticated Web UI

This is Phoenix Guardian's zero-install local web interface. It uses semantic HTML, modern CSS, plain JavaScript, and an authenticated local Python API bridge.

## Run

From the repository root:

```bash
python3 tools/launch_phoenix.py
```

Then open:

```text
http://127.0.0.1:8787
```

The launcher generates or reuses Phoenix's free first-party control key and passes it to the browser without committing it to the repository. The shell exposes bounded local actions for all visible tabs, including one-click repository protection, known-good restoration, verification, rollback, status, authorized scope, scoped web audits, reports, current-vector intelligence, safe public browser context, bounded fraud CSV import, and local inventories.

The UI elects one primary operator tab with Web Locks or a local-storage lease. Secondary tabs are read-only. The server independently prevents overlapping remediation runs and deduplicates repeated idempotency keys.

Arbitrary shell commands and arbitrary local filesystem paths are not accepted by the web API.
