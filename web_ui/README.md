# Phoenix Guardian Web UI Preview

This is a zero-install web interface prototype for Phoenix Guardian. It uses semantic HTML, modern CSS, plain JavaScript, and a local Python API bridge so it can run anywhere Python is available.

## Run

From the repository root:

```bash
python3 tools/serve_web_ui.py
```

Then open:

```text
http://127.0.0.1:8787
```

The shell currently exposes local API actions for status, authorized scope, scoped web audits, bug bounty checklist output, current-vector intelligence, voice diagnostics, Kali inventory, and report summaries. It is designed to become the future Phoenix Guardian shell while the existing Python/Tkinter app remains available as the working desktop engine.
