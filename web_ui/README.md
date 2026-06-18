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

The shell exposes real local API actions for all visible tabs: status, authorized scope, scoped web audits, bug bounty checklist output, bug bounty report drafts, Burp status, HackerOne readiness guidance, current-vector intelligence, browser context fetches, wordlist inventory, voice diagnostics, Kali inventory, guarded WSL commands, fraud report preparation, defensive response, guardrail review, tool matrix review, and report summaries.
