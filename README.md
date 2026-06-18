# Phoenix Guardian

Phoenix Guardian is a local-first cybersecurity command center built for authorized security research, bug bounty preparation, defensive validation, evidence handling, and professional reporting.

The app combines a modern dark-mode GUI with Groq-powered chat, Kali WSL integration, scoped web auditing, HackerOne-oriented workflow support, fraud analysis, voice commands, tool inventory, current vulnerability intelligence, dashboards, and export-ready reports.

This repository contains the current working version. It is not the final major release.

## Repository Description

Phoenix Guardian is a local cybersecurity command center for authorized security research, bug bounty workflows, Kali WSL tooling, Groq AI chat, fraud analysis, voice commands, reporting, and defensive posture review.

## Suggested Topics

```text
cybersecurity, bug-bounty, kali-linux, wsl2, groq, security-tools, fraud-analysis, defensive-security, tkinter, python
```

## Run

```bash
python phoenix_guardian.py
```

On Windows, launch it with Python from the repository folder:

```powershell
python .\phoenix_guardian.py
```

## Web UI Preview

Phoenix Guardian now includes a zero-install web UI preview built with semantic HTML, modern CSS, plain JavaScript, and a local Python API bridge. It is the visual direction for the future desktop shell while the Python app remains the working security engine.

```bash
python3 tools/serve_web_ui.py
```

Open:

```text
http://127.0.0.1:8787
```

The web shell now has real tab-specific actions for Command, Bug Bounty, Intelligence, Operations, Reports, and Settings. It can read local Phoenix status, add authorized scope, run scoped web audits, draft bug bounty reports, check Burp readiness, request current-vector intelligence, fetch public browser context, catalog Kali wordlists, run guarded WSL commands, run voice diagnostics, prepare fraud evidence reports, summarize findings, and display launch guardrails through the local backend.

## Optional Features

- Set `GROQ_API_KEY` or save a Groq key in the app Settings tab for chat.
- Install `SpeechRecognition` for Python voice recognition. Direct microphone capture also needs PyAudio/PortAudio; on Kali/WSL use `sudo apt-get install -y python3-pyaudio portaudio19-dev`.
- Windows System.Speech is used as a fallback for voice commands.
- Kali/WSL features require WSL2 and the configured Kali distro.

## Safety Model

Phoenix Guardian is built for authorized testing, defensive validation, and evidence-ready reporting. It keeps hard guardrails visible in the Settings tab and blocks credential theft, token grabbing, license piracy, rogue access point attacks, exploit delivery, destructive actions, persistence, and stealth workflows.

Do not commit local secrets, API keys, exported fraud data, scope files, chat memory, or evidence files.
