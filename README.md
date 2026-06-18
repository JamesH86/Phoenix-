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

## Optional Features

- Set `GROQ_API_KEY` or save a Groq key in the app Settings tab for chat.
- Install `SpeechRecognition` and a working microphone stack for Python voice recognition.
- Windows System.Speech is used as a fallback for voice commands.
- Kali/WSL features require WSL2 and the configured Kali distro.

## Safety Model

Phoenix Guardian is built for authorized testing, defensive validation, and evidence-ready reporting. It keeps hard guardrails visible in the Settings tab and blocks credential theft, token grabbing, license piracy, rogue access point attacks, exploit delivery, destructive actions, persistence, and stealth workflows.

Do not commit local secrets, API keys, exported fraud data, scope files, chat memory, or evidence files.
