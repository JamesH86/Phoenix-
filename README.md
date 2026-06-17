# Phoenix Guardian

Phoenix Guardian is a local defensive security command center for authorized security research, bug bounty evidence handling, Kali WSL workflows, Groq-powered chat, fraud analysis, reporting, and posture review.

This repository contains the current working version. It is not the final major release.

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

