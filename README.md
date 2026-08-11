# Phoenix Guardian

Phoenix Guardian is a local-first cybersecurity command center built for authorized security research, defensive validation, evidence handling, and bounded one-click application protection.

The app combines a modern dark-mode GUI with a reusable private organization profile, a free keyless local assistant, an optional approved AI provider, scoped web auditing, provider-neutral security-program workflows, fraud analysis, voice commands, tool inventory, vulnerability intelligence, dashboards, and sanitized reports.

This repository contains the current working version. It is not the final major release.

## Repository Description

Phoenix Guardian is a vendor-neutral enterprise cybersecurity command center for authorized assessment, registered application healing, defensive validation, evidence handling, reporting, and posture review.

## Suggested Topics

```text
cybersecurity, enterprise-security, remediation, orchestration, rollback, security-tools, fraud-analysis, defensive-security, tkinter, python
```

## One-click launch

Phoenix starts or reuses one local server, generates its own free first-party control API key, and opens an authenticated browser session.

- macOS: double-click `Launch Phoenix.command`
- Windows: double-click `Launch Phoenix.bat`
- Linux: run `./launch_phoenix.sh`

From a terminal:

```bash
python3 tools/launch_phoenix.py
```

Then click **Authorize & Protect**. That click grants permission for one bounded run; Phoenix completes the remaining phases without more prompts:

```text
preflight -> inventory -> assess -> plan -> snapshot -> apply -> verify -> report
```

The button now starts Phoenix's autonomous Tier-1 loop first: asset inventory, deterministic control assessment, priority ordering, registered response, recovery verification, and private audit. Its coverage page explicitly separates working local controls from enterprise adapters that are not yet connected.

Only one remediation run is allowed at a time. Repeated requests with the same idempotency key reuse the existing run. A second browser tab becomes read-only.

## Desktop app

```bash
python phoenix_guardian.py
```

On Windows, launch it with Python from the repository folder:

```powershell
python .\phoenix_guardian.py
```

## Authenticated web UI

Phoenix Guardian includes a zero-install web UI built with semantic HTML, modern CSS, plain JavaScript, and a local Python API bridge.

```bash
python3 tools/serve_web_ui.py --open
```

Open:

```text
http://127.0.0.1:8787
```

The web shell has real actions for Command, Security Programs, Intelligence, Operations, Reports, Plans, and Settings. The health probe, public plan catalog, and free Demo activation are the only unauthenticated API routes. Every operational call requires an unexpired Phoenix bearer key and exact loopback Host/Origin checks.

Settings includes a validated organization profile for company name, business unit, environment, primary domain, security contact, asset owner, maintenance window, and data region. It is stored privately outside the repository so the same application can be configured for any organization without source edits.

The browser-context route is limited to in-scope public HTTP(S) destinations. Fraud analysis accepts bounded CSV contents instead of arbitrary local paths. The old free-form WSL shell endpoint is disabled; local changes go only through registered remediation actions.

## Free Phoenix API key

Phoenix generates its own owner control key on first run. It is free because it authenticates your local Phoenix API; it is not a shared cloud-model credential. Every owner and customer key has a 30-day term and stops authenticating at expiration. File-managed owner keys rotate automatically on the next launch after expiration.

```bash
python3 tools/phoenix_key.py status
python3 tools/phoenix_key.py show
python3 tools/phoenix_key.py rotate
```

The key is stored in Phoenix's private local configuration directory with restricted permissions. The dashboard does not display the plaintext key, fingerprint, or key identifier. The launcher passes the key in a URL fragment, the browser removes that fragment immediately, and the form remains masked.

Phoenix Local works without any model key. A Groq key is optional and must belong to the user or business account that enables it; shared provider keys are not embedded in the repository.

## Monthly plans and control keys

Phoenix now exposes five progressively gated plans in the dashboard:

| Plan | 30-day price | Included capability level |
| --- | ---: | --- |
| Demo | Free | Dashboard, readiness checklist, local AI guidance, guardrails, sample reports, and Tier-1 visibility |
| Solo Researcher | $50 | Guided defensive learning, private research workspace, platform readiness, and an asset notebook; no live audits or Bug Bounty automation |
| Base Cybersecurity Personnel | $150 | Solo features plus the dedicated Bug Bounty workspace, scope management, real authorized web audits, public security vectors, and reports |
| Enterprise | $1,000 | Base features plus autonomous registered remediation, enterprise profiles, Windows/macOS Kali integration, fraud response, private access, and security-program automation |
| Government | $1,500 | Enterprise features plus government control mapping and tamper-evident evidence seals |

A Demo control key can be activated directly from the Plans screen. All issued keys expire 30 days after issuance. Customer keys are stored only as one-way SHA-256 digests of high-entropy random values; the plaintext value is displayed once at issue time.

The repository includes an owner-side issuance command for use after a trusted payment system confirms a successful monthly charge:

```bash
python3 tools/phoenix_subscription.py catalog
python3 tools/phoenix_subscription.py issue solo --customer "Customer name"
python3 tools/phoenix_subscription.py issue base --customer "Customer name"
python3 tools/phoenix_subscription.py issue enterprise --customer "Customer name"
python3 tools/phoenix_subscription.py issue government --customer "Agency name"
python3 tools/phoenix_subscription.py list
python3 tools/phoenix_subscription.py revoke KEY_ID
```

Phoenix supports Square-hosted, one-time checkout for the four paid tiers. Each independently verified payment issues one control key valid for 30 days; automatic renewal is not yet implemented. A checkout redirect or browser callback never proves payment and cannot issue a key. Production requires completed Square seller verification, a linked payout bank account, private server-side credentials, and a seller-controlled public HTTPS webhook. Phoenix never stores card or bank-account details.

See [Square billing for 30-day Phoenix access](docs/SQUARE_BILLING.md) for the exact private configuration fields, Sandbox workflow, webhook events and signature checks, Production boundary, and launch checklist.

Because this is a self-hosted source repository, reliable commercial enforcement requires running the licensing and webhook authority on infrastructure controlled by the seller rather than shipping its secrets to customer devices.

## Code healing and rollback

`phoenix_orchestrator.py` manages the exact enrolled repository root. It:

- validates paths and rejects symlink escapes;
- checks Python syntax and JavaScript syntax when Node is available;
- creates versioned known-good and pre-heal snapshots;
- restores only existing managed source files when a known-good baseline can heal a failed check;
- verifies the result and keeps an append-only JSONL audit trail;
- preserves post-run user edits by refusing conflicting rollbacks.

The first release intentionally does not elevate privileges, reboot machines, run arbitrary commands, delete data, deploy remotely, or install OS updates. It reports macOS, Windows, and Linux capabilities, while future system/package/deployment adapters must be separately enrolled and provide their own verification and rollback contract.

Displayed reports automatically redact common payment-card, government-identifier, phone-number, and labeled account-number patterns. Raw imported evidence remains local and bounded; teams should still apply their retention and classification policies.

## Optional Features

- Set `GROQ_API_KEY` or save a Groq key in the app Settings tab for chat.
- Install `SpeechRecognition` for Python voice recognition. Direct microphone capture also needs PyAudio/PortAudio; on Kali/WSL use `sudo apt-get install -y python3-pyaudio portaudio19-dev`.
- Windows System.Speech is used as a fallback for voice commands.
- On Windows, registered Kali features require WSL2 and the configured Kali distribution.
- On macOS, Enterprise and Government plans can use a confined Kali container through Docker Desktop or Colima. Phoenix can build its reviewed toolkit from the Operations screen after the runtime is installed. See [the macOS Kali guide](docs/MACOS_KALI.md).
- Private anywhere access uses Tailscale Serve, never a public Funnel or router port-forward. See [installation and remote access](docs/INSTALLATION.md).
- Windows and optional WSL2 setup are documented in [the WSL2 guide](docs/WSL2.md).

## Installable mobile and desktop app

The web dashboard is also a Progressive Web App. It can be installed from a supporting browser on iPhone, iPad, Android, macOS, Windows, and Linux. Use **Settings → Install Phoenix App**. The installed shell never caches API responses or control keys.

The security engine still runs on an authorized Mac, Windows, or Linux host. Phones and tablets connect through Phoenix's configured private HTTPS access; the PWA does not expose the engine to the public internet and does not make unavailable host tools appear to work.

Run the read-only platform check at any time:

```bash
python3 tools/readiness.py
```

## Safety Model

Phoenix Guardian is built for systems, repositories, and targets you own or are explicitly authorized to manage. It keeps hard guardrails visible in the Settings tab and blocks credential theft, token grabbing, license piracy, rogue access point attacks, exploit delivery, destructive actions, persistence, stealth workflows, arbitrary shell execution, private-address browser fetches, and unenrolled path changes.

## Verify

```bash
python3 -m unittest discover -v
node tests/js_singleton_contract_test.js
node tests/js_redaction_contract_test.js
python3 tools/smoke_web_ui.py
```

Do not commit local secrets, API keys, exported fraud data, scope files, chat memory, or evidence files.
