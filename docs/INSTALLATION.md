# Phoenix Guardian Installation

Phoenix runs locally on macOS, Windows, and Linux with Python. Its browser UI is a local application, not a publicly hosted control panel. Private anywhere access is available through Tailscale Serve.

## Prerequisites

- Python 3.9 or newer
- A reviewed copy of this repository
- Optional: Node.js for JavaScript syntax verification
- Optional: Tailscale for private access from other enrolled devices

Check the current machine without changing it:

```bash
python3 tools/readiness.py
```

## Launch

- macOS: double-click `Launch Phoenix.command`
- Windows: double-click `Launch Phoenix.bat`
- Linux: run `./launch_phoenix.sh`

The launcher starts or reuses one loopback server and opens an authenticated browser session. A duplicate browser tab is read-only. Click **Authorize & Protect** once to run inventory, assessment, prioritization, registered response, verification, and audit.

## Private anywhere access

Do not forward Phoenix's port on a router and do not use Tailscale Funnel. Install Tailscale, sign the Phoenix host and operator devices into an organization-controlled tailnet, and restrict access with tailnet policy. Start Phoenix locally, then run:

```bash
python3 tools/phoenix_remote_access.py enable
```

The setup uses Tailscale Serve HTTPS, keeps Phoenix listening only on `127.0.0.1`, requires a Tailscale user identity header, and records one exact trusted HTTPS origin. Check or disable it with:

```bash
python3 tools/phoenix_remote_access.py status
python3 tools/phoenix_remote_access.py disable
```

Phoenix intentionally does not support public Funnel access. Remote operators still need the Phoenix control key; transfer it through the organization's approved secret manager, never GitHub or chat.

## Production boundary

The included adapter protects the enrolled Phoenix application source. OS updates, EDR actions, identity containment, cloud changes, network-device changes, and business recovery need separately reviewed adapters and enterprise permissions. Missing adapters are reported as gaps; Phoenix does not pretend they ran.
