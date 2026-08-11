# Windows and WSL2

Phoenix's main web service runs on Windows with standard Python. WSL2 is optional and should be used only for approved Linux tooling and read-only inventories.

## Windows host setup

1. Install Python 3.9 or newer from an organization-approved source and enable the Python launcher.
2. Clone or extract Phoenix into a user-writable application folder.
3. Double-click `Launch Phoenix.bat`.
4. Run `py tools\readiness.py` in PowerShell to verify the host.

## Optional WSL2 setup

In an elevated PowerShell session managed by the organization:

```powershell
wsl --install
wsl --update
```

After the required restart, install a reviewed distribution such as Ubuntu or Kali from Microsoft Store or the organization's software catalog. Inside WSL:

```bash
sudo apt update
sudo apt install -y python3
```

Keep Phoenix itself on the Windows host unless the organization's deployment standard says otherwise. The old free-form WSL command endpoint remains disabled: Phoenix may inventory approved WSL tooling, but it cannot pass arbitrary shell text across the boundary.

## Access

Open the Windows loopback URL from the Windows browser. For private access from another enrolled device, configure Tailscale on the Windows host and follow `docs/INSTALLATION.md`. Never expose the loopback port through Windows port forwarding, a public reverse proxy, or Tailscale Funnel.
