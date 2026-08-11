"""Configure private Tailscale Serve access without exposing Phoenix publicly."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phoenix_remote import RemoteAccessError, RemoteAccessStore


def config_root() -> Path:
    override = str(os.environ.get("PHOENIX_CONFIG_DIR", "") or "").strip()
    if override:
        return Path(override).expanduser()
    base = os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME") or str(Path.home())
    return Path(base).expanduser() / "PhoenixGuardian"


def tailscale_path() -> str:
    executable = shutil.which("tailscale")
    if not executable:
        raise RemoteAccessError("Tailscale is not installed or is not available on PATH.")
    return executable


def run_tailscale(*arguments: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [tailscale_path(), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def device_origin() -> str:
    try:
        result = run_tailscale("status", "--json", timeout=15)
        payload = json.loads(result.stdout)
        dns_name = str(payload.get("Self", {}).get("DNSName", "") or "").strip().rstrip(".")
    except (subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise RemoteAccessError(f"Could not read authenticated Tailscale status: {exc}") from exc
    if not dns_name.endswith(".ts.net"):
        raise RemoteAccessError("Tailscale MagicDNS and HTTPS are required before Phoenix can be shared privately.")
    return f"https://{dns_name.lower()}"


def local_server_ready(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2) as response:
            return response.status == 200 and bool(json.loads(response.read().decode("utf-8")).get("ok"))
    except (OSError, ValueError, urllib.error.URLError):
        return False


def enable(port: int) -> dict:
    if not local_server_ready(port):
        raise RemoteAccessError("Start Phoenix locally before enabling private anywhere access.")
    origin = device_origin()
    target = f"http://127.0.0.1:{port}"
    try:
        run_tailscale("serve", "--bg", "--https=443", target)
    except subprocess.SubprocessError as exc:
        raise RemoteAccessError(f"Tailscale Serve could not be enabled: {exc}") from exc
    return RemoteAccessStore(config_root()).save(origin, provider="tailscale")


def disable(port: int) -> dict:
    target = f"http://127.0.0.1:{port}"
    try:
        run_tailscale("serve", "--https=443", target, "off")
    except subprocess.SubprocessError as exc:
        raise RemoteAccessError(f"Tailscale Serve could not be disabled: {exc}") from exc
    return RemoteAccessStore(config_root()).disable()


def main() -> int:
    parser = argparse.ArgumentParser(description="Private Phoenix access through authenticated Tailscale Serve")
    parser.add_argument("action", choices=("status", "enable", "disable"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PHOENIX_PORT", "8787")))
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    store = RemoteAccessStore(config_root())
    try:
        if args.action == "enable":
            result = enable(args.port)
        elif args.action == "disable":
            result = disable(args.port)
        else:
            result = store.load()
    except RemoteAccessError as exc:
        print(f"Remote access not ready: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
