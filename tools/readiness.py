"""Read-only cross-platform readiness report for Phoenix Guardian."""

from __future__ import annotations

import json
import platform
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phoenix_kali import runtime_status as kali_runtime_status


def readiness() -> dict:
    launchers = {
        "macos": (REPO_ROOT / "Launch Phoenix.command").is_file(),
        "windows": (REPO_ROOT / "Launch Phoenix.bat").is_file(),
        "linux": (REPO_ROOT / "launch_phoenix.sh").is_file(),
    }
    container_candidate = bool(shutil.which("docker"))
    kali_bridge = kali_runtime_status() if container_candidate or shutil.which("wsl.exe") or shutil.which("wsl") else {
        "ready": False,
        "provider": "WSL2 or confined Kali container",
        "runtime": "not installed",
    }
    optional = {
        "javascript_syntax_checks": bool(shutil.which("node")),
        "private_anywhere_access": bool(shutil.which("tailscale")),
        "windows_wsl_bridge": bool(shutil.which("wsl.exe") or shutil.which("wsl")),
        "burp_inventory": bool(shutil.which("burpsuite") or shutil.which("burp")),
        "cross_platform_kali_bridge": bool(kali_bridge.get("ready")),
    }
    platform_key = {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}.get(platform.system())
    required = {
        "supported_python": sys.version_info >= (3, 9),
        "web_ui": (REPO_ROOT / "web_ui" / "index.html").is_file(),
        "authenticated_server": (REPO_ROOT / "tools" / "serve_web_ui.py").is_file(),
        "tier1_control_loop": (REPO_ROOT / "phoenix_tier1.py").is_file(),
        "platform_launcher": launchers.get(platform_key, True),
    }
    return {
        "ok": all(required.values()),
        "platform": platform.system() or "Unknown",
        "required": required,
        "optional": optional,
        "kali_bridge": kali_bridge,
        "launchers": launchers,
        "notes": [
            "Optional integrations are reported as unavailable rather than simulated.",
            "Phoenix remains usable with its standard-library web UI and free local control key.",
            "Windows uses Kali WSL2; macOS and Linux use a confined, reviewed Kali container when available.",
        ],
    }


def main() -> int:
    report = readiness()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
