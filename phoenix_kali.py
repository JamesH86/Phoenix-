"""Cross-platform Kali runtime bridge for registered Phoenix actions.

Windows uses the configured Kali WSL2 distribution. macOS and other hosts use
the official Kali container image through an already-installed Docker-compatible
runtime. Phoenix never mounts host files, adds privileges, or exposes a free-form
shell through the web API.
"""

from __future__ import annotations

import os
import platform
import re
import shlex
import shutil
import subprocess
from typing import Iterable


DEFAULT_KALI_IMAGE = "phoenix-guardian-kali:latest"
OFFICIAL_KALI_BASE_IMAGE = "kalilinux/kali-rolling"
MAX_OUTPUT_CHARS = 60_000
_DISTRO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_IMAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+)?$")


class KaliBridgeError(RuntimeError):
    """Raised when the registered Kali bridge cannot run safely."""


def _completed(args, timeout: int = 12) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )


def _safe_distro(value: object) -> str:
    distro = str(value or "kali-linux").strip() or "kali-linux"
    if not _DISTRO_PATTERN.fullmatch(distro):
        raise KaliBridgeError("Kali distribution name contains unsupported characters")
    return distro


def kali_image() -> str:
    image = str(os.environ.get("PHOENIX_KALI_IMAGE", DEFAULT_KALI_IMAGE) or "").strip()
    if not _IMAGE_PATTERN.fullmatch(image):
        raise KaliBridgeError("PHOENIX_KALI_IMAGE is not a valid reviewed container image name")
    return image


def runtime_status(distro: object = "kali-linux") -> dict:
    """Return honest availability for WSL2 or the confined container bridge."""

    system = platform.system() or "Unknown"
    safe_distro = _safe_distro(distro)
    if system == "Windows":
        executable = shutil.which("wsl.exe") or shutil.which("wsl")
        if not executable:
            return {
                "ok": True,
                "ready": False,
                "platform": system,
                "provider": "WSL2",
                "runtime": "unavailable",
                "setup": "Install WSL2 and the Kali Linux distribution, then reopen Phoenix.",
            }
        try:
            result = _completed([executable, "-l", "-q"])
        except (OSError, subprocess.TimeoutExpired):
            result = subprocess.CompletedProcess([], 1, "", "WSL2 did not answer")
        distributions = [line.strip().replace("\x00", "") for line in result.stdout.splitlines() if line.strip()]
        ready = result.returncode == 0 and safe_distro.lower() in {item.lower() for item in distributions}
        return {
            "ok": True,
            "ready": ready,
            "platform": system,
            "provider": "WSL2",
            "runtime": "ready" if ready else "Kali distribution missing",
            "distro": safe_distro,
            "setup": "Ready for registered Phoenix actions." if ready else f"Install or import the {safe_distro} WSL2 distribution.",
        }

    docker = shutil.which("docker")
    colima = shutil.which("colima") if system == "Darwin" else None
    provider = "Kali container on macOS" if system == "Darwin" else "Kali container"
    if not docker:
        return {
            "ok": True,
            "ready": False,
            "platform": system,
            "provider": provider,
            "runtime": "Docker-compatible runtime unavailable",
            "setup": "Install Docker Desktop or Colima with the Docker client." if system == "Darwin" else "Install a Docker-compatible container runtime.",
            "colima_detected": bool(colima),
        }
    try:
        daemon = _completed([docker, "info", "--format", "{{.ServerVersion}}"])
    except (OSError, subprocess.TimeoutExpired):
        daemon = subprocess.CompletedProcess([], 1, "", "Container runtime did not answer")
    if daemon.returncode != 0:
        return {
            "ok": True,
            "ready": False,
            "platform": system,
            "provider": provider,
            "runtime": "installed but not running",
            "setup": "Start Colima or Docker Desktop, then refresh this check." if system == "Darwin" else "Start the container runtime, then refresh this check.",
            "colima_detected": bool(colima),
        }
    image = kali_image()
    try:
        inspected = _completed([docker, "image", "inspect", image, "--format", "{{.Id}}"])
    except (OSError, subprocess.TimeoutExpired):
        inspected = subprocess.CompletedProcess([], 1, "", "Image inspection failed")
    ready = inspected.returncode == 0
    return {
        "ok": True,
        "ready": ready,
        "platform": system,
        "provider": provider,
        "runtime": "ready" if ready else "official Kali image missing",
        "image": image,
        "isolation": "no host mounts, no added capabilities, no new privileges, bounded CPU/memory/processes",
        "setup": "Ready for registered Phoenix actions." if ready else f"Pull or build a reviewed {image} image, then refresh this check.",
        "colima_detected": bool(colima),
    }


def run_registered(command: str, distro: object = "kali-linux", timeout: int = 45) -> str:
    """Run one internally registered action in WSL2 or a confined container."""

    if not isinstance(command, str) or not command.strip() or len(command) > 12_000 or "\x00" in command:
        raise KaliBridgeError("Registered Kali action is invalid")
    status = runtime_status(distro)
    if not status.get("ready"):
        return f"{status.get('provider')}: {status.get('runtime')}. {status.get('setup')}"
    safe_distro = _safe_distro(distro)
    if status["provider"] == "WSL2":
        executable = shutil.which("wsl.exe") or shutil.which("wsl")
        args = [executable, "-d", safe_distro, "--", "bash", "-lc", command]
    else:
        docker = shutil.which("docker")
        args = [
            docker,
            "run",
            "--rm",
            "--label",
            "com.phoenix-guardian.registered-action=true",
            "--network",
            "bridge",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            "1g",
            "--cpus",
            "1",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--user",
            "65534:65534",
            "--env",
            "HOME=/tmp",
            kali_image(),
            "bash",
            "-lc",
            command,
        ]
    try:
        completed = _completed(args, timeout=max(1, min(int(timeout), 180)))
    except subprocess.TimeoutExpired:
        return "Registered Kali action timed out."
    except OSError:
        return "The selected Kali runtime could not start."
    output = (completed.stdout or completed.stderr or "").strip()
    if not output:
        output = f"Registered Kali action finished with exit code {completed.returncode}."
    return output[:MAX_OUTPUT_CHARS]


def inventory(tool_names: Iterable[str], distro: object = "kali-linux") -> dict:
    """Inventory a fixed reviewed tool list without running scans or installations."""

    names = [str(name) for name in tool_names if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", str(name))]
    checks = [
        f"if command -v {shlex.quote(name)} >/dev/null 2>&1; then printf '{name}: installed\\n'; else printf '{name}: missing\\n'; fi"
        for name in names
    ]
    status = runtime_status(distro)
    if not status.get("ready"):
        return {"ok": True, "bridge": status, "inventory": [], "text": f"{status['provider']}: {status['runtime']}. {status['setup']}"}
    command = "echo '[Phoenix registered Kali inventory]'; " + "; ".join(checks)
    text = run_registered(command, distro=distro, timeout=45)
    found = []
    for line in text.splitlines():
        if line.endswith(": installed"):
            found.append(line.split(":", 1)[0])
    return {"ok": True, "bridge": status, "inventory": found, "text": text}


def prepare_container(build_context) -> dict:
    """Build Phoenix's reviewed Kali toolkit after one explicit UI authorization."""

    system = platform.system() or "Unknown"
    if system == "Windows":
        return {
            "ok": False,
            "prepared": False,
            "message": "Windows uses Kali WSL2. Install the Kali distribution through Windows, then refresh the bridge.",
        }
    docker = shutil.which("docker")
    if not docker:
        return {
            "ok": False,
            "prepared": False,
            "message": "Install Docker Desktop or Colima with the Docker client before preparing the Kali bridge.",
        }
    context = os.fspath(build_context)
    dockerfile = os.path.join(context, "Dockerfile")
    if not os.path.isfile(dockerfile):
        raise KaliBridgeError("Reviewed Phoenix Kali Dockerfile is missing")
    try:
        daemon = _completed([docker, "info", "--format", "{{.ServerVersion}}"])
    except (OSError, subprocess.TimeoutExpired):
        daemon = subprocess.CompletedProcess([], 1, "", "Container runtime did not answer")
    if daemon.returncode != 0:
        return {
            "ok": False,
            "prepared": False,
            "message": "Start Docker Desktop or Colima before preparing the Kali bridge.",
        }
    args = [docker, "build", "--pull", "--tag", kali_image(), context]
    try:
        completed = _completed(args, timeout=900)
    except subprocess.TimeoutExpired:
        return {"ok": False, "prepared": False, "message": "Kali toolkit preparation timed out after 15 minutes."}
    except OSError:
        return {"ok": False, "prepared": False, "message": "The container runtime could not start the reviewed build."}
    output = (completed.stdout or completed.stderr or "").strip()[-MAX_OUTPUT_CHARS:]
    return {
        "ok": completed.returncode == 0,
        "prepared": completed.returncode == 0,
        "image": kali_image(),
        "base_image": OFFICIAL_KALI_BASE_IMAGE,
        "message": "Phoenix Kali toolkit is ready." if completed.returncode == 0 else "Phoenix Kali toolkit build failed; review the bounded build output.",
        "output": output,
    }
