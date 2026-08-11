"""Start or reuse one Phoenix server and open its authenticated web shell."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phoenix_auth import ControlKeyStore


def config_root() -> Path:
    override = str(os.environ.get("PHOENIX_CONFIG_DIR", "") or "").strip()
    if override:
        root = Path(override).expanduser()
    else:
        base = os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME") or str(Path.home())
        root = Path(base).expanduser() / "PhoenixGuardian"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    return root


def healthy(base_url: str, timeout: float = 1.0) -> bool:
    try:
        with urllib.request.urlopen(base_url + "/api/health", timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return response.status == 200 and bool(payload.get("ok"))
    except (OSError, ValueError, urllib.error.URLError):
        return False


def start_server(port: int, root: Path) -> None:
    log_path = root / "phoenix_web.log"
    log_handle = log_path.open("a", encoding="utf-8")
    try:
        log_path.chmod(0o600)
    except OSError:
        pass
    command = [sys.executable, str(REPO_ROOT / "tools" / "serve_web_ui.py"), "--port", str(port)]
    kwargs = {
        "cwd": str(REPO_ROOT),
        "stdin": subprocess.DEVNULL,
        "stdout": log_handle,
        "stderr": subprocess.STDOUT,
        "close_fds": os.name != "nt",
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    else:
        kwargs["start_new_session"] = True
    try:
        subprocess.Popen(command, **kwargs)
    finally:
        log_handle.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="One-click Phoenix Guardian launcher")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PHOENIX_PORT", "8787")))
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    root = config_root()
    key = ControlKeyStore(root).get_or_create_key()
    base_url = f"http://127.0.0.1:{args.port}"
    reused = healthy(base_url)
    if not reused:
        start_server(args.port, root)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not healthy(base_url):
            time.sleep(0.15)
        if not healthy(base_url):
            print(f"Phoenix did not start. Check {root / 'phoenix_web.log'}", file=sys.stderr)
            return 1

    authenticated_url = f"{base_url}/#key={key}"
    if not args.no_browser:
        webbrowser.open(authenticated_url)
    print(f"Phoenix Guardian {'reused' if reused else 'started'} at {base_url}")
    print("One active browser tab is enforced; secondary tabs are read-only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
