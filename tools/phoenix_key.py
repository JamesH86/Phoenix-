"""Inspect or rotate Phoenix Guardian's first-party local control key."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phoenix_auth import ControlKeyError, ControlKeyStore


def config_root() -> Path:
    override = str(os.environ.get("PHOENIX_CONFIG_DIR", "") or "").strip()
    if override:
        return Path(override).expanduser()
    base = os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME") or str(Path.home())
    return Path(base).expanduser() / "PhoenixGuardian"


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Phoenix's monthly owner control key")
    parser.add_argument("action", choices=("status", "show", "rotate"), nargs="?", default="status")
    args = parser.parse_args()
    store = ControlKeyStore(config_root())

    try:
        if args.action == "status":
            print(json.dumps(store.metadata(), indent=2))
        elif args.action == "show":
            print(store.get_or_create_key())
        else:
            print(store.rotate())
            print("Previous Phoenix control key revoked; restart or relaunch open web sessions.", file=sys.stderr)
    except ControlKeyError as exc:
        print(f"Phoenix key error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
