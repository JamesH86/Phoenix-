"""Read-only host and repository inventory for Phoenix Guardian Evolution Engine.

This first milestone collects package and manifest metadata only. It does not
install, update, remove, execute project code, inspect secret contents, or make
network requests.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

MANIFEST_NAMES = {
    "requirements.txt", "requirements-dev.txt", "pyproject.toml",
    "poetry.lock", "Pipfile", "Pipfile.lock", "package.json",
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
}
EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    "build", "dist", ".tox", ".mypy_cache",
}
MAX_MANIFESTS = 500
MAX_PACKAGES = 50000


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_inventory(root_value: str | None) -> dict[str, Any] | None:
    if not root_value:
        return None
    root = Path(root_value).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("repository root must be a directory")
    manifests: list[dict[str, Any]] = []
    truncated = False
    for path in root.rglob("*"):
        relative_parts = path.relative_to(root).parts
        if any(part in EXCLUDED_DIRS for part in relative_parts):
            continue
        if path.is_symlink() or not path.is_file() or path.name not in MANIFEST_NAMES:
            continue
        resolved = path.resolve(strict=True)
        if root not in resolved.parents:
            continue
        manifests.append({
            "path": resolved.relative_to(root).as_posix(),
            "bytes": resolved.stat().st_size,
            "sha256": _sha256(resolved),
        })
        if len(manifests) >= MAX_MANIFESTS:
            truncated = True
            break
    return {
        "root": str(root),
        "manifest_count": len(manifests),
        "manifests_truncated": truncated,
        "manifests": sorted(manifests, key=lambda item: item["path"]),
        "collection": "manifest names, sizes, and SHA-256 hashes only; file contents are not collected",
    }


def debian_packages() -> dict[str, Any]:
    executable = shutil.which("dpkg-query")
    if not executable:
        return {"available": False, "manager": "dpkg", "reason": "dpkg-query not found"}
    result = subprocess.run(
        [executable, "-W", "-f=${binary:Package}\t${Version}\n"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode != 0:
        return {
            "available": False, "manager": "dpkg",
            "reason": (result.stderr.strip() or f"dpkg-query exited {result.returncode}")[:500],
        }
    packages = []
    for line in result.stdout.splitlines()[:MAX_PACKAGES]:
        name, separator, version = line.partition("\t")
        if separator and name:
            packages.append({"name": name, "version": version})
    return {
        "available": True, "manager": "dpkg",
        "package_count": len(packages),
        "truncated": len(result.stdout.splitlines()) > MAX_PACKAGES,
        "packages": packages,
    }


def build_report(repo_root: str | None = None) -> dict[str, Any]:
    system = platform.system()
    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": "read-only-inventory",
        "host": {
            "system": system,
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "package_inventory": (
            debian_packages() if system == "Linux"
            else {"available": False, "reason": "initial prototype supports dpkg inventory on Linux only"}
        ),
        "repository": repository_inventory(repo_root),
        "safety": {
            "network_requests": False,
            "package_changes": False,
            "project_code_execution": False,
            "secret_contents_collected": False,
            "privilege_escalation": False,
        },
        "limitations": [
            "Inventory is not a vulnerability determination.",
            "Package-to-CVE matching and vendor advisory verification are a later milestone.",
            "A missing package record is not proof that software is absent.",
            "Run this only on a host and repository you own or are authorized to assess.",
        ],
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", help="Optional repository directory to inventory")
    parser.add_argument("--output", help="Write JSON report to this path instead of stdout")
    args = parser.parse_args()
    try:
        report = build_report(args.repo_root)
        rendered = json.dumps(report, indent=2, sort_keys=True)
        if args.output:
            destination = Path(args.output).expanduser()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(rendered + "\n", encoding="utf-8")
            print(f"Read-only inventory written to {destination}")
        else:
            print(rendered)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
