"""Auditable autonomous Tier-1 security control loop for Phoenix Guardian.

The loop inventories the enrolled Phoenix application, evaluates deterministic
local controls, prioritizes findings, and delegates any authorized change to
``RemediationManager``.  It is intentionally not an endpoint agent, privileged
patch manager, arbitrary command runner, or replacement for organizational
risk ownership.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import platform
import stat
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


MANIFEST_NAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}
LOCKFILE_NAMES = {
    "poetry.lock",
    "Pipfile.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}
LAUNCHER_NAMES = {"Launch Phoenix.command", "Launch Phoenix.bat", "launch_phoenix.sh"}
SECRET_FILE_NAMES = {
    ".env",
    "credentials.json",
    "secrets.json",
    "service-account.json",
    "id_rsa",
    "id_ed25519",
}
SECRET_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".jks", ".keystore"}
EXCLUDED_PARTS = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _finding(
    identifier: str,
    control: str,
    title: str,
    severity: str,
    evidence: str,
    action: str,
    auto_remediable: bool = False,
) -> Dict[str, Any]:
    return {
        "id": identifier,
        "control": control,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "recommended_action": action,
        "auto_remediable": bool(auto_remediable),
    }


class Tier1SecurityManager:
    """Run deterministic, bounded security operations for one enrolled repo."""

    def __init__(self, repo_root: Any, state_root: Any, remediation: Any) -> None:
        self.repo_root = Path(os.fspath(repo_root)).expanduser().resolve(strict=True)
        if not self.repo_root.is_dir():
            raise ValueError("repo_root must be an existing directory")
        requested = Path(os.fspath(state_root)).expanduser()
        if not requested.is_absolute():
            requested = self.repo_root / requested
        requested.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state_root = requested.resolve(strict=True)
        if self.state_root == self.repo_root:
            raise ValueError("state_root cannot be the repository root")
        self.remediation = remediation
        self.audit_path = self.state_root / "tier1-audit.jsonl"
        if self.audit_path.exists() and self.audit_path.is_symlink():
            raise ValueError("audit path cannot be a symbolic link")
        self._lock = threading.Lock()
        self._last_report: Optional[Dict[str, Any]] = None
        self._idempotency: Dict[str, Dict[str, Any]] = {}
        self._audit("tier1_initialized")

    def coverage(self) -> Dict[str, Any]:
        """Return honest capability coverage, including material gaps."""
        return {
            "ok": True,
            "framework": "NIST Cybersecurity Framework 2.0",
            "functions": [
                {
                    "function": "Govern",
                    "status": "assisted",
                    "automated": ["locked execution policy", "local audit trail"],
                    "requires_organization": ["risk appetite", "legal accountability", "exception approval"],
                },
                {
                    "function": "Identify",
                    "status": "managed-local",
                    "automated": ["enrolled application inventory", "dependency manifest discovery", "control assessment"],
                    "requires_adapter": ["enterprise CMDB", "cloud accounts", "identity providers", "network devices"],
                },
                {
                    "function": "Protect",
                    "status": "managed-local",
                    "automated": ["authenticated control API", "scope enforcement", "known-good source snapshots"],
                    "requires_adapter": ["OS patch management", "EDR", "MDM", "IAM policy enforcement"],
                },
                {
                    "function": "Detect",
                    "status": "managed-local",
                    "automated": ["source health checks", "configuration posture checks", "finding prioritization"],
                    "requires_adapter": ["endpoint telemetry", "SIEM", "cloud and identity event streams"],
                },
                {
                    "function": "Respond",
                    "status": "bounded-local",
                    "automated": ["registered source restoration", "verification", "automatic rollback"],
                    "requires_adapter": ["host isolation", "account disablement", "firewall and cloud containment"],
                },
                {
                    "function": "Recover",
                    "status": "bounded-local",
                    "automated": ["pre-change snapshot", "known-good restore", "post-change validation"],
                    "requires_adapter": ["business continuity", "infrastructure restore", "communications and regulatory workflows"],
                },
            ],
            "claim": "Autonomous Tier-1 controls for the enrolled local application; not a replacement for accountable security leadership.",
        }

    def status(self) -> Dict[str, Any]:
        with self._lock:
            report = dict(self._last_report) if self._last_report else None
        return {
            "ok": True,
            "mode": "autonomous-tier1",
            "last_report": report,
            "audit_ready": self.audit_path.exists(),
            "capabilities": {
                "continuous_control_model": True,
                "deterministic_assessment": True,
                "priority_queue": True,
                "registered_response_only": True,
                "recovery_verification": True,
                "arbitrary_commands": False,
                "privilege_escalation": False,
                "public_exposure": False,
            },
        }

    def inventory(self) -> Dict[str, Any]:
        manifests: List[str] = []
        launchers: List[str] = []
        source_types = set()
        for path in self._files():
            relative = path.relative_to(self.repo_root).as_posix()
            if path.name in MANIFEST_NAMES:
                manifests.append(relative)
            if path.name in LAUNCHER_NAMES:
                launchers.append(relative)
            if path.suffix in {".py", ".js", ".mjs", ".cjs", ".html", ".css"}:
                source_types.add(path.suffix.lstrip("."))
        return {
            "asset": "enrolled-local-application",
            "platform": platform.system() or "Unknown",
            "architecture": platform.machine() or "Unknown",
            "source_types": sorted(source_types),
            "dependency_manifests": sorted(manifests),
            "launchers": sorted(launchers),
            "data_collection": "metadata-only; secret contents are never collected",
        }

    def assess(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        files = list(self._files())
        relative_names = {path.relative_to(self.repo_root).as_posix(): path for path in files}

        secret_candidates = [
            relative
            for relative, path in relative_names.items()
            if path.name in SECRET_FILE_NAMES or path.suffix.lower() in SECRET_SUFFIXES
        ]
        if secret_candidates:
            findings.append(_finding(
                "ID.SECRET.FILE",
                "Protect",
                "Potential secret-bearing files require repository review",
                "high",
                "Sensitive filename patterns were found; Phoenix did not open or return their contents.",
                "Remove secrets from version control, rotate affected credentials, and use an approved secret store.",
            ))

        requirements = relative_names.get("requirements.txt")
        if requirements is not None:
            lines = requirements.read_text(encoding="utf-8", errors="replace").splitlines()
            dependencies = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
            if dependencies and any("==" not in line for line in dependencies):
                findings.append(_finding(
                    "PR.DEP.PIN",
                    "Protect",
                    "Python dependencies are not reproducibly pinned",
                    "medium",
                    "requirements.txt contains range or unpinned dependency specifications.",
                    "Create a reviewed lock file or pin exact versions with an automated update process.",
                ))

        manifest_names = {path.name for path in files if path.name in MANIFEST_NAMES}
        package_managers_need_lock = (
            ("package.json" in manifest_names and not manifest_names.intersection(LOCKFILE_NAMES))
            or ("pyproject.toml" in manifest_names and not manifest_names.intersection(LOCKFILE_NAMES))
        )
        if package_managers_need_lock:
            findings.append(_finding(
                "PR.DEP.LOCK",
                "Protect",
                "A dependency lock file is missing",
                "medium",
                "A package manifest exists without a recognized lock file.",
                "Generate, review, and commit the ecosystem lock file.",
            ))

        missing_launchers = sorted(LAUNCHER_NAMES - {path.name for path in files})
        if missing_launchers:
            findings.append(_finding(
                "ID.PLATFORM.LAUNCH",
                "Identify",
                "Cross-platform launch coverage is incomplete",
                "low",
                "One or more supported platform launchers are absent.",
                "Add reviewed macOS, Windows, and Linux launchers.",
            ))

        private_failures = self._private_state_failures()
        if private_failures:
            findings.append(_finding(
                "PR.CONFIG.MODE",
                "Protect",
                "Phoenix private state permissions need repair",
                "high",
                "One or more Phoenix configuration paths are broader than owner-only permissions.",
                "Restrict the Phoenix configuration directory to the current account.",
            ))

        plan = self.remediation.plan()
        if not plan.get("ok"):
            findings.append(_finding(
                "DE.SOURCE.PREFLIGHT",
                "Detect",
                "Registered source-health preflight failed",
                "high",
                "The enrolled remediation engine could not complete its safe assessment.",
                "Review the local remediation audit and restore the reviewed application package.",
            ))
        elif not plan.get("assessment", {}).get("healthy", False):
            findings.append(_finding(
                "DE.SOURCE.HEALTH",
                "Detect",
                "Enrolled source failed deterministic health checks",
                "high",
                "Python or JavaScript syntax validation failed in the enrolled application.",
                "Authorize registered known-good restoration and verification.",
                auto_remediable=bool(plan.get("apply_supported")),
            ))

        if not findings:
            findings.append(_finding(
                "DE.BASELINE.CLEAR",
                "Detect",
                "No local Tier-1 control exceptions detected",
                "info",
                "All deterministic controls available to this installation passed.",
                "Continue scheduled assessment and connect approved enterprise telemetry adapters.",
            ))
        return sorted(findings, key=lambda item: (SEVERITY_ORDER[item["severity"]], item["id"]))

    def run_once(
        self,
        *,
        apply: bool = False,
        authorization: bool = False,
        idempotency_key: str = "",
    ) -> Dict[str, Any]:
        if apply and not authorization:
            return {
                "ok": False,
                "error": {"code": "authorization_required", "message": "One-click authorization is required before registered response actions."},
            }
        key = str(idempotency_key or "").strip()
        if len(key) > 256:
            return {"ok": False, "error": {"code": "invalid_idempotency_key", "message": "Idempotency key is too long."}}
        with self._lock:
            if key and key in self._idempotency:
                replay = dict(self._idempotency[key])
                replay["idempotent_replay"] = True
                return replay

        report: Dict[str, Any] = {
            "ok": True,
            "report_id": uuid.uuid4().hex,
            "created_at": _utc_now(),
            "mode": "authorized-response" if apply else "assessment-only",
            "inventory": self.inventory(),
            "findings": self.assess(),
            "coverage": self.coverage(),
            "response": {
                "status": "not-requested",
                "registered_actions_only": True,
                "human_exception_required": False,
            },
        }
        if apply:
            remediation_key = f"tier1-{key}" if key else f"tier1-{report['report_id']}"
            remediation_result = self.remediation.start(
                self.repo_root,
                idempotency_key=remediation_key,
                apply=True,
            )
            report["response"] = {
                "status": "started" if remediation_result.get("ok") else "blocked",
                "registered_actions_only": True,
                "human_exception_required": not remediation_result.get("ok", False),
                "remediation": remediation_result,
            }
        self._audit(
            "tier1_run_completed",
            report_id=report["report_id"],
            mode=report["mode"],
            severities=[item["severity"] for item in report["findings"]],
            response_status=report["response"]["status"],
        )
        with self._lock:
            self._last_report = report
            if key:
                self._idempotency[key] = report
        return report

    def _files(self) -> Iterable[Path]:
        for path in self.repo_root.rglob("*"):
            if any(part in EXCLUDED_PARTS for part in path.relative_to(self.repo_root).parts):
                continue
            if path.is_symlink() or not path.is_file():
                continue
            resolved = path.resolve(strict=True)
            if _within(resolved, self.repo_root):
                yield resolved

    def _private_state_failures(self) -> List[str]:
        if os.name == "nt":
            return []
        failures = []
        paths = [self.state_root]
        paths.extend(path for path in self.state_root.iterdir() if not path.is_symlink())
        for path in paths:
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                failures.append(path.name)
        return failures

    def _audit(self, event: str, **fields: Any) -> None:
        record = {"timestamp": _utc_now(), "event": event, **fields}
        descriptor = os.open(str(self.audit_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
                descriptor = -1
                handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
