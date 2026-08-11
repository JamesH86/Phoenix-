"""Bounded, local-only remediation orchestration for Phoenix Guardian.

This module deliberately does not expose a general command runner.  It can
inventory managed Python and JavaScript source files, validate their syntax,
record verified known-good snapshots, and restore existing files from the
last known-good snapshot.  It never performs network access, elevation,
system updates, deletion, or shell-string execution.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import subprocess
import threading
import time
import tokenize
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PIPELINE_PHASES = (
    "preflight",
    "inventory",
    "assess",
    "plan",
    "snapshot",
    "apply",
    "verify",
    "report",
)
TERMINAL_STATES = {"succeeded", "failed", "cancelled", "rolled_back"}
ACTIVE_STATES = {"queued", "running", "cancelling"}
SOURCE_SUFFIXES = {".py", ".js", ".mjs", ".cjs"}
EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
    ".venv",
}

MAX_SOURCE_FILES = 1000
MAX_SOURCE_FILE_BYTES = 4 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_CHARS = 12000
MAX_AUDIT_LINE_CHARS = 24000
NODE_CHECK_TIMEOUT_SECONDS = 15


class _Cancelled(Exception):
    """Internal cooperative-cancellation signal."""


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def _bounded(value: Any, limit: int = MAX_OUTPUT_CHARS) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]"


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _json_error(code: str, message: str, **extra: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "ok": False,
        "error": {"code": code, "message": _bounded(message)},
    }
    payload.update(extra)
    return payload


class RemediationManager:
    """Coordinate one bounded remediation run for an exact repository root.

    Parameters are intentionally local filesystem values.  ``node_path`` is
    optional; when absent or unavailable, JavaScript checks are reported as
    skipped rather than executed by another mechanism.
    """

    def __init__(
        self,
        repo_root: Any,
        state_root: Optional[Any] = None,
        node_path: Optional[Any] = None,
    ) -> None:
        root = Path(os.fspath(repo_root)).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError("repo_root must be an existing directory")
        self.repo_root = root

        requested_state = (
            Path(os.fspath(state_root)).expanduser()
            if state_root is not None
            else root / ".phoenix_orchestrator_state"
        )
        if not requested_state.is_absolute():
            requested_state = root / requested_state
        requested_state.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved_state = requested_state.resolve(strict=True)
        if not resolved_state.is_dir():
            raise ValueError("state_root must resolve to a directory")
        if resolved_state == root:
            raise ValueError("state_root cannot be the managed repository root")
        self.state_root = resolved_state

        self._node_path = self._resolve_node_path(node_path)
        self._audit_path = self.state_root / "audit.jsonl"
        if self._audit_path.exists() and self._audit_path.is_symlink():
            raise ValueError("audit path cannot be a symbolic link")

        self._lock = threading.RLock()
        self._audit_lock = threading.Lock()
        self._runs: Dict[str, Dict[str, Any]] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._cancel_events: Dict[str, threading.Event] = {}
        self._idempotency: Dict[str, Dict[str, Any]] = {}
        self._active_run_id: Optional[str] = None
        self._rollback_in_progress: Optional[str] = None

        self._audit(
            "manager_initialized",
            repo_root=str(self.repo_root),
            state_root=str(self.state_root),
            node_available=bool(self._node_path),
        )

    # ------------------------------------------------------------------
    # Public JSON-returning interface
    # ------------------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        with self._lock:
            active = self._active_run_id
            if active and self._runs.get(active, {}).get("status") not in ACTIVE_STATES:
                self._active_run_id = None
                active = None
            return {
                "ok": True,
                "repo_root": str(self.repo_root),
                "state_root": str(self.state_root),
                "active_run_id": active,
                "rollback_in_progress": self._rollback_in_progress,
                "run_count": len(self._runs),
                "node_check_available": bool(self._node_path),
                "capabilities": {
                    "python_compile": True,
                    "javascript_node_check": bool(self._node_path),
                    "known_good_snapshots": True,
                    "restore_existing_files_only": True,
                    "network": False,
                    "elevation": False,
                    "system_updates": False,
                    "deletion": False,
                    "shell_strings": False,
                },
            }

    def plan(self, asset_path: Optional[Any] = None) -> Dict[str, Any]:
        try:
            asset = self._resolve_asset(asset_path)
            preflight = self._preflight(asset)
            inventory = self._inventory(asset)
            assessment = self._assess(asset, inventory)
            baseline = self._load_latest_baseline(asset)
            action = self._choose_action(inventory, assessment, baseline)
            result = {
                "ok": True,
                "asset_path": str(asset),
                "repo_root": str(self.repo_root),
                "preflight": preflight,
                "inventory": self._public_inventory(inventory),
                "assessment": assessment,
                "baseline": self._public_baseline(baseline),
                "planned_action": action,
                "pipeline": list(PIPELINE_PHASES),
                "apply_supported": action["type"] != "report_only",
            }
            self._audit(
                "plan_created",
                asset_path=str(asset),
                planned_action=action["type"],
                healthy=assessment["healthy"],
                source_files=inventory["source_file_count"],
            )
            return result
        except (OSError, ValueError) as exc:
            return _json_error("invalid_asset", str(exc))
        except Exception as exc:  # keep the public boundary JSON-only
            return _json_error("plan_failed", f"{type(exc).__name__}: {exc}")

    def start(
        self,
        asset_path: Optional[Any] = None,
        idempotency_key: str = "",
        apply: bool = True,
    ) -> Dict[str, Any]:
        try:
            asset = self._resolve_asset(asset_path)
        except (OSError, ValueError) as exc:
            return _json_error("invalid_asset", str(exc))

        key = str(idempotency_key or "").strip()
        if len(key) > 256:
            return _json_error("invalid_idempotency_key", "idempotency_key exceeds 256 characters")

        with self._lock:
            if key and key in self._idempotency:
                record = self._idempotency[key]
                if record["asset_path"] != str(asset) or record["apply"] != bool(apply):
                    return _json_error(
                        "idempotency_conflict",
                        "idempotency_key was already used with different parameters",
                        run_id=record["run_id"],
                    )
                replay = self._serialize_run_locked(record["run_id"])
                replay["idempotent_replay"] = True
                return replay

            if self._rollback_in_progress:
                return _json_error(
                    "rollback_in_progress",
                    "a rollback is currently in progress",
                    run_id=self._rollback_in_progress,
                )

            if self._active_run_id:
                active = self._runs.get(self._active_run_id)
                if active and active.get("status") in ACTIVE_STATES:
                    return _json_error(
                        "run_active",
                        "only one remediation run may be active",
                        run_id=self._active_run_id,
                    )
                self._active_run_id = None

            run_id = uuid.uuid4().hex
            created = _utc_now()
            run: Dict[str, Any] = {
                "run_id": run_id,
                "status": "queued",
                "phase": "queued",
                "asset_path": str(asset),
                "apply": bool(apply),
                "idempotency_key": key,
                "created_at": created,
                "started_at": None,
                "finished_at": None,
                "cancel_requested": False,
                "phases": [
                    {
                        "name": name,
                        "status": "pending",
                        "started_at": None,
                        "finished_at": None,
                        "summary": "",
                    }
                    for name in PIPELINE_PHASES
                ],
                "plan": None,
                "snapshot": None,
                "apply_result": None,
                "verification": None,
                "report": None,
                "error": None,
            }
            cancel_event = threading.Event()
            thread = threading.Thread(
                target=self._run_pipeline,
                args=(run_id, asset, bool(apply), cancel_event),
                name=f"phoenix-remediation-{run_id[:8]}",
                daemon=True,
            )
            self._runs[run_id] = run
            self._threads[run_id] = thread
            self._cancel_events[run_id] = cancel_event
            self._active_run_id = run_id
            if key:
                self._idempotency[key] = {
                    "run_id": run_id,
                    "asset_path": str(asset),
                    "apply": bool(apply),
                }
            self._audit(
                "run_created",
                run_id=run_id,
                asset_path=str(asset),
                apply=bool(apply),
                idempotency_key=key,
            )
            thread.start()
            return self._serialize_run_locked(run_id)

    def get(self, run_id: str) -> Dict[str, Any]:
        identifier = str(run_id or "").strip()
        with self._lock:
            if identifier not in self._runs:
                return _json_error("run_not_found", "unknown remediation run", run_id=identifier)
            return self._serialize_run_locked(identifier)

    def wait(self, run_id: str, timeout: float = 30) -> Dict[str, Any]:
        identifier = str(run_id or "").strip()
        try:
            bounded_timeout = max(0.0, min(float(timeout), 3600.0))
        except (TypeError, ValueError):
            return _json_error("invalid_timeout", "timeout must be numeric", run_id=identifier)
        with self._lock:
            thread = self._threads.get(identifier)
            if identifier not in self._runs:
                return _json_error("run_not_found", "unknown remediation run", run_id=identifier)
        if thread:
            thread.join(bounded_timeout)
        result = self.get(identifier)
        if thread and thread.is_alive():
            result["wait_timed_out"] = True
        else:
            result["wait_timed_out"] = False
        return result

    def cancel(self, run_id: str) -> Dict[str, Any]:
        identifier = str(run_id or "").strip()
        with self._lock:
            run = self._runs.get(identifier)
            if run is None:
                return _json_error("run_not_found", "unknown remediation run", run_id=identifier)
            if run["status"] in TERMINAL_STATES:
                result = self._serialize_run_locked(identifier)
                result["cancel_effective"] = False
                return result
            event = self._cancel_events[identifier]
            event.set()
            run["cancel_requested"] = True
            run["status"] = "cancelling"
            self._audit("cancel_requested", run_id=identifier, phase=run.get("phase"))
            result = self._serialize_run_locked(identifier)
            result["cancel_effective"] = True
            return result

    def rollback(self, run_id: str) -> Dict[str, Any]:
        identifier = str(run_id or "").strip()
        with self._lock:
            run = self._runs.get(identifier)
            if run is None:
                return _json_error("run_not_found", "unknown remediation run", run_id=identifier)
            if self._active_run_id and self._runs.get(self._active_run_id, {}).get("status") in ACTIVE_STATES:
                return _json_error(
                    "run_active",
                    "rollback is unavailable while a remediation run is active",
                    run_id=self._active_run_id,
                )
            if self._rollback_in_progress:
                return _json_error(
                    "rollback_in_progress",
                    "another rollback is in progress",
                    run_id=self._rollback_in_progress,
                )
            snapshot = copy.deepcopy(run.get("snapshot"))
            apply_result = copy.deepcopy(run.get("apply_result")) or {}
            changed = list(apply_result.get("changed_files") or [])
            if not snapshot:
                return _json_error("rollback_unavailable", "run has no pre-heal snapshot", run_id=identifier)
            self._rollback_in_progress = identifier

        try:
            if not changed:
                rollback_result = {
                    "ok": True,
                    "run_id": identifier,
                    "restored_files": [],
                    "conflicts": [],
                    "message": "The run made no managed-source changes; rollback is a no-op.",
                }
            else:
                rollback_result = self._restore_pre_heal_snapshot(identifier, snapshot, changed)

            with self._lock:
                current = self._runs[identifier]
                current["rollback"] = copy.deepcopy(rollback_result)
                if rollback_result["ok"]:
                    current["status"] = "rolled_back"
                    current["finished_at"] = _utc_now()
                self._audit(
                    "rollback_completed" if rollback_result["ok"] else "rollback_conflict",
                    run_id=identifier,
                    restored_files=len(rollback_result.get("restored_files", [])),
                    conflicts=len(rollback_result.get("conflicts", [])),
                )
            return copy.deepcopy(rollback_result)
        except Exception as exc:
            self._audit("rollback_failed", run_id=identifier, error=f"{type(exc).__name__}: {exc}")
            return _json_error("rollback_failed", f"{type(exc).__name__}: {exc}", run_id=identifier)
        finally:
            with self._lock:
                self._rollback_in_progress = None

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------
    def _run_pipeline(
        self,
        run_id: str,
        asset: Path,
        apply_requested: bool,
        cancel_event: threading.Event,
    ) -> None:
        current_phase = "preflight"
        context: Dict[str, Any] = {}
        try:
            with self._lock:
                run = self._runs[run_id]
                run["status"] = "running"
                run["started_at"] = _utc_now()
            self._audit("run_started", run_id=run_id, asset_path=str(asset), apply=apply_requested)

            for phase in PIPELINE_PHASES:
                current_phase = phase
                self._raise_if_cancelled(cancel_event)
                self._begin_phase(run_id, phase)

                if phase == "preflight":
                    context["preflight"] = self._preflight(asset)
                    summary = "managed root and local capabilities validated"
                elif phase == "inventory":
                    context["inventory"] = self._inventory(asset)
                    summary = f"{context['inventory']['source_file_count']} managed source files"
                elif phase == "assess":
                    context["assessment"] = self._assess(asset, context["inventory"])
                    context["baseline"] = self._load_latest_baseline(asset)
                    summary = "checks passed" if context["assessment"]["healthy"] else "checks found source errors"
                elif phase == "plan":
                    action = self._choose_action(
                        context["inventory"], context["assessment"], context["baseline"]
                    )
                    context["action"] = action
                    plan_payload = {
                        "asset_path": str(asset),
                        "preflight": context["preflight"],
                        "inventory": self._public_inventory(context["inventory"]),
                        "assessment": context["assessment"],
                        "baseline": self._public_baseline(context["baseline"]),
                        "planned_action": action,
                    }
                    with self._lock:
                        self._runs[run_id]["plan"] = copy.deepcopy(plan_payload)
                    summary = action["type"]
                elif phase == "snapshot":
                    if apply_requested and context["inventory"]["source_file_count"]:
                        context["snapshot"] = self._create_pre_heal_snapshot(
                            run_id, asset, context["inventory"]
                        )
                        with self._lock:
                            self._runs[run_id]["snapshot"] = copy.deepcopy(context["snapshot"])
                        summary = f"snapshotted {context['snapshot']['file_count']} files"
                    else:
                        context["snapshot"] = None
                        summary = "skipped: dry-run or no managed source files"
                elif phase == "apply":
                    context["apply_result"] = self._apply_action(
                        asset,
                        context["action"],
                        context["baseline"],
                        context["inventory"],
                        apply_requested,
                    )
                    with self._lock:
                        self._runs[run_id]["apply_result"] = copy.deepcopy(context["apply_result"])
                    summary = context["apply_result"]["summary"]
                elif phase == "verify":
                    final_inventory = self._inventory(asset)
                    final_assessment = self._assess(asset, final_inventory)
                    context["final_inventory"] = final_inventory
                    context["verification"] = final_assessment
                    with self._lock:
                        self._runs[run_id]["verification"] = copy.deepcopy(final_assessment)
                    summary = "verification passed" if final_assessment["healthy"] else "verification failed"
                else:  # report
                    context["report"] = self._build_report(
                        asset,
                        apply_requested,
                        context["action"],
                        context["assessment"],
                        context["verification"],
                        context["final_inventory"],
                        context["apply_result"],
                    )
                    with self._lock:
                        self._runs[run_id]["report"] = copy.deepcopy(context["report"])
                    summary = context["report"]["summary"]

                self._finish_phase(run_id, phase, "succeeded", summary)

            healthy = bool(context["verification"]["healthy"])
            with self._lock:
                run = self._runs[run_id]
                run["status"] = "succeeded" if healthy else "failed"
                run["phase"] = "complete"
                run["finished_at"] = _utc_now()
                if not healthy:
                    run["error"] = {
                        "code": "verification_failed",
                        "message": "managed source verification did not pass",
                    }
            self._audit(
                "run_finished",
                run_id=run_id,
                status="succeeded" if healthy else "failed",
                healthy=healthy,
                action=context["action"]["type"],
            )
        except _Cancelled:
            self._finish_phase(run_id, current_phase, "cancelled", "cancelled by request")
            with self._lock:
                run = self._runs[run_id]
                run["status"] = "cancelled"
                run["phase"] = current_phase
                run["finished_at"] = _utc_now()
                run["error"] = {"code": "cancelled", "message": "run cancelled by request"}
            self._audit("run_cancelled", run_id=run_id, phase=current_phase)
        except Exception as exc:
            message = _bounded(f"{type(exc).__name__}: {exc}")
            self._finish_phase(run_id, current_phase, "failed", message)
            with self._lock:
                run = self._runs[run_id]
                run["status"] = "failed"
                run["phase"] = current_phase
                run["finished_at"] = _utc_now()
                run["error"] = {"code": "pipeline_failed", "message": message}
            self._audit("run_failed", run_id=run_id, phase=current_phase, error=message)
        finally:
            with self._lock:
                if self._active_run_id == run_id:
                    self._active_run_id = None

    def _begin_phase(self, run_id: str, phase: str) -> None:
        with self._lock:
            run = self._runs[run_id]
            run["phase"] = phase
            item = self._phase_item(run, phase)
            item["status"] = "running"
            item["started_at"] = _utc_now()
        self._audit("phase_started", run_id=run_id, phase=phase)

    def _finish_phase(self, run_id: str, phase: str, status: str, summary: str) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            if not run:
                return
            item = self._phase_item(run, phase)
            item["status"] = status
            item["finished_at"] = _utc_now()
            item["summary"] = _bounded(summary, 1000)
        self._audit("phase_finished", run_id=run_id, phase=phase, status=status, summary=summary)

    @staticmethod
    def _phase_item(run: Dict[str, Any], phase: str) -> Dict[str, Any]:
        for item in run["phases"]:
            if item["name"] == phase:
                return item
        raise ValueError(f"unknown phase: {phase}")

    @staticmethod
    def _raise_if_cancelled(cancel_event: threading.Event) -> None:
        if cancel_event.is_set():
            raise _Cancelled()

    # ------------------------------------------------------------------
    # Bounded checks and actions
    # ------------------------------------------------------------------
    def _preflight(self, asset: Path) -> Dict[str, Any]:
        if not _is_within(asset, self.repo_root):
            raise ValueError("asset escaped the exact managed repository root")
        if not asset.exists():
            raise ValueError("asset no longer exists")
        return {
            "repo_root": str(self.repo_root),
            "asset_path": str(asset),
            "asset_type": "directory" if asset.is_dir() else "file",
            "writable": os.access(str(asset if asset.is_dir() else asset.parent), os.W_OK),
            "platform": self._platform_inventory(),
            "policy": {
                "network": False,
                "elevation": False,
                "system_updates": False,
                "deletion": False,
                "shell_strings": False,
                "allowed_mutation": "restore existing managed source files from a verified baseline",
            },
        }

    def _platform_inventory(self) -> Dict[str, Any]:
        package_tools = []
        for name in ("apt", "dnf", "yum", "zypper", "pacman", "brew", "winget"):
            if shutil.which(name):
                package_tools.append(name)
        return {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "package_tools_detected": package_tools,
            "advisory_only": True,
            "advisory": (
                "Operating-system and package-manager information is inventory only. "
                "Phoenix Orchestrator does not install updates, elevate privileges, reboot, "
                "or change system configuration."
            ),
        }

    def _inventory(self, asset: Path) -> Dict[str, Any]:
        records: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        total_bytes = 0
        complete = True

        for path in self._iter_source_candidates(asset):
            if len(records) >= MAX_SOURCE_FILES:
                complete = False
                skipped.append({"path": self._relative_repo(path), "reason": "source file limit reached"})
                break
            try:
                resolved = self._validate_managed_file(path, asset)
                size = resolved.stat().st_size
                if size > MAX_SOURCE_FILE_BYTES:
                    complete = False
                    skipped.append({"path": self._relative_repo(resolved), "reason": "file size limit exceeded"})
                    continue
                if total_bytes + size > MAX_SOURCE_TOTAL_BYTES:
                    complete = False
                    skipped.append({"path": self._relative_repo(resolved), "reason": "total source size limit exceeded"})
                    break
                records.append(
                    {
                        "path": self._relative_repo(resolved),
                        "asset_path": self._relative_asset(resolved, asset),
                        "suffix": resolved.suffix.lower(),
                        "size": size,
                        "sha256": _sha256_file(resolved),
                    }
                )
                total_bytes += size
            except (OSError, ValueError) as exc:
                complete = False
                skipped.append({"path": self._relative_repo(path), "reason": _bounded(exc, 500)})

        records.sort(key=lambda item: item["path"])
        return {
            "asset_path": str(asset),
            "source_file_count": len(records),
            "total_bytes": total_bytes,
            "complete": complete,
            "files": records,
            "skipped": skipped[:100],
        }

    def _iter_source_candidates(self, asset: Path) -> Iterable[Path]:
        if asset.is_file():
            if asset.suffix.lower() in SOURCE_SUFFIXES:
                yield asset
            return

        for root_text, directory_names, file_names in os.walk(str(asset), topdown=True, followlinks=False):
            root = Path(root_text)
            kept_directories = []
            for name in directory_names:
                candidate = root / name
                if name in EXCLUDED_DIRECTORY_NAMES or candidate.is_symlink():
                    continue
                try:
                    resolved = candidate.resolve(strict=True)
                except OSError:
                    continue
                if self._path_is_state(resolved):
                    continue
                if _is_within(resolved, self.repo_root):
                    kept_directories.append(name)
            directory_names[:] = kept_directories
            for name in sorted(file_names):
                candidate = root / name
                if candidate.suffix.lower() in SOURCE_SUFFIXES and not candidate.is_symlink():
                    yield candidate

    def _assess(self, asset: Path, inventory: Dict[str, Any]) -> Dict[str, Any]:
        checks: List[Dict[str, Any]] = []
        failures = 0
        skipped = 0

        if not inventory["complete"]:
            failures += 1
            checks.append(
                {
                    "type": "inventory",
                    "path": "",
                    "status": "failed",
                    "output": "inventory limits or path validation prevented a complete assessment",
                }
            )

        for record in inventory["files"]:
            path = self._repo_path_from_record(record, asset)
            current_hash = _sha256_file(path)
            if current_hash != record["sha256"]:
                failures += 1
                checks.append(
                    {
                        "type": "integrity",
                        "path": record["path"],
                        "status": "failed",
                        "output": "file changed during inventory or assessment",
                    }
                )
                continue

            if record["suffix"] == ".py":
                check = self._check_python(path, record["path"])
            else:
                check = self._check_javascript(path, record["path"], asset)
            checks.append(check)
            if check["status"] == "failed":
                failures += 1
            elif check["status"] == "skipped":
                skipped += 1

        return {
            "healthy": failures == 0,
            "checks_total": len(checks),
            "checks_failed": failures,
            "checks_skipped": skipped,
            "checks": checks[:MAX_SOURCE_FILES + 1],
        }

    @staticmethod
    def _check_python(path: Path, display_path: str) -> Dict[str, Any]:
        try:
            with tokenize.open(str(path)) as handle:
                source = handle.read()
            compile(source, str(path), "exec")
            return {"type": "python_compile", "path": display_path, "status": "passed", "output": ""}
        except Exception as exc:
            return {
                "type": "python_compile",
                "path": display_path,
                "status": "failed",
                "output": _bounded(f"{type(exc).__name__}: {exc}"),
            }

    def _check_javascript(self, path: Path, display_path: str, asset: Path) -> Dict[str, Any]:
        if not self._node_path:
            return {
                "type": "javascript_node_check",
                "path": display_path,
                "status": "skipped",
                "output": "node executable is unavailable; JavaScript syntax was not executed",
            }
        safe_env: Dict[str, str] = {}
        for key in ("PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "LANG", "LC_ALL"):
            if key in os.environ:
                safe_env[key] = os.environ[key]
        cwd = asset if asset.is_dir() else asset.parent
        try:
            completed = subprocess.run(
                [self._node_path, "--check", str(path)],
                cwd=str(cwd),
                env=safe_env,
                capture_output=True,
                text=True,
                timeout=NODE_CHECK_TIMEOUT_SECONDS,
                check=False,
            )
            output = _bounded((completed.stdout or "") + (completed.stderr or ""))
            return {
                "type": "javascript_node_check",
                "path": display_path,
                "status": "passed" if completed.returncode == 0 else "failed",
                "exit_code": int(completed.returncode),
                "output": output,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "type": "javascript_node_check",
                "path": display_path,
                "status": "failed",
                "output": _bounded(f"node --check timed out: {exc}"),
            }
        except Exception as exc:
            return {
                "type": "javascript_node_check",
                "path": display_path,
                "status": "failed",
                "output": _bounded(f"{type(exc).__name__}: {exc}"),
            }

    @staticmethod
    def _choose_action(
        inventory: Dict[str, Any],
        assessment: Dict[str, Any],
        baseline: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if inventory["source_file_count"] == 0:
            return {
                "type": "report_only",
                "reason": "no managed Python or JavaScript source files were found",
                "mutates_managed_source": False,
            }
        if assessment["healthy"]:
            return {
                "type": "establish_or_update_known_good",
                "reason": "all bounded source checks passed",
                "mutates_managed_source": False,
            }
        if baseline:
            return {
                "type": "restore_last_known_good",
                "reason": "source checks failed and a previously verified baseline exists",
                "mutates_managed_source": True,
                "baseline_id": baseline["baseline_id"],
            }
        return {
            "type": "report_only",
            "reason": "source checks failed and no verified baseline exists",
            "mutates_managed_source": False,
        }

    def _apply_action(
        self,
        asset: Path,
        action: Dict[str, Any],
        baseline: Optional[Dict[str, Any]],
        inventory: Dict[str, Any],
        apply_requested: bool,
    ) -> Dict[str, Any]:
        if not apply_requested:
            return {
                "applied": False,
                "action": action["type"],
                "changed_files": [],
                "summary": "dry-run: no managed source files changed",
            }
        if action["type"] != "restore_last_known_good":
            return {
                "applied": False,
                "action": action["type"],
                "changed_files": [],
                "summary": "no managed source mutation was required",
            }
        if not baseline:
            raise ValueError("restore action has no verified baseline")
        result = self._restore_known_good(asset, baseline, inventory)
        result["action"] = action["type"]
        result["applied"] = bool(result["changed_files"])
        result["summary"] = f"restored {len(result['changed_files'])} existing files from known-good baseline"
        return result

    def _build_report(
        self,
        asset: Path,
        apply_requested: bool,
        action: Dict[str, Any],
        initial: Dict[str, Any],
        final: Dict[str, Any],
        final_inventory: Dict[str, Any],
        apply_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        baseline_result = None
        if apply_requested and final["healthy"] and final_inventory["source_file_count"]:
            baseline_result = self._save_known_good_baseline(asset, final_inventory)
        healthy = bool(final["healthy"])
        return {
            "healthy": healthy,
            "initial_healthy": bool(initial["healthy"]),
            "action": action["type"],
            "apply_requested": apply_requested,
            "managed_source_changed": bool(apply_result.get("changed_files")),
            "known_good_baseline": self._public_baseline(baseline_result),
            "summary": (
                "managed source verification passed"
                if healthy
                else "managed source verification failed; no new known-good baseline was recorded"
            ),
            "os_advisory": self._platform_inventory()["advisory"],
        }

    # ------------------------------------------------------------------
    # Snapshots, baselines, and rollback
    # ------------------------------------------------------------------
    def _create_pre_heal_snapshot(
        self, run_id: str, asset: Path, inventory: Dict[str, Any]
    ) -> Dict[str, Any]:
        snapshot_root = self.state_root / "runs" / run_id / "pre_heal"
        files_root = snapshot_root / "files"
        files_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        manifest_files = self._copy_inventory_files(asset, inventory, files_root)
        manifest = {
            "kind": "pre_heal",
            "run_id": run_id,
            "asset_relative": self._asset_key_text(asset),
            "created_at": _utc_now(),
            "files": manifest_files,
        }
        manifest_path = snapshot_root / "manifest.json"
        self._write_json_new(manifest_path, manifest)
        return {
            "kind": "pre_heal",
            "manifest_path": str(manifest_path),
            "file_count": len(manifest_files),
            "created_at": manifest["created_at"],
        }

    def _save_known_good_baseline(
        self, asset: Path, inventory: Dict[str, Any]
    ) -> Dict[str, Any]:
        digest = self._inventory_digest(inventory)
        latest = self._load_latest_baseline(asset)
        if latest and latest.get("digest") == digest:
            result = copy.deepcopy(latest)
            result["updated"] = False
            return result

        key = self._baseline_key(asset)
        baseline_id = uuid.uuid4().hex
        version_root = self.state_root / "baselines" / key / "versions" / baseline_id
        files_root = version_root / "files"
        files_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        manifest_files = self._copy_inventory_files(asset, inventory, files_root)
        manifest = {
            "kind": "known_good",
            "baseline_id": baseline_id,
            "asset_relative": self._asset_key_text(asset),
            "created_at": _utc_now(),
            "digest": digest,
            "files": manifest_files,
        }
        manifest_path = version_root / "manifest.json"
        self._write_json_new(manifest_path, manifest)
        index_path = self.state_root / "baselines" / key / "index.jsonl"
        index_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._append_jsonl(
            index_path,
            {
                "baseline_id": baseline_id,
                "asset_relative": manifest["asset_relative"],
                "created_at": manifest["created_at"],
                "digest": digest,
                "manifest_path": str(manifest_path),
                "file_count": len(manifest_files),
            },
        )
        result = {
            "baseline_id": baseline_id,
            "asset_relative": manifest["asset_relative"],
            "created_at": manifest["created_at"],
            "digest": digest,
            "manifest_path": str(manifest_path),
            "file_count": len(manifest_files),
            "updated": True,
            "manifest": manifest,
        }
        self._audit(
            "known_good_recorded",
            baseline_id=baseline_id,
            asset_path=str(asset),
            file_count=len(manifest_files),
            digest=digest,
        )
        return result

    def _load_latest_baseline(self, asset: Path) -> Optional[Dict[str, Any]]:
        key = self._baseline_key(asset)
        index_path = self.state_root / "baselines" / key / "index.jsonl"
        if not index_path.exists():
            return None
        if index_path.is_symlink():
            raise ValueError("baseline index cannot be a symbolic link")
        latest: Optional[Dict[str, Any]] = None
        with index_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                if len(raw_line) > MAX_AUDIT_LINE_CHARS:
                    continue
                try:
                    candidate = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                if candidate.get("asset_relative") == self._asset_key_text(asset):
                    latest = candidate
        if not latest:
            return None

        manifest_path = Path(str(latest.get("manifest_path", ""))).resolve(strict=True)
        if not _is_within(manifest_path, self.state_root) or manifest_path.is_symlink():
            raise ValueError("baseline manifest escaped state_root")
        if manifest_path.stat().st_size > MAX_SOURCE_TOTAL_BYTES:
            raise ValueError("baseline manifest is too large")
        with manifest_path.open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        if manifest.get("baseline_id") != latest.get("baseline_id"):
            raise ValueError("baseline manifest identity mismatch")
        if manifest.get("asset_relative") != self._asset_key_text(asset):
            raise ValueError("baseline asset identity mismatch")
        result = dict(latest)
        result["manifest"] = manifest
        return result

    def _restore_known_good(
        self,
        asset: Path,
        baseline: Dict[str, Any],
        current_inventory: Dict[str, Any],
    ) -> Dict[str, Any]:
        manifest = baseline["manifest"]
        baseline_root = Path(baseline["manifest_path"]).parent / "files"
        current = {item["asset_path"]: item for item in current_inventory["files"]}
        changed: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []

        for entry in manifest.get("files", []):
            relative = str(entry.get("asset_path", ""))
            current_record = current.get(relative)
            if not current_record:
                skipped.append({"path": relative, "reason": "file is not currently present; creation is prohibited"})
                continue
            target = self._repo_path_from_record(current_record, asset)
            source = (baseline_root / relative).resolve(strict=True)
            if not _is_within(source, baseline_root.resolve(strict=True)) or source.is_symlink():
                raise ValueError("baseline source path escaped its snapshot")
            expected = str(entry.get("sha256", ""))
            if _sha256_file(source) != expected:
                raise ValueError(f"known-good snapshot integrity failed for {relative}")
            before = _sha256_file(target)
            if before == expected:
                continue
            shutil.copy2(str(source), str(target), follow_symlinks=False)
            after = _sha256_file(target)
            if after != expected:
                raise OSError(f"restore verification failed for {relative}")
            changed.append(
                {
                    "path": current_record["path"],
                    "asset_path": relative,
                    "before_sha256": before,
                    "after_sha256": after,
                }
            )
        return {"changed_files": changed, "skipped_files": skipped[:100]}

    def _restore_pre_heal_snapshot(
        self,
        run_id: str,
        snapshot: Dict[str, Any],
        changed: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        manifest_path = Path(snapshot["manifest_path"]).resolve(strict=True)
        if not _is_within(manifest_path, self.state_root) or manifest_path.is_symlink():
            raise ValueError("pre-heal manifest escaped state_root")
        with manifest_path.open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        if manifest.get("run_id") != run_id:
            raise ValueError("pre-heal snapshot identity mismatch")
        files_root = manifest_path.parent / "files"
        snapshot_entries = {item["asset_path"]: item for item in manifest.get("files", [])}
        restored: List[str] = []
        conflicts: List[Dict[str, Any]] = []

        for item in changed:
            relative = item["asset_path"]
            entry = snapshot_entries.get(relative)
            if not entry:
                conflicts.append({"path": relative, "reason": "pre-heal snapshot entry missing"})
                continue
            target = (self.repo_root / item["path"]).resolve(strict=True)
            if not _is_within(target, self.repo_root) or target.is_symlink():
                conflicts.append({"path": relative, "reason": "managed target is no longer safe"})
                continue
            current_hash = _sha256_file(target)
            if current_hash != item["after_sha256"]:
                conflicts.append({"path": relative, "reason": "file changed after remediation; preserved"})
                continue
            source = (files_root / relative).resolve(strict=True)
            if not _is_within(source, files_root.resolve(strict=True)) or source.is_symlink():
                conflicts.append({"path": relative, "reason": "snapshot path is unsafe"})
                continue
            expected = entry["sha256"]
            if _sha256_file(source) != expected:
                conflicts.append({"path": relative, "reason": "snapshot integrity mismatch"})
                continue
            shutil.copy2(str(source), str(target), follow_symlinks=False)
            if _sha256_file(target) != expected:
                conflicts.append({"path": relative, "reason": "rollback verification failed"})
                continue
            restored.append(relative)

        return {
            "ok": not conflicts,
            "run_id": run_id,
            "restored_files": restored,
            "conflicts": conflicts,
            "message": (
                f"restored {len(restored)} files from the pre-heal snapshot"
                if not conflicts
                else f"rollback preserved {len(conflicts)} conflicting files"
            ),
        }

    def _copy_inventory_files(
        self, asset: Path, inventory: Dict[str, Any], destination_root: Path
    ) -> List[Dict[str, Any]]:
        copied: List[Dict[str, Any]] = []
        for record in inventory["files"]:
            source = self._repo_path_from_record(record, asset)
            if _sha256_file(source) != record["sha256"]:
                raise ValueError(f"source changed before snapshot: {record['path']}")
            destination = destination_root / record["asset_path"]
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if destination.exists():
                raise FileExistsError(f"snapshot destination already exists: {destination}")
            shutil.copy2(str(source), str(destination), follow_symlinks=False)
            copied_hash = _sha256_file(destination)
            if copied_hash != record["sha256"]:
                raise OSError(f"snapshot integrity failed for {record['path']}")
            copied.append(
                {
                    "path": record["path"],
                    "asset_path": record["asset_path"],
                    "size": record["size"],
                    "sha256": copied_hash,
                }
            )
        return copied

    # ------------------------------------------------------------------
    # Exact path handling and persistence helpers
    # ------------------------------------------------------------------
    def _resolve_asset(self, asset_path: Optional[Any]) -> Path:
        if asset_path is None or str(asset_path).strip() == "":
            candidate = self.repo_root
        else:
            raw = Path(os.fspath(asset_path)).expanduser()
            candidate = raw if raw.is_absolute() else self.repo_root / raw
        lexical = Path(os.path.abspath(os.fspath(candidate)))
        if not _is_within(lexical, self.repo_root):
            raise ValueError("asset path must be lexically inside the exact managed repository root")
        self._reject_symlink_components(lexical, self.repo_root, "managed asset")
        resolved = lexical.resolve(strict=True)
        if not _is_within(resolved, self.repo_root):
            raise ValueError("asset must resolve inside the exact managed repository root")
        if not (resolved.is_dir() or resolved.is_file()):
            raise ValueError("asset must be a regular file or directory")
        if self._path_is_state(resolved):
            raise ValueError("orchestrator state cannot be selected as a managed asset")
        if resolved.is_symlink():
            raise ValueError("managed asset cannot be a symbolic link")
        return resolved

    def _validate_managed_file(self, path: Path, asset: Path) -> Path:
        lexical = Path(os.path.abspath(os.fspath(path)))
        if not _is_within(lexical, self.repo_root):
            raise ValueError("managed source escaped repo_root")
        self._reject_symlink_components(lexical, self.repo_root, "managed source")
        resolved = lexical.resolve(strict=True)
        if not resolved.is_file() or resolved.is_symlink():
            raise ValueError("managed source must be a regular non-symlink file")
        if not _is_within(resolved, self.repo_root):
            raise ValueError("managed source escaped repo_root")
        if asset.is_dir() and not _is_within(resolved, asset):
            raise ValueError("managed source escaped the selected asset")
        if asset.is_file() and resolved != asset:
            raise ValueError("managed source does not match the selected file")
        if self._path_is_state(resolved):
            raise ValueError("state files cannot be managed source")
        return resolved

    @staticmethod
    def _reject_symlink_components(path: Path, root: Path, label: str) -> None:
        try:
            relative_parts = path.relative_to(root).parts
        except ValueError as exc:
            raise ValueError(f"{label} escaped its allowed root") from exc
        cursor = root
        for part in relative_parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError(f"{label} cannot traverse symbolic links")

    def _repo_path_from_record(self, record: Dict[str, Any], asset: Path) -> Path:
        candidate = self.repo_root / str(record["path"])
        return self._validate_managed_file(candidate, asset)

    def _path_is_state(self, path: Path) -> bool:
        return _is_within(path, self.state_root)

    def _relative_repo(self, path: Path) -> str:
        try:
            return path.resolve(strict=False).relative_to(self.repo_root).as_posix()
        except ValueError:
            return _bounded(str(path), 1000)

    @staticmethod
    def _relative_asset(path: Path, asset: Path) -> str:
        base = asset if asset.is_dir() else asset.parent
        return path.relative_to(base).as_posix()

    def _asset_key_text(self, asset: Path) -> str:
        if asset == self.repo_root:
            return "."
        return asset.relative_to(self.repo_root).as_posix()

    def _baseline_key(self, asset: Path) -> str:
        text = self._asset_key_text(asset).encode("utf-8")
        return hashlib.sha256(text).hexdigest()[:24]

    @staticmethod
    def _inventory_digest(inventory: Dict[str, Any]) -> str:
        digest = hashlib.sha256()
        for record in inventory["files"]:
            digest.update(record["asset_path"].encode("utf-8"))
            digest.update(b"\0")
            digest.update(record["sha256"].encode("ascii"))
            digest.update(b"\n")
        return digest.hexdigest()

    @staticmethod
    def _public_inventory(inventory: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "asset_path": inventory["asset_path"],
            "source_file_count": inventory["source_file_count"],
            "total_bytes": inventory["total_bytes"],
            "complete": inventory["complete"],
            "files": copy.deepcopy(inventory["files"]),
            "skipped": copy.deepcopy(inventory["skipped"]),
        }

    @staticmethod
    def _public_baseline(baseline: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not baseline:
            return None
        return {
            key: copy.deepcopy(value)
            for key, value in baseline.items()
            if key != "manifest"
        }

    def _resolve_node_path(self, node_path: Optional[Any]) -> Optional[str]:
        if node_path is None or str(node_path).strip() == "":
            discovered = shutil.which("node")
        else:
            supplied = os.fspath(node_path)
            discovered = supplied if os.path.isabs(supplied) else shutil.which(supplied)
        if not discovered:
            return None
        try:
            resolved = Path(discovered).expanduser().resolve(strict=True)
        except OSError:
            return None
        if not resolved.is_file() or not os.access(str(resolved), os.X_OK):
            return None
        return str(resolved)

    @staticmethod
    def _write_json_new(path: Path, payload: Dict[str, Any]) -> None:
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"refusing to overwrite state file: {path}")
        encoded = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
        with path.open("x", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _append_jsonl(self, path: Path, payload: Dict[str, Any]) -> None:
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        if len(encoded) > MAX_AUDIT_LINE_CHARS:
            encoded = json.dumps(
                {"event": "oversized_event", "summary": _bounded(encoded, MAX_AUDIT_LINE_CHARS - 200)},
                sort_keys=True,
                separators=(",", ":"),
            )
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with self._audit_lock:
            descriptor = os.open(str(path), flags, 0o600)
            try:
                os.write(descriptor, (encoded + "\n").encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def _audit(self, event: str, run_id: str = "", **fields: Any) -> None:
        payload: Dict[str, Any] = {
            "timestamp": _utc_now(),
            "event": str(event),
            "run_id": str(run_id or ""),
        }
        for key, value in fields.items():
            if isinstance(value, (str, int, float, bool)) or value is None:
                payload[str(key)] = _bounded(value) if isinstance(value, str) else value
            else:
                payload[str(key)] = _bounded(json.dumps(value, sort_keys=True, default=str))
        self._append_jsonl(self._audit_path, payload)

    def _serialize_run_locked(self, run_id: str) -> Dict[str, Any]:
        return {"ok": True, **copy.deepcopy(self._runs[run_id])}
