"""Server-side Phoenix subscription tiers and monthly opaque control keys.

Customer keys are returned only when issued. The persistent store keeps a
SHA-256 digest, tier, status, and expiry metadata, never the plaintext key.
Payment confirmation is deliberately outside this module; a trusted payment
webhook or owner-operated issuer must call ``issue`` after payment is verified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, Optional


SUBSCRIPTION_TERM_DAYS = 30
STORE_VERSION = 1
STORE_FILE = "phoenix_subscriptions.json"
LOCK_FILE = ".phoenix_subscriptions.lock"
KEY_PATTERN = re.compile(r"^phx_(demo|solo|base|enterprise|government)_[A-Za-z0-9_-]{32,128}$")
TIERS: Dict[str, dict] = {
    "demo": {
        "id": "demo",
        "name": "Demo",
        "price_monthly_usd": 0,
        "audience": "Explore Phoenix safely",
        "features": [
            "demo_dashboard",
            "security_basics",
            "local_ai",
            "guardrails",
            "sample_reports",
            "tier1_visibility",
            "platform_readiness",
        ],
        "highlights": [
            "Read-only security posture preview",
            "Security checklist and local guidance",
            "Sample reports with no live remediation",
        ],
        "defense_vectors": ["Security fundamentals", "Guardrail awareness", "Posture preview"],
    },
    "solo": {
        "id": "solo",
        "name": "Solo Researcher",
        "price_monthly_usd": 50,
        "audience": "Learners and independent cybersecurity enthusiasts",
        "features": [
            "demo_dashboard",
            "security_basics",
            "local_ai",
            "guardrails",
            "sample_reports",
            "tier1_visibility",
            "platform_readiness",
            "guided_learning_vectors",
            "researcher_workspace",
            "personal_asset_notebook",
        ],
        "highlights": [
            "Guided defensive learning vectors and lab readiness",
            "Private researcher workspace and asset notebook",
            "No live audits, Bug Bounty automation, or remediation",
        ],
        "defense_vectors": ["Local lab readiness", "Asset hygiene", "Threat modeling", "Evidence basics", "Learning roadmaps"],
    },
    "base": {
        "id": "base",
        "name": "Base Cybersecurity Personnel",
        "price_monthly_usd": 150,
        "audience": "Independent operators and small teams",
        "features": [
            "demo_dashboard",
            "security_basics",
            "local_ai",
            "guardrails",
            "sample_reports",
            "tier1_visibility",
            "platform_readiness",
            "guided_learning_vectors",
            "researcher_workspace",
            "personal_asset_notebook",
            "scope_manage",
            "web_audit",
            "reports",
            "bug_bounty",
            "security_intelligence",
        ],
        "highlights": [
            "Dedicated Bug Bounty workspace with real scoped audits",
            "Public vulnerability vectors, findings, and report drafts",
            "Professional scope controls and defensive guardrails",
        ],
        "defense_vectors": ["Web headers", "TLS posture", "DNS posture", "Public CVEs", "Scope validation", "Evidence capture", "Bug Bounty reporting", "Safe OSINT"],
    },
    "enterprise": {
        "id": "enterprise",
        "name": "Enterprise",
        "price_monthly_usd": 1000,
        "audience": "Businesses operating managed security workflows",
        "features": [
            "demo_dashboard",
            "security_basics",
            "local_ai",
            "guardrails",
            "sample_reports",
            "tier1_visibility",
            "platform_readiness",
            "guided_learning_vectors",
            "researcher_workspace",
            "personal_asset_notebook",
            "scope_manage",
            "web_audit",
            "reports",
            "bug_bounty",
            "autonomous_remediation",
            "enterprise_profile",
            "security_intelligence",
            "browser_context",
            "tool_inventory",
            "cross_platform_kali",
            "fraud_response",
            "private_remote_access",
            "security_program_autopilot",
        ],
        "highlights": [
            "Autonomous Tier-1 remediation, verification, and rollback",
            "Windows WSL2 and macOS containerized Kali bridge",
            "Fraud response and private anywhere-access readiness",
        ],
        "defense_vectors": ["Autonomous Tier-1", "Code healing", "Verified rollback", "Dependency posture", "Cross-platform Kali", "Tool inventory", "Private access", "Fraud response", "Web defense", "Threat intelligence", "Enterprise profiles", "Security-program automation"],
    },
    "government": {
        "id": "government",
        "name": "Government",
        "price_monthly_usd": 1500,
        "audience": "Public-sector and regulated environments",
        "features": [
            "demo_dashboard",
            "security_basics",
            "local_ai",
            "guardrails",
            "sample_reports",
            "tier1_visibility",
            "platform_readiness",
            "guided_learning_vectors",
            "researcher_workspace",
            "personal_asset_notebook",
            "scope_manage",
            "web_audit",
            "reports",
            "bug_bounty",
            "autonomous_remediation",
            "enterprise_profile",
            "security_intelligence",
            "browser_context",
            "tool_inventory",
            "cross_platform_kali",
            "fraud_response",
            "private_remote_access",
            "security_program_autopilot",
            "government_compliance",
            "evidence_integrity",
        ],
        "highlights": [
            "Everything in Enterprise",
            "Compliance-control mapping without false certification claims",
            "Tamper-evident evidence sealing and hardened local policy",
        ],
        "defense_vectors": ["Government control mapping", "Evidence integrity", "Hardened local policy", "Audit traceability", "Autonomous Tier-1", "Code healing", "Verified rollback", "Dependency posture", "Cross-platform Kali", "Tool inventory", "Private access", "Fraud response", "Threat intelligence", "Recovery assurance"],
    },
}


class SubscriptionError(RuntimeError):
    """Raised when subscription state cannot be safely handled."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise SubscriptionError("Subscription time must include a timezone")
    return value.astimezone(timezone.utc)


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise SubscriptionError("Subscription expiration is missing")
    try:
        return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError as exc:
        raise SubscriptionError("Subscription expiration is invalid") from exc


def catalog() -> dict:
    """Return the public, non-secret tier catalog."""
    return {
        "currency": "USD",
        "billing_period": "30 days",
        "tiers": [dict(TIERS[name]) for name in ("demo", "solo", "base", "enterprise", "government")],
        "payment_status": "A trusted payment webhook is required before automatic paid-key delivery.",
        "certification_notice": "Government tier features support control mapping and evidence integrity; no FedRAMP, FISMA, or agency authorization is claimed.",
    }


def owner_context(expires_at: Optional[str] = None) -> dict:
    features = sorted({feature for tier in TIERS.values() for feature in tier["features"]} | {"owner_admin"})
    return {
        "authenticated": True,
        "kind": "owner",
        "tier": "owner",
        "tier_name": "Phoenix Owner",
        "features": features,
        "expires_at": expires_at,
        "active": True,
    }


class SubscriptionStore:
    def __init__(self, config_dir, now=None) -> None:
        self.config_dir = Path(config_dir).expanduser()
        self.path = self.config_dir / STORE_FILE
        self.lock_path = self.config_dir / LOCK_FILE
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._thread_lock = threading.RLock()

    def issue(self, tier: str, customer_label: str = "") -> dict:
        tier = str(tier or "").strip().lower()
        if tier not in TIERS:
            raise SubscriptionError("Unknown Phoenix subscription tier")
        label = " ".join(str(customer_label or "").strip().split())
        if len(label) > 120:
            raise SubscriptionError("Customer label is too long")
        key = f"phx_{tier}_{secrets.token_urlsafe(32)}"
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        now = _utc(self._now())
        record = {
            "key_hash": digest,
            "key_id": digest[:12],
            "tier": tier,
            "customer_label": label,
            "created_at": now.isoformat(timespec="seconds"),
            "expires_at": (now + timedelta(days=SUBSCRIPTION_TERM_DAYS)).isoformat(timespec="seconds"),
            "status": "active",
        }
        with self._thread_lock, self._exclusive_lock():
            payload = self._read()
            payload["licenses"].append(record)
            self._write(payload)
        return {"control_key": key, "subscription": self._public_record(record)}

    def authenticate(self, candidate: object) -> Optional[dict]:
        if not isinstance(candidate, str) or not KEY_PATTERN.fullmatch(candidate):
            return None
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        with self._thread_lock, self._exclusive_lock():
            payload = self._read()
        for record in payload["licenses"]:
            if not hmac.compare_digest(str(record.get("key_hash", "")), digest):
                continue
            public = self._public_record(record)
            if not public["active"]:
                return None
            return {
                "authenticated": True,
                "kind": "subscription",
                "tier": public["tier"],
                "tier_name": public["tier_name"],
                "features": list(TIERS[public["tier"]]["features"]),
                "expires_at": public["expires_at"],
                "active": True,
            }
        return None

    def status_for_key(self, candidate: object) -> Optional[dict]:
        context = self.authenticate(candidate)
        if context is None:
            return None
        return {key: value for key, value in context.items() if key != "authenticated"}

    def list_records(self) -> list:
        with self._thread_lock, self._exclusive_lock():
            payload = self._read()
        return [self._public_record(record) for record in payload["licenses"]]

    def revoke(self, key_id: str) -> dict:
        identifier = str(key_id or "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{12}", identifier):
            raise SubscriptionError("Subscription key ID must be 12 hexadecimal characters")
        changed = False
        with self._thread_lock, self._exclusive_lock():
            payload = self._read()
            for record in payload["licenses"]:
                if hmac.compare_digest(str(record.get("key_id", "")), identifier):
                    record["status"] = "revoked"
                    changed = True
                    break
            if changed:
                self._write(payload)
        if not changed:
            raise SubscriptionError("Subscription key ID was not found")
        return {"revoked": True, "key_id": identifier}

    def _public_record(self, record: dict) -> dict:
        tier = str(record.get("tier", ""))
        if tier not in TIERS:
            raise SubscriptionError("Subscription record contains an unknown tier")
        expiry = _parse_time(record.get("expires_at"))
        active = record.get("status") == "active" and _utc(self._now()) < expiry
        return {
            "key_id": str(record.get("key_id", "")),
            "tier": tier,
            "tier_name": TIERS[tier]["name"],
            "customer_label": str(record.get("customer_label", "")),
            "created_at": str(record.get("created_at", "")),
            "expires_at": expiry.isoformat(timespec="seconds"),
            "status": "active" if active else ("revoked" if record.get("status") == "revoked" else "expired"),
            "active": active,
            "features": list(TIERS[tier]["features"]),
        }

    def _prepare(self) -> None:
        if self.config_dir.is_symlink():
            raise SubscriptionError("Subscription directory cannot be a symbolic link")
        self.config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.config_dir.chmod(0o700)
        except OSError:
            pass
        if self.path.exists() and self.path.is_symlink():
            raise SubscriptionError("Subscription store cannot be a symbolic link")

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        self._prepare()
        descriptor = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            if os.name == "nt":
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def _read(self) -> dict:
        self._prepare()
        if not self.path.exists():
            return {"version": STORE_VERSION, "licenses": []}
        try:
            if not stat.S_ISREG(self.path.stat().st_mode):
                raise SubscriptionError("Subscription store is not a regular file")
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except SubscriptionError:
            raise
        except (OSError, json.JSONDecodeError) as exc:
            raise SubscriptionError(f"Could not read subscription store: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("version") != STORE_VERSION:
            raise SubscriptionError("Subscription store has an invalid version")
        if not isinstance(payload.get("licenses"), list):
            raise SubscriptionError("Subscription store has an invalid license list")
        return payload

    def _write(self, payload: dict) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix="subscriptions-", suffix=".tmp", dir=str(self.config_dir))
        temporary_path = Path(temporary)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                json.dump(payload, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(str(temporary_path), str(self.path))
            self.path.chmod(0o600)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_path.exists():
                temporary_path.unlink()
