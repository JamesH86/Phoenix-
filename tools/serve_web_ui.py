"""Authenticated loopback web shell for Phoenix Guardian.

The server intentionally exposes only a bounded local API. Mutations require a
Phoenix first-party control key, exact loopback Host/Origin validation, and
JSON request bodies. Remediation is delegated to the registered, transactional
``RemediationManager`` rather than to a general shell runner.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import http.server
import importlib.util
import ipaddress
import json
import os
import shutil
import socket
import socketserver
import sys
import tempfile
import threading
import traceback
import webbrowser
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.error import HTTPError
from urllib.parse import parse_qs, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


PORT = int(os.environ.get("PHOENIX_PORT", "8787"))
MAX_JSON_BYTES = 1024 * 1024
MAX_BROWSER_BYTES = 90_000
MAX_REDIRECTS = 3
REPO_ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = REPO_ROOT / "web_ui"
ENGINE_PATH = REPO_ROOT / "phoenix_guardian.py"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phoenix_auth import ControlKeyStore, extract_bearer, request_origin_mode
from phoenix_enterprise import EnterpriseProfileError, EnterpriseProfileStore
from phoenix_orchestrator import RemediationManager
from phoenix_remote import RemoteAccessError, RemoteAccessStore
from phoenix_square import (
    CONFIG_FILE_ENV as SQUARE_CONFIG_FILE_ENV,
    PurchaseStore,
    SquareAPIError,
    SquareClient,
    SquareConfig,
    SquareConfigError,
    SquarePurchaseError,
    SquareWebhookError,
    offer_catalog as square_offer_catalog,
)
from phoenix_subscriptions import SubscriptionError, SubscriptionStore, catalog as subscription_catalog, owner_context
from phoenix_tier1 import Tier1SecurityManager
from tools.readiness import readiness as platform_readiness


def load_engine():
    spec = importlib.util.spec_from_file_location("phoenix_guardian_engine", ENGINE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load the Phoenix Guardian engine")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
    return root.resolve()


def find_node() -> Optional[str]:
    configured = str(os.environ.get("PHOENIX_NODE_PATH", "") or "").strip()
    if configured:
        return configured
    return shutil.which("node")


engine = load_engine()
CONFIG_ROOT = config_root()
CONTROL_KEYS = ControlKeyStore(CONFIG_ROOT)
CONTROL_KEYS.get_or_create_key()
ENTERPRISE_PROFILE = EnterpriseProfileStore(CONFIG_ROOT)
REMOTE_ACCESS = RemoteAccessStore(CONFIG_ROOT)
SUBSCRIPTIONS = SubscriptionStore(CONFIG_ROOT)


def load_square_billing():
    """Load owner-private Square state without making server startup depend on it."""

    configured_path = str(os.environ.get(SQUARE_CONFIG_FILE_ENV, "") or "").strip()
    environment = str(os.environ.get("PHOENIX_SQUARE_ENVIRONMENT", "sandbox") or "sandbox").strip().lower()
    default_path = CONFIG_ROOT / f"square_{environment}_credentials.json"
    path = Path(configured_path).expanduser() if configured_path else default_path
    try:
        if configured_path or path.exists():
            config = SquareConfig.load(path)
        else:
            config = SquareConfig.load()
        client = SquareClient(config)
        purchases = PurchaseStore(CONFIG_ROOT / f"square_{config.environment}_purchases.sqlite3", config.location_id)
        return config, client, purchases
    except (SquareConfigError, SquarePurchaseError, OSError):
        return None, None, None


SQUARE_CONFIG, SQUARE_CLIENT, SQUARE_PURCHASES = load_square_billing()
scope = engine.ScopeManager(str(CONFIG_ROOT / engine.DATA_FILE))
remediation = RemediationManager(
    REPO_ROOT,
    state_root=CONFIG_ROOT / "remediation",
    node_path=find_node(),
)
tier1 = Tier1SecurityManager(
    REPO_ROOT,
    state_root=CONFIG_ROOT / "tier1",
    remediation=remediation,
)

findings = []
findings_lock = threading.Lock()
latest_run_lock = threading.Lock()
latest_run_id = ""
government_evidence_lock = threading.Lock()

SQUARE_WEBHOOK_ROUTE = "/api/billing/square/webhook"
PUBLIC_GET_ROUTES = {
    "/api/health",
    "/api/subscriptions/catalog",
    "/api/billing/square/status",
}
PUBLIC_POST_ROUTES = {
    "/api/subscriptions/demo",
    "/api/billing/square/checkout",
    "/api/billing/square/purchase",
    "/api/billing/square/claim",
}
FEATURE_MINIMUM_TIER = {
    "owner_admin": "Phoenix Owner",
    "enterprise_profile": "Enterprise",
    "autonomous_remediation": "Enterprise",
    "security_intelligence": "Base",
    "browser_context": "Enterprise",
    "tool_inventory": "Enterprise",
    "fraud_response": "Enterprise",
    "security_program_autopilot": "Enterprise",
    "government_compliance": "Government",
    "evidence_integrity": "Government",
    "scope_manage": "Base",
    "web_audit": "Base",
    "reports": "Base",
    "bug_bounty": "Base",
    "guided_learning_vectors": "Solo",
}


def required_feature(method: str, path: str) -> str:
    method = method.upper()
    exact = {
        ("GET", "/api/control-key"): "owner_admin",
        ("POST", "/api/control-key/rotate"): "owner_admin",
        ("GET", "/api/enterprise/profile"): "enterprise_profile",
        ("POST", "/api/enterprise/profile"): "enterprise_profile",
        ("GET", "/api/kali-inventory"): "tool_inventory",
        ("GET", "/api/kali-bridge"): "tool_inventory",
        ("GET", "/api/burp-status"): "bug_bounty",
        ("GET", "/api/wordlists"): "tool_inventory",
        ("GET", "/api/checklist"): "bug_bounty",
        ("GET", "/api/hackerone-readiness"): "bug_bounty",
        ("GET", "/api/learning-vectors"): "guided_learning_vectors",
        ("GET", "/api/current-vectors"): "security_intelligence",
        ("POST", "/api/browser-context"): "browser_context",
        ("POST", "/api/kali-bridge/prepare"): "tool_inventory",
        ("POST", "/api/scope"): "scope_manage",
        ("POST", "/api/web-audit"): "web_audit",
        ("POST", "/api/bug-bounty-report"): "bug_bounty",
        ("POST", "/api/bug-bounty-autopilot"): "security_program_autopilot",
        ("POST", "/api/fraud-report"): "fraud_response",
        ("POST", "/api/defensive-drone"): "fraud_response",
        ("POST", "/api/clear-findings"): "reports",
        ("GET", "/api/government/compliance"): "government_compliance",
        ("POST", "/api/government/evidence-seal"): "evidence_integrity",
    }
    if (method, path) in exact:
        return exact[(method, path)]
    if path == "/api/tier1/run" or path.startswith("/api/remediation/"):
        return "autonomous_remediation"
    return ""


def government_compliance_payload() -> Dict[str, Any]:
    return {
        "ok": True,
        "profile": "Government control-assurance workspace",
        "controls": {
            "govern": "Tier ownership, locked guardrails, and auditable authorization",
            "identify": "Enrolled local asset and dependency metadata inventory",
            "protect": "Authenticated API, scope boundaries, and known-good snapshots",
            "detect": "Deterministic source and configuration posture checks",
            "respond": "Registered remediation with verification and rollback",
            "recover": "Pre-change snapshots and post-change evidence",
        },
        "hardened_policy": {
            "arbitrary_shell": False,
            "privilege_escalation": False,
            "public_exposure": False,
            "evidence_local_by_default": True,
        },
        "notice": "This is a technical control map, not FedRAMP, FISMA, agency authorization, or legal certification.",
    }


def seal_government_evidence() -> Dict[str, Any]:
    with findings_lock:
        snapshot = [finding_payload(item) for item in findings]
    evidence = {
        "coverage": tier1.coverage(),
        "findings": snapshot,
        "guardrails": {key: value["enabled"] for key, value in guardrail_payload().items()},
    }
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record = {
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "algorithm": "sha256",
        "digest": hashlib.sha256(canonical).hexdigest(),
        "source": "current-local-phoenix-state",
    }
    audit_path = CONFIG_ROOT / "government-evidence-seals.jsonl"
    if audit_path.exists() and audit_path.is_symlink():
        raise ApiError("Evidence seal log cannot be a symbolic link.", 500, "unsafe_evidence_log")
    with government_evidence_lock:
        descriptor = os.open(str(audit_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return {"ok": True, "seal": record, "certification": "No external certification is implied."}


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request") -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


def square_public_status() -> Dict[str, Any]:
    """Return browser-safe billing readiness without paths, IDs, or secrets."""

    if SQUARE_CONFIG is None:
        return {
            "configured": False,
            "environment": "unavailable",
            "currency": "USD",
            "checkout_ready": False,
            "webhook_ready": False,
            "automatic_delivery_ready": False,
            "offers": square_offer_catalog(),
        }
    status = dict(SQUARE_CONFIG.public_status())
    status["automatic_delivery_ready"] = bool(status.get("webhook_ready"))
    if SQUARE_CONFIG.environment == "production" and not status["automatic_delivery_ready"]:
        status["checkout_ready"] = False
    return status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802 - stdlib hook name
        return None


def finding_payload(item):
    return {
        "title": item.title,
        "target": item.target,
        "severity": item.severity,
        "category": item.category,
        "detail": item.detail,
        "remediation": item.remediation,
    }


def finding_identity(item) -> Tuple[str, ...]:
    return (
        str(item.title),
        str(item.target),
        str(item.severity),
        str(item.category),
        str(item.detail),
    )


def add_findings(items: Iterable[Any]) -> int:
    """Add only new findings so retries and duplicate clicks are idempotent."""

    with findings_lock:
        existing = {finding_identity(item) for item in findings}
        added = 0
        for item in items:
            identity = finding_identity(item)
            if identity in existing:
                continue
            findings.append(item)
            existing.add(identity)
            added += 1
        return added


def require_scoped_target(target):
    target = str(target or "").strip()
    if not target:
        return False, "Target is required."
    if not scope.is_allowed(target):
        return False, "Target is not in authorized scope. Add it to scope first."
    return True, target


def guardrail_payload():
    return {
        "scopeRequired": {
            "label": "Require authorized scope",
            "enabled": True,
            "locked": True,
            "description": "Remote target workflows require an allowlisted asset.",
        },
        "authenticatedControlApi": {
            "label": "Authenticate local control API",
            "enabled": True,
            "locked": True,
            "description": "Every API call except health requires Phoenix's private first-party control key.",
        },
        "registeredRemediationOnly": {
            "label": "Registered remediation actions only",
            "enabled": True,
            "locked": True,
            "description": "The one-click engine cannot execute arbitrary shell text, elevate privileges, or patch unenrolled paths.",
        },
        "verifiedRollback": {
            "label": "Snapshot, verify, and roll back",
            "enabled": True,
            "locked": True,
            "description": "Managed code is snapshotted and verified; failed source health can restore the last known-good version.",
        },
        "credentialAttacksBlocked": {
            "label": "Block credential theft and token grabbing",
            "enabled": True,
            "locked": True,
            "description": "Phoenix will not run credential theft, token extraction, or session hijacking workflows.",
        },
        "rogueApBlocked": {
            "label": "Block rogue access point attacks",
            "enabled": True,
            "locked": True,
            "description": "Wireless workflows are defensive posture and inventory only.",
        },
        "exploitDeliveryBlocked": {
            "label": "Block exploit delivery",
            "enabled": True,
            "locked": True,
            "description": "Findings use safe checks, evidence drafting, and remediation guidance.",
        },
        "reportReviewRequired": {
            "label": "Require external report review",
            "enabled": True,
            "locked": True,
            "description": "External submissions remain drafts; local registered healing can run after the Protect click.",
        },
    }


def tool_matrix_payload():
    return [
        {"name": "Autonomous Tier-1 loop", "tab": "Command", "status": "Ready", "mode": "Inventory, assess, prioritize, registered response, and recovery verification"},
        {"name": "Protect This System", "tab": "Command", "status": "Ready", "mode": "Snapshot, registered healing, verify, rollback"},
        {"name": "Phoenix control API", "tab": "Settings", "status": "Locked", "mode": "Free first-party bearer key; loopback Host/Origin checks"},
        {"name": "Enterprise profile", "tab": "Settings", "status": "Ready", "mode": "Private organization configuration with no code changes"},
        {"name": "Private anywhere access", "tab": "Settings", "status": "Optional", "mode": "HTTPS through an authenticated Tailscale network; local engine remains loopback-only"},
        {"name": "Web audit", "tab": "Bug Bounty", "status": "Ready at Base+", "mode": "Real scoped safe HTTP checks with evidence"},
        {"name": "Current vectors", "tab": "Intelligence", "status": "Ready", "mode": "CISA, NVD, and public search context"},
        {"name": "Cross-platform Kali", "tab": "Operations", "status": "Enterprise+", "mode": "Kali WSL2 on Windows or confined reviewed container on macOS/Linux; registered actions only"},
        {"name": "Installable app", "tab": "Settings", "status": "Ready", "mode": "PWA shell for iPhone, iPad, Android, macOS, Windows, and Linux; private backend required"},
        {"name": "Phoenix Local AI", "tab": "Command", "status": "Free", "mode": "Keyless local guidance; optional personal Groq provider"},
        {"name": "Fraud forensics", "tab": "Operations", "status": "Ready", "mode": "Bounded CSV upload and lawful evidence report"},
        {"name": "Reports", "tab": "Reports", "status": "Ready", "mode": "Executive and finding-report markdown drafts"},
    ]


def public_control_metadata() -> Dict[str, Any]:
    metadata = dict(CONTROL_KEYS.metadata())
    metadata.pop("key_path", None)
    return metadata


def _public_ip_addresses(hostname: str, port: int) -> list:
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ApiError(f"Could not resolve browser-context host: {exc}", 400, "dns_failed") from exc
    addresses = []
    for record in records:
        address = record[4][0].split("%", 1)[0]
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            raise ApiError("Browser context blocks private, loopback, link-local, reserved, and metadata destinations.", 403, "private_destination")
        addresses.append(str(parsed))
    if not addresses:
        raise ApiError("Browser-context host did not resolve.", 400, "dns_failed")
    return sorted(set(addresses))


def validate_scoped_public_url(value: str) -> str:
    url = str(value or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ApiError("Browser context accepts only http:// or https:// URLs.", 400, "scheme_blocked")
    if parsed.username or parsed.password or not parsed.hostname:
        raise ApiError("Browser-context URL is invalid.", 400, "invalid_url")
    allowed, message = require_scoped_target(url)
    if not allowed:
        raise ApiError(message, 403, "scope_required")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    _public_ip_addresses(parsed.hostname, port)
    return url


def fetch_scoped_public_text(value: str) -> Tuple[int, str, str, str]:
    opener = build_opener(NoRedirect())
    current = validate_scoped_public_url(value)
    for _redirect in range(MAX_REDIRECTS + 1):
        request = Request(current, headers={"User-Agent": f"{engine.APP_NAME}/1.0 scoped-browser-context"})
        try:
            response = opener.open(request, timeout=12)
        except HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                body = exc.read(MAX_BROWSER_BYTES).decode("utf-8", errors="replace")
                return exc.code, exc.headers.get_content_type(), body, current
            location = exc.headers.get("Location", "")
            if not location:
                raise ApiError("Redirect response had no destination.", 400, "invalid_redirect")
            current = validate_scoped_public_url(urljoin(current, location))
            continue
        with contextlib.closing(response):
            content_type = response.headers.get_content_type()
            if not (content_type.startswith("text/") or content_type in {"application/json", "application/xml", "application/xhtml+xml"}):
                raise ApiError("Browser context accepts text and JSON/XML responses only.", 415, "content_type_blocked")
            body = response.read(MAX_BROWSER_BYTES + 1)
            if len(body) > MAX_BROWSER_BYTES:
                raise ApiError("Browser-context response exceeded the safe size limit.", 413, "response_too_large")
            charset = response.headers.get_content_charset() or "utf-8"
            return response.status, content_type, body.decode(charset, errors="replace"), current
    raise ApiError("Browser context exceeded the redirect limit.", 400, "redirect_limit")


@contextlib.contextmanager
def temporary_fraud_csv(csv_text: str):
    incoming = CONFIG_ROOT / "incoming"
    incoming.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = csv_text.encode("utf-8")
    if len(raw) > MAX_JSON_BYTES:
        raise ApiError("Fraud CSV imports are limited to 1 MB.", 413, "csv_too_large")
    descriptor, path = tempfile.mkstemp(prefix="phoenix-fraud-", suffix=".csv", dir=str(incoming))
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(raw)
            handle.flush()
        yield path
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            Path(path).unlink()
        except FileNotFoundError:
            pass


def manager_error_status(result: Dict[str, Any]) -> int:
    error = result.get("error") or {}
    code = error.get("code", "") if isinstance(error, dict) else ""
    if code == "run_not_found":
        return 404
    if code in {"run_active", "rollback_in_progress", "idempotency_conflict", "rollback_unavailable"}:
        return 409
    return 400


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class PhoenixWebHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "PhoenixGuardian/2"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    @property
    def api_port(self) -> int:
        return int(self.server.server_address[1])

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        try:
            remote = REMOTE_ACCESS.load()
            if remote.get("enabled") and str(self.headers.get("Host", "")).lower().split(":", 1)[0] == urlparse(str(remote.get("trusted_origin", ""))).hostname:
                self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        except (RemoteAccessError, ValueError):
            pass
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            if not self._request_allowed():
                return
            if parsed.path not in PUBLIC_GET_ROUTES and not self._authenticated():
                return
            self.handle_api_get(parsed)
            return
        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            self.write_error_json("Not found", status=404, code="not_found")
            return
        if parsed.path == SQUARE_WEBHOOK_ROUTE:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                self.write_error_json("Square webhooks require application/json.", status=415, code="json_required")
                return
            self.handle_square_webhook()
            return
        if not self._request_allowed():
            return
        if parsed.path not in PUBLIC_POST_ROUTES and not self._authenticated():
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.write_error_json("POST requests require application/json.", status=415, code="json_required")
            return
        self.handle_api_post(parsed)

    def do_OPTIONS(self):
        self.write_error_json("Cross-origin requests are not supported.", status=405, code="method_not_allowed")

    def _request_allowed(self) -> bool:
        try:
            remote = REMOTE_ACCESS.load()
        except RemoteAccessError:
            remote = {"enabled": False, "trusted_origin": ""}
        trusted_origin = remote.get("trusted_origin", "") if remote.get("enabled") else ""
        mode = request_origin_mode(
            self.headers.get("Host", ""),
            self.headers.get("Origin"),
            self.api_port,
            trusted_origin,
        )
        if mode == "local":
            return True
        if mode == "remote":
            try:
                client_ip = ipaddress.ip_address(str(self.client_address[0]).split("%", 1)[0])
            except ValueError:
                client_ip = None
            identity = str(self.headers.get("Tailscale-User-Login", "") or "").strip()
            if client_ip is not None and client_ip.is_loopback and identity:
                return True
            self.write_error_json("Private remote identity is required.", status=403, code="remote_identity_required")
            return False
        self.write_error_json("Phoenix accepts only its local origin or the configured private HTTPS origin.", status=403, code="origin_blocked")
        return False

    def _authenticated(self) -> bool:
        token = extract_bearer(self.headers.get("Authorization", ""))
        if CONTROL_KEYS.authenticate(token):
            metadata = CONTROL_KEYS.metadata()
            self.auth_context = owner_context(metadata.get("expires_at"))
            return True
        subscription = SUBSCRIPTIONS.authenticate(token)
        if subscription:
            self.auth_context = subscription
            return True
        self.write_error_json("A valid, unexpired Phoenix control key is required.", status=401, code="authentication_required")
        return False

    def _require_route_feature(self, method: str, path: str) -> None:
        feature = required_feature(method, path)
        if not feature:
            return
        context = getattr(self, "auth_context", {}) or {}
        if feature in set(context.get("features", [])):
            return
        required_tier = FEATURE_MINIMUM_TIER.get(feature, "a higher")
        raise ApiError(
            f"This feature requires the {required_tier} tier. Your current tier remains active for included features.",
            403,
            "upgrade_required",
        )

    def read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError as exc:
            raise ApiError("Invalid Content-Length.", 400, "invalid_length") from exc
        if length < 0 or length > MAX_JSON_BYTES:
            raise ApiError("JSON request exceeded the 1 MB limit.", 413, "request_too_large")
        if not length:
            return b""
        return self.rfile.read(length)

    def read_json(self, raw_body: Optional[bytes] = None):
        raw_bytes = self.read_body() if raw_body is None else raw_body
        raw = raw_bytes.decode("utf-8", errors="strict")
        try:
            payload = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            raise ApiError("Request body is not valid JSON.", 400, "invalid_json") from exc
        if not isinstance(payload, dict):
            raise ApiError("JSON request body must be an object.", 400, "invalid_json")
        return payload

    def handle_square_webhook(self) -> None:
        """Accept only cryptographically verified Square server events.

        This route deliberately skips browser Origin and Phoenix-key checks
        because Square calls it server-to-server. The exact raw request bytes
        and Square signature are its authentication boundary.
        """

        try:
            raw_body = self.read_body()
            if SQUARE_CONFIG is None or SQUARE_PURCHASES is None or not SQUARE_CONFIG.public_status()["webhook_ready"]:
                raise ApiError(
                    "Square webhook verification is not configured.",
                    503,
                    "square_webhook_unavailable",
                )
            result = SQUARE_PURCHASES.process_webhook(
                raw_body,
                self.headers.get("x-square-hmacsha256-signature", ""),
                SQUARE_CONFIG,
            )
            public = {
                "ok": True,
                "accepted": bool(result.get("accepted")),
                "duplicate": bool(result.get("duplicate")),
                "ignored": bool(result.get("ignored")),
            }
            self.write_json(public, status=int(result.get("http_status", 200)))
        except ApiError as exc:
            self.write_error_json(exc.message, status=exc.status, code=exc.code)
        except SquareWebhookError as exc:
            message = str(exc)
            signature_failure = "signature" in message.lower()
            self.write_error_json(
                message,
                status=403 if signature_failure else 400,
                code="square_webhook_rejected",
            )
        except Exception as exc:
            self.log_error("Square webhook failed: %s\n%s", exc, traceback.format_exc())
            self.write_error_json(
                "Phoenix could not process the Square webhook.",
                status=500,
                code="square_webhook_failed",
            )

    def write_json(self, payload, status=200):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if status == 401:
            self.send_header("WWW-Authenticate", 'Bearer realm="Phoenix Guardian"')
        self.end_headers()
        self.wfile.write(body)

    def write_error_json(self, message, status=400, code="bad_request"):
        self.write_json({"ok": False, "error": message, "code": code}, status=status)

    def _write_manager_result(self, result: Dict[str, Any], status: int = 200):
        if result.get("ok"):
            self.write_json({"ok": True, "run": result}, status=status)
            return
        error = result.get("error") or {}
        message = error.get("message", "Remediation request failed.") if isinstance(error, dict) else str(error)
        code = error.get("code", "remediation_failed") if isinstance(error, dict) else "remediation_failed"
        self.write_error_json(message, status=manager_error_status(result), code=code)

    def handle_api_get(self, parsed):
        try:
            query = parse_qs(parsed.query)
            self._require_route_feature("GET", parsed.path)
            if parsed.path == "/api/health":
                self.write_json({"ok": True, "app": engine.APP_NAME, "api": "loopback"})
            elif parsed.path == "/api/subscriptions/catalog":
                self.write_json({"ok": True, **subscription_catalog()})
            elif parsed.path == "/api/billing/square/status":
                self.write_json({"ok": True, "square": square_public_status()})
            elif parsed.path == "/api/subscriptions/status":
                self.write_json({"ok": True, "subscription": self.subscription_payload()})
            elif parsed.path == "/api/status":
                self.write_json(self.status_payload())
            elif parsed.path == "/api/platform-readiness":
                self.write_json(platform_readiness())
            elif parsed.path == "/api/security-basics":
                self.write_json({
                    "ok": True,
                    "title": "Phoenix defensive security basics",
                    "checks": [
                        "Work only on systems and accounts you own or are explicitly authorized to test.",
                        "Keep operating systems, browsers, applications, and dependencies on supported patched versions.",
                        "Use unique credentials, multi-factor authentication, least privilege, and tested recovery methods.",
                        "Inventory assets, remove unused exposure, retain useful logs, and verify backups through restoration tests.",
                        "Preserve minimal sanitized evidence and stop before testing could affect another user or service.",
                    ],
                })
            elif parsed.path == "/api/learning-vectors":
                self.write_json({
                    "ok": True,
                    "title": "Phoenix guided cybersecurity pathway",
                    "vectors": [
                        {"stage": "Foundation", "focus": "Scope, authorization, networking, Linux, HTTP, and evidence handling", "mode": "guided"},
                        {"stage": "Defend", "focus": "Headers, TLS, dependencies, secrets hygiene, logging, backup, and recovery", "mode": "hands-on local"},
                        {"stage": "Validate", "focus": "Harmless canaries, owned test accounts, rate limits, and reproducible proof", "mode": "lab only"},
                        {"stage": "Report", "focus": "Clear impact, sanitized evidence, remediation, and retest notes", "mode": "portfolio ready"},
                    ],
                    "guardrail": "No credential attacks, exploit delivery, stealth, persistence, or testing outside explicit authorization.",
                })
            elif parsed.path == "/api/control-key":
                self.write_json({"ok": True, "controlApi": public_control_metadata()})
            elif parsed.path == "/api/enterprise/profile":
                self.write_json({"ok": True, "profile": ENTERPRISE_PROFILE.load()})
            elif parsed.path == "/api/remediation/status":
                status = remediation.status()
                with latest_run_lock:
                    identifier = latest_run_id
                if identifier:
                    status["latest_run"] = remediation.get(identifier)
                self.write_json(status)
            elif parsed.path == "/api/tier1/status":
                self.write_json(tier1.status())
            elif parsed.path == "/api/tier1/coverage":
                self.write_json(tier1.coverage())
            elif parsed.path.startswith("/api/remediation/runs/"):
                identifier = parsed.path.rsplit("/", 1)[-1]
                self._write_manager_result(remediation.get(identifier))
            elif parsed.path == "/api/scope":
                self.write_json({"ok": True, "scope": list(scope.scope)})
            elif parsed.path == "/api/report-summary":
                with findings_lock:
                    summary = engine.ai_summary(list(findings))
                    count = len(findings)
                self.write_json({"ok": True, "findings": count, "summary": summary})
            elif parsed.path == "/api/checklist":
                self.write_json({"ok": True, "text": engine.vulnerability_checklist_text()})
            elif parsed.path == "/api/voice-diagnostics":
                self.write_json({"ok": True, "text": engine.voice_dependency_report()})
            elif parsed.path == "/api/kali-inventory":
                distro = query.get("distro", ["kali-linux"])[0] or "kali-linux"
                self.write_json({"ok": True, "text": engine.kali_tool_inventory(distro=distro)})
            elif parsed.path == "/api/kali-bridge":
                distro = query.get("distro", ["kali-linux"])[0] or "kali-linux"
                self.write_json({"ok": True, "bridge": engine.kali_runtime_status(distro=distro)})
            elif parsed.path == "/api/burp-status":
                burp_findings, evidence = engine.burp_suite_status()
                self.write_json({
                    "ok": True,
                    "findings": [finding_payload(item) for item in burp_findings],
                    "evidence": evidence,
                    "text": "\n\n".join(evidence),
                    "readOnly": True,
                })
            elif parsed.path == "/api/wordlists":
                distro = query.get("distro", ["kali-linux"])[0] or "kali-linux"
                self.write_json({"ok": True, "text": engine.wordlist_catalog(distro=distro)})
            elif parsed.path == "/api/guardrails":
                self.write_json({"ok": True, "guardrails": guardrail_payload()})
            elif parsed.path == "/api/tool-matrix":
                self.write_json({"ok": True, "tools": tool_matrix_payload()})
            elif parsed.path == "/api/hackerone-readiness":
                handle = query.get("handle", [""])[0].strip() or "external program"
                self.write_json({
                    "ok": True,
                    "text": (
                        f"External security program readiness for {handle}\n"
                        "- Link an approved provider credential only when private program data is required.\n"
                        "- Confirm every asset is explicitly enrolled before testing.\n"
                        "- Phoenix prepares evidence locally; external transmission stays disabled by default."
                    ),
                })
            elif parsed.path == "/api/current-vectors":
                topic = query.get("query", ["enterprise application API cloud identity security"])[0]
                target = query.get("target", [""])[0]
                if query.get("fast", ["0"])[0] == "1":
                    self.write_json({"ok": True, "text": "Current-vector intelligence route is wired. Run without fast=1 for live CISA/NVD/web context."})
                else:
                    if target:
                        allowed, message = require_scoped_target(target)
                        if not allowed:
                            raise ApiError(message, 403, "scope_required")
                    self.write_json({"ok": True, "text": engine.current_vectors_report(query=topic, target=target, days=7)})
            elif parsed.path == "/api/government/compliance":
                self.write_json(government_compliance_payload())
            else:
                self.write_error_json("Unknown API route", status=404, code="not_found")
        except ApiError as exc:
            self.write_error_json(exc.message, status=exc.status, code=exc.code)
        except Exception as exc:
            self.log_error("API GET %s failed: %s\n%s", parsed.path, exc, traceback.format_exc())
            self.write_error_json("Phoenix could not complete the request.", status=500, code="internal_error")

    def square_checkout_return_url(self) -> str:
        origin = str(self.headers.get("Origin", "") or "").strip()
        if origin:
            parsed = urlparse(origin)
            if (
                parsed.scheme in {"http", "https"}
                and parsed.netloc
                and parsed.username is None
                and parsed.password is None
                and not parsed.path.strip("/")
                and not parsed.query
                and not parsed.fragment
            ):
                return f"{origin.rstrip('/')}/?panel=plans&square=return"
        if SQUARE_CONFIG is not None and SQUARE_CONFIG.environment == "sandbox":
            return f"http://127.0.0.1:{self.api_port}/?panel=plans&square=return"
        try:
            remote = REMOTE_ACCESS.load()
        except RemoteAccessError:
            remote = {}
        trusted_origin = str(remote.get("trusted_origin", "") or "").rstrip("/")
        if remote.get("enabled") and trusted_origin.startswith("https://"):
            return f"{trusted_origin}/?panel=plans&square=return"
        raise ApiError(
            "Production Square checkout requires Phoenix's seller-controlled HTTPS billing service.",
            503,
            "square_https_required",
        )

    def handle_api_post(self, parsed):
        global latest_run_id
        try:
            payload = self.read_json()
            self._require_route_feature("POST", parsed.path)
            if parsed.path == "/api/subscriptions/demo":
                issued = SUBSCRIPTIONS.issue("demo", customer_label="self-service demo")
                self.write_json({"ok": True, **issued}, status=201)
            elif parsed.path == "/api/billing/square/checkout":
                if SQUARE_CONFIG is None or SQUARE_CLIENT is None or SQUARE_PURCHASES is None:
                    raise ApiError("Square checkout is not configured.", 503, "square_unavailable")
                public = square_public_status()
                if not public.get("checkout_ready"):
                    raise ApiError(
                        "Square checkout is waiting for verified webhook setup.",
                        503,
                        "square_webhook_required",
                    )
                try:
                    purchase = SQUARE_PURCHASES.begin_checkout(
                        SQUARE_CLIENT,
                        str(payload.get("tier", "")),
                        self.square_checkout_return_url(),
                    )
                except SquareAPIError as exc:
                    raise ApiError(str(exc), 502, "square_checkout_failed") from exc
                except SquarePurchaseError as exc:
                    raise ApiError(str(exc), 400, "square_purchase_invalid") from exc
                self.write_json({"ok": True, **purchase}, status=201)
            elif parsed.path == "/api/billing/square/purchase":
                if SQUARE_PURCHASES is None:
                    raise ApiError("Square checkout is not configured.", 503, "square_unavailable")
                try:
                    purchase = SQUARE_PURCHASES.authenticated_status(
                        payload.get("purchase_id"), payload.get("claim_token")
                    )
                except SquarePurchaseError as exc:
                    raise ApiError(str(exc), 403, "square_purchase_invalid") from exc
                self.write_json({"ok": True, **purchase})
            elif parsed.path == "/api/billing/square/claim":
                if SQUARE_PURCHASES is None:
                    raise ApiError("Square checkout is not configured.", 503, "square_unavailable")
                try:
                    claimed = SQUARE_PURCHASES.claim(
                        payload.get("purchase_id"),
                        payload.get("claim_token"),
                        SUBSCRIPTIONS,
                    )
                except SquarePurchaseError as exc:
                    message = str(exc)
                    status = 409 if "complete" in message.lower() or "claimed" in message.lower() else 403
                    raise ApiError(message, status, "square_claim_rejected") from exc
                except SubscriptionError as exc:
                    raise ApiError(str(exc), 500, "subscription_issue_failed") from exc
                self.write_json({"ok": True, **claimed}, status=201)
            elif parsed.path == "/api/control-key/rotate":
                new_key = CONTROL_KEYS.rotate()
                self.write_json({"ok": True, "controlKey": new_key, "controlApi": public_control_metadata()})
            elif parsed.path == "/api/enterprise/profile":
                try:
                    profile = ENTERPRISE_PROFILE.save(payload)
                except EnterpriseProfileError as exc:
                    raise ApiError(str(exc), 400, "invalid_enterprise_profile") from exc
                self.write_json({"ok": True, "profile": profile})
            elif parsed.path == "/api/kali-bridge/prepare":
                if payload.get("authorization") is not True:
                    raise ApiError("One-click authorization is required before building the reviewed Kali toolkit.", 403, "authorization_required")
                result = engine.prepare_kali_container(REPO_ROOT / "containers" / "kali-phoenix")
                self.write_json(result, status=200 if result.get("ok") else 409)
            elif parsed.path == "/api/remediation/plan":
                result = remediation.plan(payload.get("asset") or None)
                if result.get("ok"):
                    self.write_json({"ok": True, "plan": result})
                else:
                    self._write_manager_result(result)
            elif parsed.path == "/api/remediation/runs":
                idempotency_key = str(self.headers.get("Idempotency-Key", "") or "").strip()
                if not idempotency_key:
                    raise ApiError("Idempotency-Key is required for remediation runs.", 400, "idempotency_required")
                if payload.get("authorization") is not True:
                    raise ApiError("One-click authorization is required for this protection run.", 403, "authorization_required")
                result = remediation.start(
                    payload.get("asset") or None,
                    idempotency_key=idempotency_key,
                    apply=bool(payload.get("apply", True)),
                )
                if result.get("ok"):
                    with latest_run_lock:
                        latest_run_id = result.get("run_id", "")
                    self.write_json({"ok": True, "run": result}, status=202)
                else:
                    self._write_manager_result(result)
            elif parsed.path == "/api/tier1/run":
                idempotency_key = str(self.headers.get("Idempotency-Key", "") or "").strip()
                if not idempotency_key:
                    raise ApiError("Idempotency-Key is required for Tier-1 runs.", 400, "idempotency_required")
                apply = bool(payload.get("apply", True))
                if apply and payload.get("authorization") is not True:
                    raise ApiError("One-click authorization is required for registered response actions.", 403, "authorization_required")
                result = tier1.run_once(
                    apply=apply,
                    authorization=payload.get("authorization") is True,
                    idempotency_key=idempotency_key,
                )
                if not result.get("ok"):
                    error = result.get("error", {})
                    raise ApiError(error.get("message", "Tier-1 run failed."), 400, error.get("code", "tier1_failed"))
                remediation_result = result.get("response", {}).get("remediation", {})
                if remediation_result.get("ok"):
                    with latest_run_lock:
                        latest_run_id = remediation_result.get("run_id", "")
                self.write_json({"ok": True, "report": result}, status=202 if apply else 200)
            elif parsed.path.startswith("/api/remediation/runs/") and parsed.path.endswith("/cancel"):
                identifier = parsed.path.split("/")[-2]
                self._write_manager_result(remediation.cancel(identifier))
            elif parsed.path.startswith("/api/remediation/runs/") and parsed.path.endswith("/rollback"):
                identifier = parsed.path.split("/")[-2]
                result = remediation.rollback(identifier)
                if result.get("ok"):
                    self.write_json({"ok": True, "run": remediation.get(identifier), "rollback": result})
                else:
                    self._write_manager_result(result)
            elif parsed.path == "/api/scope":
                target = str(payload.get("target", "")).strip()
                if not target:
                    raise ApiError("Target is required.")
                added = scope.add(target)
                self.write_json({"ok": True, "added": added, "scope": list(scope.scope)})
            elif parsed.path == "/api/web-audit":
                target = str(payload.get("target", "")).strip()
                allowed, value = require_scoped_target(target)
                if not allowed:
                    raise ApiError(value, 403 if "scope" in value else 400, "scope_required")
                audit_findings, evidence = engine.web_audit(value)
                new_count = add_findings(audit_findings)
                with findings_lock:
                    total = len(findings)
                self.write_json({
                    "ok": True,
                    "target": value,
                    "findings": [finding_payload(item) for item in audit_findings],
                    "evidence": evidence,
                    "newFindings": new_count,
                    "totalFindings": total,
                    "summary": engine.ai_summary(audit_findings),
                })
            elif parsed.path == "/api/bug-bounty-report":
                target = str(payload.get("target", "")).strip()
                allowed, value = require_scoped_target(target)
                if not allowed:
                    raise ApiError(value, 403 if "scope" in value else 400, "scope_required")
                with findings_lock:
                    snapshot = [item for item in findings if engine.host_for_target(item.target) == engine.host_for_target(value)]
                report = engine.bug_bounty_report(value, snapshot, ["Report generated from Phoenix web session evidence."])
                self.write_json({"ok": True, "target": value, "report": report})
            elif parsed.path == "/api/bug-bounty-autopilot":
                target = str(payload.get("target", "")).strip()
                allowed, value = require_scoped_target(target)
                if not allowed:
                    raise ApiError(value, 403 if "scope" in value else 400, "scope_required")
                distro = str(payload.get("distro", "kali-linux")).strip() or "kali-linux"
                autopilot_findings, evidence = engine.bug_bounty_autopilot(value, distro=distro)
                add_findings(autopilot_findings)
                with findings_lock:
                    total = len(findings)
                self.write_json({
                    "ok": True,
                    "target": value,
                    "findings": [finding_payload(item) for item in autopilot_findings],
                    "evidence": evidence,
                    "totalFindings": total,
                    "summary": engine.ai_summary(autopilot_findings),
                })
            elif parsed.path == "/api/browser-context":
                status, content_type, text, final_url = fetch_scoped_public_text(str(payload.get("url", "")))
                self.write_json({"ok": True, "url": final_url, "text": f"HTTP {status}\nContent-Type: {content_type}\n\n{text[:12000]}"})
            elif parsed.path == "/api/wsl-command":
                self.write_error_json(
                    "The arbitrary WSL shell bridge is disabled. Use registered inventory and remediation actions.",
                    status=410,
                    code="shell_bridge_disabled",
                )
            elif parsed.path == "/api/groq-chat":
                message = str(payload.get("message", "")).strip()
                if not message:
                    raise ApiError("Message is required.")
                if engine.contains_blocked_intent(message):
                    raise ApiError("Blocked by Phoenix guardrails. Ask for authorized defensive, reporting, or scoped remediation help.", 403, "unsafe_intent")
                api_key = str(payload.get("apiKey", "")).strip() or os.environ.get("GROQ_API_KEY", "") or engine.load_local_secret("GROQ_API_KEY")
                model = str(payload.get("model", engine.GROQ_AUTO_MODEL)).strip() or engine.GROQ_AUTO_MODEL
                context = f"Authorized scope: {', '.join(scope.scope)}"
                text = engine.groq_chat_response(api_key, model, message, context=context, web_context="")
                self.write_json({"ok": True, "text": text, "provider": "Groq" if api_key else "Phoenix Local"})
            elif parsed.path == "/api/fraud-report":
                csv_text = str(payload.get("csvText", "") or "")
                if not csv_text:
                    self.write_json({
                        "ok": True,
                        "findings": [],
                        "evidence": [],
                        "report": "Fraud report workspace ready. Choose a local CSV file; Phoenix accepts its bounded contents without exposing an arbitrary filesystem path.",
                    })
                    return
                with temporary_fraud_csv(csv_text) as fraud_path:
                    fraud_findings, evidence, report = engine.fraud_forensic_analysis(fraud_path)
                add_findings(fraud_findings)
                self.write_json({"ok": True, "findings": [finding_payload(item) for item in fraud_findings], "evidence": evidence, "report": report})
            elif parsed.path == "/api/defensive-drone":
                target = str(payload.get("target", "")).strip()
                csv_text = str(payload.get("csvText", "") or "")
                if target:
                    allowed, value = require_scoped_target(target)
                    if not allowed:
                        raise ApiError(value, 403 if "scope" in value else 400, "scope_required")
                    target = value
                if csv_text:
                    with temporary_fraud_csv(csv_text) as fraud_path:
                        drone_findings, evidence = engine.defensive_response_drone(target=target, fraud_path=fraud_path)
                else:
                    drone_findings, evidence = engine.defensive_response_drone(target=target, fraud_path="")
                add_findings(drone_findings)
                self.write_json({"ok": True, "findings": [finding_payload(item) for item in drone_findings], "evidence": evidence, "summary": engine.ai_summary(drone_findings)})
            elif parsed.path == "/api/clear-findings":
                with findings_lock:
                    findings.clear()
                self.write_json({"ok": True, "findings": 0})
            elif parsed.path == "/api/government/evidence-seal":
                self.write_json(seal_government_evidence(), status=201)
            else:
                self.write_error_json("Unknown API route", status=404, code="not_found")
        except ApiError as exc:
            self.write_error_json(exc.message, status=exc.status, code=exc.code)
        except UnicodeDecodeError:
            self.write_error_json("Request body must be UTF-8 JSON.", status=400, code="invalid_encoding")
        except Exception as exc:
            self.log_error("API POST %s failed: %s\n%s", parsed.path, exc, traceback.format_exc())
            self.write_error_json("Phoenix could not complete the request.", status=500, code="internal_error")

    def status_payload(self):
        with findings_lock:
            snapshot = list(findings)
        severity = {}
        category = {}
        for finding in snapshot:
            severity[finding.severity] = severity.get(finding.severity, 0) + 1
            category[finding.category] = category.get(finding.category, 0) + 1
        remediation_status = remediation.status()
        return {
            "ok": True,
            "app": engine.APP_NAME,
            "scope": list(scope.scope),
            "scopeCount": len(scope.scope),
            "findingsCount": len(snapshot),
            "groqConfigured": bool(os.environ.get("GROQ_API_KEY") or engine.load_local_secret("GROQ_API_KEY")),
            "aiProvider": "Groq (personal key)" if os.environ.get("GROQ_API_KEY") or engine.load_local_secret("GROQ_API_KEY") else "Phoenix Local (free, keyless)",
            "controlApi": public_control_metadata() if getattr(self, "auth_context", {}).get("kind") == "owner" else {
                "configured": True,
                "source": "subscription",
                "active": True,
                "expires_at": getattr(self, "auth_context", {}).get("expires_at"),
            },
            "subscription": self.subscription_payload(),
            "enterprise": ENTERPRISE_PROFILE.load(),
            "remediation": remediation_status,
            "tier1": tier1.status(),
            "severity": severity,
            "categories": category,
            "guardrails": {key: value["enabled"] for key, value in guardrail_payload().items()},
            "features": [
                "One-click registered remediation",
                "Autonomous Tier-1 control loop",
                "Known-good code snapshots",
                "Automatic verification and rollback",
                "Authenticated local control API",
                "Private reusable enterprise profile",
                "Duplicate-run idempotency",
                "Scoped web audit",
                "Current vulnerability vectors",
                "Keyless Phoenix Local AI",
                "Bounded fraud CSV import",
            ],
        }

    def subscription_payload(self) -> Dict[str, Any]:
        context = dict(getattr(self, "auth_context", {}) or {})
        context.pop("authenticated", None)
        context["catalog"] = [
            {
                "id": item["id"],
                "name": item["name"],
                "price_monthly_usd": item["price_monthly_usd"],
            }
            for item in subscription_catalog()["tiers"]
        ]
        return context


def main():
    parser = argparse.ArgumentParser(description="Serve Phoenix Guardian's authenticated local web UI")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--open", action="store_true", help="Open the authenticated one-click URL in the default browser")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    key = CONTROL_KEYS.get_or_create_key()
    url = f"http://127.0.0.1:{args.port}"
    authenticated_url = f"{url}/#key={key}"
    with ReusableTCPServer(("127.0.0.1", args.port), PhoenixWebHandler) as httpd:
        metadata = public_control_metadata()
        print(f"Phoenix Guardian Web UI + authenticated API: {url}")
        print(f"Phoenix control key: {metadata['fingerprint']} ({metadata['source']})")
        print("Use tools/launch_phoenix.py for one-click authenticated launch.")
        if args.open:
            threading.Timer(0.25, lambda: webbrowser.open(authenticated_url)).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nPhoenix Guardian stopped.")


if __name__ == "__main__":
    main()
