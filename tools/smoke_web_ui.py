"""Deterministic smoke checks for the authenticated Phoenix web API.

The default suite performs no live target scan, WSL command, external AI call,
or system update. It validates authentication, safety boundaries, idempotency,
and the local transactional remediation pipeline.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phoenix_auth import ControlKeyStore


BASE_URL = os.environ.get("PHOENIX_BASE_URL", "http://127.0.0.1:8787").rstrip("/")


def config_root() -> Path:
    override = str(os.environ.get("PHOENIX_CONFIG_DIR", "") or "").strip()
    if override:
        return Path(override).expanduser()
    base = os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME") or str(Path.home())
    return Path(base).expanduser() / "PhoenixGuardian"


def control_key() -> str:
    return ControlKeyStore(config_root()).get_or_create_key()


def request(
    path,
    method="GET",
    payload=None,
    timeout=45,
    authenticated=True,
    token=None,
    headers=None,
    content_type="application/json",
):
    data = None
    request_headers = dict(headers or {})
    if content_type:
        request_headers["Content-Type"] = content_type
    if authenticated:
        request_headers["Authorization"] = f"Bearer {token or control_key()}"
    if payload is not None:
        if isinstance(payload, bytes):
            data = payload
        else:
            data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(BASE_URL + path, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        return exc.code, json.loads(body)


def assert_ok(path, method="GET", payload=None, headers=None, **kwargs):
    status, body = request(
        path,
        method=method,
        payload=payload,
        headers=headers,
        **kwargs,
    )
    if status not in {200, 201, 202} or not body.get("ok"):
        raise AssertionError(f"{method} {path} failed: HTTP {status} {body}")
    return body


def assert_error(expected_status, path, method="GET", payload=None, **kwargs):
    status, body = request(path, method=method, payload=payload, **kwargs)
    if status != expected_status or body.get("ok") is not False:
        raise AssertionError(
            f"{method} {path} expected HTTP {expected_status}, got HTTP {status} {body}"
        )
    return body


def wait_for_run(run_id, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = assert_ok(f"/api/remediation/runs/{run_id}")["run"]
        if result.get("status") in {"succeeded", "failed", "cancelled", "rolled_back"}:
            return result
        time.sleep(0.1)
    raise AssertionError(f"remediation run {run_id} did not finish within {timeout}s")


def main():
    status, health = request("/api/health", authenticated=False)
    if status != 200 or not health.get("ok"):
        raise AssertionError(f"health check failed: HTTP {status} {health}")

    catalog = assert_ok("/api/subscriptions/catalog", authenticated=False)
    prices = {
        tier["id"]: tier["price_monthly_usd"]
        for tier in catalog.get("tiers", [])
    }
    if prices != {"demo": 0, "solo": 50, "base": 150, "enterprise": 1000, "government": 1500}:
        raise AssertionError(f"unexpected subscription catalog: {catalog}")

    billing = assert_ok("/api/billing/square/status", authenticated=False)
    square = billing.get("square", {})
    square_prices = {
        offer["tier"]: offer["amount_cents"]
        for offer in square.get("offers", [])
    }
    if square_prices != {"solo": 5000, "base": 15000, "enterprise": 100000, "government": 150000}:
        raise AssertionError(f"unexpected Square offer catalog: {billing}")
    rendered_billing = json.dumps(billing).lower()
    for forbidden in ("access_token", "application_id", "location_id", "signature_key", "notification_url"):
        if forbidden in rendered_billing:
            raise AssertionError(f"Square public status exposed private field {forbidden}")
    if square.get("environment") == "production" and square.get("checkout_ready") and not square.get("webhook_ready"):
        raise AssertionError("Production checkout was enabled without verified webhook configuration")

    demo = assert_ok(
        "/api/subscriptions/demo",
        method="POST",
        payload={"customer_label": "Automated smoke test"},
        authenticated=False,
    )
    demo_key = demo.get("control_key")
    if not demo_key:
        raise AssertionError(f"demo activation did not return a control key: {demo}")
    demo_status = assert_ok("/api/subscriptions/status", token=demo_key)
    if demo_status.get("subscription", {}).get("tier") != "demo":
        raise AssertionError(f"demo key reported the wrong tier: {demo_status}")
    assert_ok("/api/platform-readiness", token=demo_key)
    checklist_upgrade = assert_error(403, "/api/checklist", token=demo_key)
    if checklist_upgrade.get("code") != "upgrade_required":
        raise AssertionError(f"demo Bug Bounty denial was not explicit: {checklist_upgrade}")
    upgrade = assert_error(
        403,
        "/api/tier1/run",
        method="POST",
        payload={"apply": True, "authorization": True},
        token=demo_key,
        headers={"Idempotency-Key": f"demo-denied-{int(time.time() * 1000)}"},
    )
    if upgrade.get("code") != "upgrade_required":
        raise AssertionError(f"demo paid-feature denial was not explicit: {upgrade}")

    assert_error(401, "/api/status", authenticated=False)
    assert_error(
        403,
        "/api/status",
        headers={"Origin": "http://evil.example:8787"},
    )
    assert_error(
        415,
        "/api/scope",
        method="POST",
        payload=b"{}",
        content_type="text/plain",
    )

    initial = assert_ok("/api/status")
    assert_ok("/api/guardrails")
    assert_ok("/api/tool-matrix")
    assert_ok("/api/control-key")
    profile = assert_ok("/api/enterprise/profile")["profile"]
    assert_ok("/api/enterprise/profile", method="POST", payload=profile)
    assert_ok("/api/remediation/status")
    assert_ok("/api/tier1/status")
    coverage = assert_ok("/api/tier1/coverage")
    if [item.get("function") for item in coverage.get("functions", [])] != ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"]:
        raise AssertionError(f"unexpected Tier-1 coverage model: {coverage}")
    assert_ok("/api/checklist")
    assert_ok("/api/current-vectors?query=web%20security&fast=1")

    before_burp = assert_ok("/api/status")["findingsCount"]
    assert_ok("/api/burp-status")
    after_burp = assert_ok("/api/status")["findingsCount"]
    if before_burp != after_burp:
        raise AssertionError("GET /api/burp-status mutated shared findings")

    assert_ok("/api/scope", method="POST", payload={"target": "example.com"})
    assert_error(
        403,
        "/api/web-audit",
        method="POST",
        payload={"target": "not-in-scope.invalid"},
    )
    assert_error(
        400,
        "/api/browser-context",
        method="POST",
        payload={"url": "file:///etc/passwd"},
    )
    assert_error(
        410,
        "/api/wsl-command",
        method="POST",
        payload={"command": "echo should-not-run"},
    )
    assert_error(
        400,
        "/api/remediation/plan",
        method="POST",
        payload={"asset": "../outside"},
    )
    assert_ok("/api/remediation/plan", method="POST", payload={"asset": "."})
    assert_ok("/api/fraud-report", method="POST", payload={"csvText": ""})
    assert_ok(
        "/api/groq-chat",
        method="POST",
        payload={"message": "Give me a local defensive readiness summary", "apiKey": "", "model": "auto"},
    )

    idempotency_key = f"smoke-{int(time.time() * 1000)}"
    assert_error(
        403,
        "/api/tier1/run",
        method="POST",
        payload={"apply": True},
        headers={"Idempotency-Key": f"tier1-{idempotency_key}-unauthorized"},
    )
    assert_error(
        403,
        "/api/remediation/runs",
        method="POST",
        payload={"asset": ".", "apply": True},
        headers={"Idempotency-Key": f"{idempotency_key}-unauthorized"},
    )
    started = assert_ok(
        "/api/remediation/runs",
        method="POST",
        payload={"asset": ".", "apply": True, "authorization": True},
        headers={"Idempotency-Key": idempotency_key},
    )["run"]
    finished = wait_for_run(started["run_id"])
    if finished.get("status") != "succeeded":
        raise AssertionError(f"bounded remediation did not verify successfully: {finished}")

    replay = assert_ok(
        "/api/remediation/runs",
        method="POST",
        payload={"asset": ".", "apply": True, "authorization": True},
        headers={"Idempotency-Key": idempotency_key},
    )["run"]
    if replay.get("run_id") != started["run_id"] or not replay.get("idempotent_replay"):
        raise AssertionError(f"idempotent replay created a duplicate run: {replay}")

    final = assert_ok("/api/status")
    if not final.get("controlApi", {}).get("configured"):
        raise AssertionError("Phoenix control API key is not configured")
    if final.get("aiProvider") not in {"Phoenix Local (free, keyless)", "Groq (personal key)"}:
        raise AssertionError(f"unexpected AI provider status: {final.get('aiProvider')}")

    print(
        "Phoenix authenticated smoke passed: auth/origin/content-type boundaries, "
        "monthly tier catalog, secret-free Square status, restricted free demo, read-only GETs, scoped blocking, "
        "SSRF/shell blocking, free owner control key, "
        "and one idempotent verified remediation run."
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"SMOKE FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
