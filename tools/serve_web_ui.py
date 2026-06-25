import http.server
import importlib.util
import json
import socketserver
import sys
import threading
import traceback
from pathlib import Path
from urllib.parse import parse_qs, urlparse


PORT = 8787
REPO_ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = REPO_ROOT / "web_ui"
ENGINE_PATH = REPO_ROOT / "phoenix_guardian.py"


def load_engine():
    spec = importlib.util.spec_from_file_location("phoenix_guardian_engine", ENGINE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


engine = load_engine()
scope = engine.ScopeManager(str(REPO_ROOT / engine.DATA_FILE))
findings = []
findings_lock = threading.Lock()


def finding_payload(item):
    return {
        "title": item.title,
        "target": item.target,
        "severity": item.severity,
        "category": item.category,
        "detail": item.detail,
        "remediation": item.remediation,
    }


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
            "label": "Require report review",
            "enabled": True,
            "locked": True,
            "description": "Bug bounty reports remain drafts until a human reviews the evidence.",
        },
    }


def tool_matrix_payload():
    return [
        {"name": "Web audit", "tab": "Bug Bounty", "status": "Ready", "mode": "Scoped safe HTTP checks"},
        {"name": "Current vectors", "tab": "Intelligence", "status": "Ready", "mode": "CISA, NVD, and public search context"},
        {"name": "Burp Suite", "tab": "Bug Bounty", "status": "Ready", "mode": "Local status and manual validation workflow"},
        {"name": "Kali WSL", "tab": "Operations", "status": "Ready", "mode": "Local inventory and guarded command bridge"},
        {"name": "Voice diagnostics", "tab": "Operations", "status": "Ready", "mode": "Speech dependency report and typed fallback"},
        {"name": "Fraud forensics", "tab": "Operations", "status": "Ready", "mode": "CSV evidence clustering and police handoff report"},
        {"name": "Reports", "tab": "Reports", "status": "Ready", "mode": "Executive and bug bounty markdown drafts"},
    ]


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class PhoenixWebHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self.handle_api_get(parsed)
            return
        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self.handle_api_post(parsed)
            return
        self.send_error(404, "Not found")

    def read_json(self):
        length = int(self.headers.get("content-length", "0") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        return json.loads(raw or "{}")

    def write_json(self, payload, status=200):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def write_error_json(self, message, status=400, detail=""):
        self.write_json({"ok": False, "error": message, "detail": detail}, status=status)

    def handle_api_get(self, parsed):
        try:
            query = parse_qs(parsed.query)
            if parsed.path == "/api/status":
                self.write_json(self.status_payload())
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
            elif parsed.path == "/api/burp-status":
                burp_findings, evidence = engine.burp_suite_status()
                with findings_lock:
                    findings.extend(burp_findings)
                self.write_json({
                    "ok": True,
                    "findings": [finding_payload(item) for item in burp_findings],
                    "evidence": evidence,
                    "text": "\n\n".join(evidence),
                })
            elif parsed.path == "/api/wordlists":
                distro = query.get("distro", ["kali-linux"])[0] or "kali-linux"
                self.write_json({"ok": True, "text": engine.wordlist_catalog(distro=distro)})
            elif parsed.path == "/api/guardrails":
                self.write_json({"ok": True, "guardrails": guardrail_payload()})
            elif parsed.path == "/api/tool-matrix":
                self.write_json({"ok": True, "tools": tool_matrix_payload()})
            elif parsed.path == "/api/hackerone-readiness":
                handle = query.get("handle", [""])[0].strip() or "program"
                self.write_json({
                    "ok": True,
                    "text": (
                        f"HackerOne readiness for {handle}\n"
                        "- Link an API token in the desktop app or environment before fetching private program data.\n"
                        "- Confirm every asset is eligible for submission and bounty before testing.\n"
                        "- Phoenix can draft reports and report-intent payloads, but review is required before submission.\n"
                        "- Use your HackerOne handle/tag only in final reports you have reviewed."
                    ),
                })
            elif parsed.path == "/api/current-vectors":
                topic = query.get("query", ["web application API cloud auth bug bounty"])[0]
                target = query.get("target", [""])[0]
                if query.get("fast", ["0"])[0] == "1":
                    self.write_json({"ok": True, "text": "Current-vector intelligence route is wired. Run without fast=1 for live CISA/NVD/web context."})
                else:
                    self.write_json({"ok": True, "text": engine.current_vectors_report(query=topic, target=target, days=7)})
            else:
                self.write_error_json("Unknown API route", status=404)
        except Exception as exc:
            self.write_error_json(str(exc), status=500, detail=traceback.format_exc())

    def handle_api_post(self, parsed):
        try:
            payload = self.read_json()
            if parsed.path == "/api/scope":
                target = str(payload.get("target", "")).strip()
                if not target:
                    self.write_error_json("Target is required.")
                    return
                added = scope.add(target)
                self.write_json({"ok": True, "added": added, "scope": list(scope.scope)})
            elif parsed.path == "/api/web-audit":
                target = str(payload.get("target", "")).strip()
                allowed, value = require_scoped_target(target)
                if not allowed:
                    self.write_error_json(value, status=403 if "scope" in value else 400)
                    return
                audit_findings, evidence = engine.web_audit(value)
                with findings_lock:
                    findings.extend(audit_findings)
                    total = len(findings)
                self.write_json({
                    "ok": True,
                    "target": value,
                    "findings": [finding_payload(item) for item in audit_findings],
                    "evidence": evidence,
                    "totalFindings": total,
                    "summary": engine.ai_summary(audit_findings),
                })
            elif parsed.path == "/api/bug-bounty-report":
                target = str(payload.get("target", "")).strip()
                allowed, value = require_scoped_target(target)
                if not allowed:
                    self.write_error_json(value, status=403 if "scope" in value else 400)
                    return
                with findings_lock:
                    snapshot = [item for item in findings if engine.host_for_target(item.target) == engine.host_for_target(value)]
                    if not snapshot:
                        snapshot = list(findings)
                report = engine.bug_bounty_report(value, snapshot, ["Report generated from Phoenix web session evidence."])
                self.write_json({"ok": True, "target": value, "report": report})
            elif parsed.path == "/api/bug-bounty-autopilot":
                target = str(payload.get("target", "")).strip()
                allowed, value = require_scoped_target(target)
                if not allowed:
                    self.write_error_json(value, status=403 if "scope" in value else 400)
                    return
                distro = str(payload.get("distro", "kali-linux")).strip() or "kali-linux"
                autopilot_findings, evidence = engine.bug_bounty_autopilot(value, distro=distro)
                with findings_lock:
                    findings.extend(autopilot_findings)
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
                url = str(payload.get("url", "")).strip()
                if not url:
                    self.write_error_json("URL is required.")
                    return
                status, content_type, text = engine.fetch_url_text(engine.ensure_url(url), timeout=12, limit=90000)
                self.write_json({"ok": True, "url": url, "text": f"HTTP {status}\nContent-Type: {content_type}\n\n{text[:12000]}"})
            elif parsed.path == "/api/wsl-command":
                command = str(payload.get("command", "")).strip()
                if not command:
                    self.write_error_json("Command is required.")
                    return
                if engine.contains_blocked_intent(command):
                    self.write_error_json("Blocked by Phoenix guardrails. Use scoped defensive or inventory commands only.", status=403)
                    return
                distro = str(payload.get("distro", "kali-linux")).strip() or "kali-linux"
                output = engine.run_wsl_command(command, distro=distro, timeout=45)
                self.write_json({"ok": True, "command": command, "text": output})
            elif parsed.path == "/api/groq-chat":
                message = str(payload.get("message", "")).strip()
                if not message:
                    self.write_error_json("Message is required.")
                    return
                if engine.contains_blocked_intent(message):
                    self.write_error_json("Blocked by Phoenix guardrails. Ask for authorized defensive, reporting, or scoped testing help.", status=403)
                    return
                api_key = str(payload.get("apiKey", "")).strip() or engine.load_local_secret("GROQ_API_KEY")
                model = str(payload.get("model", engine.GROQ_AUTO_MODEL)).strip() or engine.GROQ_AUTO_MODEL
                context = f"Authorized scope: {', '.join(scope.scope)}"
                text = engine.groq_chat_response(api_key, model, message, context=context, web_context="")
                self.write_json({"ok": True, "text": text})
            elif parsed.path == "/api/fraud-report":
                fraud_path = str(payload.get("path", "")).strip()
                if not fraud_path:
                    report = (
                        "Fraud report workspace ready.\n"
                        "Provide a local CSV path with transaction_id, timestamp, amount, merchant, terminal, ip, device, status, and pin_result fields when available."
                    )
                    self.write_json({"ok": True, "findings": [], "evidence": [], "report": report})
                    return
                fraud_findings, evidence, report = engine.fraud_forensic_analysis(fraud_path)
                with findings_lock:
                    findings.extend(fraud_findings)
                self.write_json({"ok": True, "findings": [finding_payload(item) for item in fraud_findings], "evidence": evidence, "report": report})
            elif parsed.path == "/api/defensive-drone":
                target = str(payload.get("target", "")).strip()
                fraud_path = str(payload.get("fraudPath", "")).strip()
                if target:
                    allowed, value = require_scoped_target(target)
                    if not allowed:
                        self.write_error_json(value, status=403 if "scope" in value else 400)
                        return
                    target = value
                drone_findings, evidence = engine.defensive_response_drone(target=target, fraud_path=fraud_path)
                with findings_lock:
                    findings.extend(drone_findings)
                self.write_json({"ok": True, "findings": [finding_payload(item) for item in drone_findings], "evidence": evidence, "summary": engine.ai_summary(drone_findings)})
            elif parsed.path == "/api/clear-findings":
                with findings_lock:
                    findings.clear()
                self.write_json({"ok": True, "findings": 0})
            else:
                self.write_error_json("Unknown API route", status=404)
        except Exception as exc:
            self.write_error_json(str(exc), status=500, detail=traceback.format_exc())

    def status_payload(self):
        with findings_lock:
            snapshot = list(findings)
        severity = {}
        category = {}
        for finding in snapshot:
            severity[finding.severity] = severity.get(finding.severity, 0) + 1
            category[finding.category] = category.get(finding.category, 0) + 1
        return {
            "ok": True,
            "app": engine.APP_NAME,
            "scope": list(scope.scope),
            "scopeCount": len(scope.scope),
            "findingsCount": len(snapshot),
            "groqConfigured": bool(engine.load_local_secret("GROQ_API_KEY")),
            "severity": severity,
            "categories": category,
            "guardrails": {
                key: value["enabled"] for key, value in guardrail_payload().items()
            },
            "features": [
                "Scoped web audit",
                "Current vulnerability vectors",
                "Kali WSL inventory",
                "Voice diagnostics",
                "Bug bounty checklist",
                "Report summary",
                "Burp status",
                "Wordlist catalog",
                "Defensive drone",
                "Fraud evidence report",
                "Guarded WSL command bridge",
            ],
        }


def main():
    with ReusableTCPServer(("127.0.0.1", PORT), PhoenixWebHandler) as httpd:
        print(f"Phoenix Guardian Web UI + API: http://127.0.0.1:{PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
