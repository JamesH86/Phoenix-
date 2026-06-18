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
            elif parsed.path == "/api/current-vectors":
                topic = query.get("query", ["web application API cloud auth bug bounty"])[0]
                target = query.get("target", [""])[0]
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
                if not target:
                    self.write_error_json("Target is required.")
                    return
                if not scope.is_allowed(target):
                    self.write_error_json("Target is not in authorized scope. Add it to scope first.", status=403)
                    return
                audit_findings, evidence = engine.web_audit(target)
                with findings_lock:
                    findings.extend(audit_findings)
                    total = len(findings)
                self.write_json({
                    "ok": True,
                    "target": target,
                    "findings": [item.__dict__ for item in audit_findings],
                    "evidence": evidence,
                    "totalFindings": total,
                    "summary": engine.ai_summary(audit_findings),
                })
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
            "severity": severity,
            "categories": category,
            "guardrails": {
                "scopeRequired": True,
                "credentialAttacksBlocked": True,
                "tokenGrabbingBlocked": True,
                "rogueApBlocked": True,
                "exploitDeliveryBlocked": True,
            },
            "features": [
                "Scoped web audit",
                "Current vulnerability vectors",
                "Kali WSL inventory",
                "Voice diagnostics",
                "Bug bounty checklist",
                "Report summary",
            ],
        }


def main():
    with ReusableTCPServer(("127.0.0.1", PORT), PhoenixWebHandler) as httpd:
        print(f"Phoenix Guardian Web UI + API: http://127.0.0.1:{PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
