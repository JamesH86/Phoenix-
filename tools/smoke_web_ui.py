import json
import sys
import urllib.error
import urllib.request


BASE_URL = "http://127.0.0.1:8787"


def request(path, method="GET", payload=None):
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        return exc.code, json.loads(body)


def assert_ok(path, method="GET", payload=None):
    status, body = request(path, method=method, payload=payload)
    if status != 200 or not body.get("ok"):
        raise AssertionError(f"{method} {path} failed: HTTP {status} {body}")
    return body


def main():
    checks = [
        ("GET", "/api/status", None),
        ("GET", "/api/checklist", None),
        ("GET", "/api/current-vectors?query=web%20security&fast=1", None),
        ("GET", "/api/voice-diagnostics", None),
        ("GET", "/api/kali-inventory", None),
        ("GET", "/api/burp-status", None),
        ("GET", "/api/wordlists", None),
        ("GET", "/api/guardrails", None),
        ("GET", "/api/tool-matrix", None),
        ("GET", "/api/hackerone-readiness?handle=shopify", None),
        ("POST", "/api/scope", {"target": "example.com"}),
        ("POST", "/api/web-audit", {"target": "example.com"}),
        ("POST", "/api/bug-bounty-report", {"target": "example.com"}),
        ("POST", "/api/browser-context", {"url": "https://example.com"}),
        ("POST", "/api/wsl-command", {"command": "echo phoenix-smoke"}),
        ("POST", "/api/groq-chat", {"message": "hello", "apiKey": "", "model": "llama-3.1-8b-instant"}),
        ("POST", "/api/fraud-report", {"path": ""}),
        ("POST", "/api/defensive-drone", {"target": "example.com", "fraudPath": ""}),
    ]
    for method, path, payload in checks:
        assert_ok(path, method=method, payload=payload)

    status, body = request("/api/web-audit", method="POST", payload={"target": "not-in-scope.invalid"})
    if status != 403 or body.get("ok"):
        raise AssertionError(f"Out-of-scope audit was not blocked: HTTP {status} {body}")

    print(f"Phoenix web UI smoke passed: {len(checks)} endpoint checks and one guardrail check.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"SMOKE FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
