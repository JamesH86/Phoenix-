import csv
import datetime as dt
import hashlib
import html
import json
import math
import os
import queue
import re
import shutil
import shlex
import socket
import ssl
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from tkinter import filedialog, messagebox, simpledialog, ttk
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs
from urllib.parse import unquote
from urllib.parse import urlparse
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import base64


APP_NAME = "Phoenix Guardian"
DATA_FILE = "phoenix_guardian_scope.json"
CHAT_MEMORY_FILE = "phoenix_guardian_chat_memory.json"
SECRET_FILE = "phoenix_guardian_secrets.json"
HACKERONE_API_BASE = "https://api.hackerone.com/v1"
GROQ_API_BASE = "https://api.groq.com/openai/v1"
GROQ_DEFAULT_MODEL = "llama-3.3-70b-versatile"
CISA_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

THEME = {
    "bg": "#080a0f",
    "panel": "#0f1117",
    "panel_alt": "#151821",
    "panel_soft": "#1b2030",
    "field": "#050816",
    "text": "#f6f7fb",
    "muted": "#9ba3af",
    "line": "#2b3245",
    "accent": "#7dd3fc",
    "accent_2": "#a78bfa",
    "accent_3": "#fb923c",
    "grid": "#172033",
    "glow": "#164e63",
    "route": "#38bdf8",
    "good": "#22c55e",
    "warn": "#f59e0b",
    "bad": "#ef4444",
}

THEME_PRESETS = {
    "Codex Dark": dict(THEME),
    "Phoenix HUD": {
        "bg": "#05070c",
        "panel": "#0b101a",
        "panel_alt": "#101827",
        "panel_soft": "#162033",
        "field": "#050917",
        "text": "#eef6ff",
        "muted": "#8da2b7",
        "line": "#26364f",
        "accent": "#38d5ff",
        "accent_2": "#b46cff",
        "accent_3": "#ff8a3d",
        "grid": "#102238",
        "glow": "#0e7490",
        "route": "#22d3ee",
        "good": "#2dd4bf",
        "warn": "#fbbf24",
        "bad": "#fb7185",
    },
    "Phoenix Fire": {
        "bg": "#120906",
        "panel": "#1b0f0b",
        "panel_alt": "#24120d",
        "panel_soft": "#3a1a10",
        "field": "#0b0504",
        "text": "#fff7ed",
        "muted": "#f3b28f",
        "line": "#5c2b1a",
        "accent": "#fb923c",
        "accent_2": "#facc15",
        "accent_3": "#38bdf8",
        "grid": "#3a1a10",
        "glow": "#7c2d12",
        "route": "#f97316",
        "good": "#34d399",
        "warn": "#f59e0b",
        "bad": "#ef4444",
    },
}


SECURITY_HEADERS = {
    "strict-transport-security": "Helps enforce HTTPS.",
    "content-security-policy": "Limits script/content injection impact.",
    "x-frame-options": "Reduces clickjacking risk.",
    "x-content-type-options": "Prevents MIME sniffing.",
    "referrer-policy": "Limits sensitive referrer leakage.",
    "permissions-policy": "Restricts browser feature access.",
}

SEVERITY_POINTS = {
    "High": 8,
    "Medium": 5,
    "Low": 2,
    "Info": 1,
}

KALI_TOOL_NAMES = [
    "amass", "arachni", "assetfinder", "burpsuite", "cewl", "curl", "dig",
    "checkov", "cosign", "dirb", "dirbuster", "dirsearch", "dnsenum", "dnsrecon", "feroxbuster",
    "ffuf", "gobuster", "hakrawler", "host", "httpx", "hydra", "jq", "katana",
    "masscan", "metasploit-framework", "msfconsole", "nikto", "nmap", "nuclei",
    "openscap", "openssl", "osv-scanner", "prowler", "python3", "searchsploit", "semgrep",
    "sqlmap", "sslscan", "sslyze", "syft", "tfsec", "trivy", "trufflehog",
    "subfinder", "testssl.sh", "theHarvester", "wafw00f", "wapiti", "wfuzz",
    "whatweb", "whois", "wpscan", "zap-baseline.py", "zap.sh",
]

KALI_DRONE_TASKS = [
    "Recon Drone",
    "Cybersecurity Drone",
    "Defensive Response Drone",
    "Burp Proxy Drone",
    "Bug Bounty Autopilot",
    "Port Posture Drone",
    "Web Fingerprint Drone",
    "TLS Certificate Drone",
    "DNS Records Drone",
    "WHOIS Drone",
    "WAF Fingerprint Drone",
    "SSL Scan Drone",
    "HTTP Probe Drone",
    "Content Baseline Drone",
    "Subdomain Passive Drone",
    "Nikto Headers Drone",
]

AUTONOMOUS_DRONE_TASKS = [
    "Recon Drone",
    "Cybersecurity Drone",
    "Defensive Response Drone",
    "DNS Records Drone",
    "TLS Certificate Drone",
    "HTTP Probe Drone",
    "Online OSINT Drone",
    "Wordlist Catalog Drone",
]

BUG_BOUNTY_AUTONOMOUS_TASKS = [
    "Bug Bounty Autopilot",
    "Burp Proxy Drone",
    "Online OSINT Drone",
    "Wordlist Catalog Drone",
]

WORDLIST_PATHS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster/wordlists",
    "/usr/share/wfuzz/wordlist",
]

GUARDRAIL_ITEMS = [
    ("require_scope", "Require allowlisted scope", True, False, "Every remote target must be in the authorized scope list."),
    ("allow_online_osint", "Allow online OSINT/web search", True, True, "Collect public information needed for scoped testing."),
    ("allow_burp_proxy", "Allow Burp proxy probe", True, True, "Send header-only requests through local Burp proxy."),
    ("allow_wordlist_catalog", "Allow wordlist cataloging", True, True, "Inventory local wordlists for content discovery planning and offline/lab auditing."),
    ("allow_money_estimates", "Allow monetary estimates", True, True, "Estimate bounty value, remediation cost, and financial exposure from findings."),
    ("block_credential_attacks", "Block credential attacks", True, False, "No password spraying, credential stuffing, phishing, or live login attacks."),
    ("block_token_grabbing", "Block token/OAuth grabbers", True, False, "No token extractor, OAuth2 grabber, session theft, or secret exfiltration."),
    ("block_license_piracy", "Block license/key generators", True, False, "No Burp Professional license generator or piracy workflow."),
    ("block_rogue_ap", "Block rogue AP/MITM attacks", True, False, "No evil twin, deauth, rogue AP, credential capture, or traffic interception against others."),
    ("block_exploit_delivery", "Block exploit delivery", True, False, "No payload delivery, persistence, destructive exploitation, or stealth."),
]

TOOL_POLICY_CATALOG = [
    ("Metasploit / Armitage", "Inventory and lab planning only", "blocked for live exploitation"),
    ("Stego tools", "Defensive file review and evidence notes", "allowed"),
    ("Burp Suite", "Manual proxy, logger, repeater-assisted validation", "allowed"),
    ("Nikto", "Low-impact headers/server posture checks", "allowed"),
    ("Wifite / WPS", "Owned-router defense review only", "blocked for cracking/bruteforce"),
    ("MITM / rogue access point", "Risk education and defensive detection notes", "blocked for attack automation"),
    ("Website auditing", "Headers, TLS, cookies, canary validation", "allowed"),
    ("XSS", "Harmless reflection canary and encoding review", "allowed"),
    ("CSRF token tracer", "Token presence and form-review guidance", "allowed"),
    ("JWT", "Offline decode/header-claims review only", "allowed"),
    ("Java", "Burp/runtime inventory and version notes", "allowed"),
    ("Command injection attacker", "Safe canary planning only", "blocked for exploit execution"),
    ("WordPress scanner", "Version/plugin exposure review when in scope", "allowed"),
    ("Broken link hijacking", "Passive link/reference checks only", "allowed"),
    ("Python scripter", "Defensive automation templates", "allowed"),
    ("Burp Suite Professional license generator", "Not provided", "blocked piracy"),
    ("Token extractor", "Not provided", "blocked credential theft"),
    ("OAuth2 grabber", "Not provided", "blocked credential/session theft"),
]

VULNERABILITY_TAXONOMY = [
    "Cross-Site Scripting (XSS) - Stored",
    "Cross-Site Scripting (XSS) - Reflected",
    "Cross-Site Scripting (XSS) - DOM",
    "Insecure Direct Object Reference (IDOR)",
    "Server-Side Request Forgery (SSRF)",
    "SQL Injection (SQLi)",
    "Command Injection",
    "Code Injection",
    "Local File Inclusion (LFI)",
    "Remote File Inclusion (RFI)",
    "Cross-Site Request Forgery (CSRF)",
    "Improper Access Control",
    "Broken Object Level Authorization (BOLA)",
    "Broken Function Level Authorization (BFLA)",
    "Privilege Escalation - Vertical",
    "Privilege Escalation - Horizontal",
    "Improper Authentication",
    "Broken Session Management",
    "Session Fixation",
    "Information Disclosure",
    "Sensitive Data Exposure",
    "XML External Entity (XXE) Injection",
    "Insecure Deserialization",
    "Security Misconfiguration",
    "Directory Traversal",
    "Open Redirect",
    "Clickjacking (UI Redressing)",
    "Business Logic Errors",
    "Race Condition",
    "Rate Limiting Bypass",
    "Brute Force Amplification",
    "Cross-Origin Resource Sharing (CORS) Misconfiguration",
    "Server-Side Template Injection (SSTI)",
    "HTTP Request Smuggling",
    "GraphQL Injection",
    "Mass Assignment",
    "Insecure Components and Dependencies",
    "Insufficient Logging and Monitoring",
    "Cryptographic Failures",
]

CURRENT_VECTOR_SOURCES = [
    ("CISA KEV", CISA_KEV_JSON_URL),
    ("NVD CVE API", NVD_CVE_API_URL),
    ("OWASP Web Security Testing Guide", "https://owasp.org/www-project-web-security-testing-guide/"),
    ("OWASP API Security Top 10", "https://owasp.org/API-Security/"),
    ("HackerOne Hacktivity", "https://hackerone.com/hacktivity"),
]

BUG_BOUNTY_VECTOR_PLAYBOOKS = [
    (
        "Identity and session authorization",
        "IDOR/BOLA/BFLA, horizontal privilege confusion, session fixation, OAuth callback mistakes, stale JWT claims.",
        "Map roles and object IDs you own, verify server-side authorization, capture request/response evidence, and avoid touching other users' data.",
    ),
    (
        "Web injection and browser trust boundaries",
        "Stored/reflected/DOM XSS, HTML injection, CSP gaps, template injection indicators, open redirects, clickjacking.",
        "Use harmless canaries, browser developer tools, response headers, and Burp history. Do not deliver exploit payloads or steal tokens.",
    ),
    (
        "API and GraphQL abuse paths",
        "Mass assignment, schema exposure, broken pagination controls, excessive data exposure, rate-limit weakness, GraphQL introspection risk.",
        "Exercise only owned test accounts and documented scope. Collect schema, endpoint, role, and rate evidence with sensitive values redacted.",
    ),
    (
        "Supply chain and exposed components",
        "Known vulnerable dependencies, abandoned subdomains, broken link hijacking, exposed build artifacts, outdated WordPress/plugin surfaces.",
        "Correlate public version evidence with NVD/CISA/maintainer advisories and submit only when the vulnerable asset is in program scope.",
    ),
    (
        "Cloud, metadata, and SSRF-adjacent risk",
        "SSRF indicators, internal URL fetch features, webhook validators, cloud metadata exposure, unsafe redirect/fetch allowlists.",
        "Document fetch behavior with benign domains you control or public canaries. Stop before internal probing or data access.",
    ),
    (
        "Business logic and money movement",
        "Coupon stacking, refund logic, payment state desync, race conditions, inventory manipulation, card-fraud indicators.",
        "Use approved test accounts, minimal values, and program-safe flows. Preserve timestamps and request IDs for reproducibility.",
    ),
    (
        "AI, LLM, and agentic app surfaces",
        "Prompt injection, unsafe tool authorization, RAG data leakage, model output trust boundaries, tenant isolation mistakes, secret exposure in traces.",
        "Use owned prompts, benign canaries, trace review, and policy screenshots. Do not extract secrets, private records, or third-party data.",
    ),
    (
        "Cloud, container, CI/CD, and supply chain",
        "SBOM gaps, vulnerable images, exposed signing keys, OIDC trust mistakes, dependency confusion indicators, IaC drift, public secret leakage.",
        "Correlate public evidence with CISA/NVD/vendor advisories and run local-only checks such as Trivy, Syft, Semgrep, Checkov, or OSV Scanner when installed.",
    ),
]

BLOCKED_INTENT_PATTERNS = [
    "credential stuffing", "password spraying", "token grab", "token extractor",
    "oauth2 grabber", "session hijack", "burp suite professional license generator",
    "license generator", "keygen", "rogue access point", "evil twin", "deauth",
    "bypass guardrail", "disable guardrail", "steal", "exfiltrate", "persistence",
]


@dataclass
class Finding:
    target: str
    category: str
    severity: str
    title: str
    detail: str
    remediation: str
    timestamp: str = field(default_factory=lambda: dt.datetime.now().isoformat(timespec="seconds"))


class ScopeManager:
    def __init__(self, path):
        self.path = path
        self.scope = []
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            self.scope = []
            return
        with open(self.path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.scope = payload.get("scope", [])

    def save(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump({"scope": self.scope}, handle, indent=2)

    def add(self, value):
        normalized = normalize_target(value)
        if normalized and normalized not in self.scope:
            self.scope.append(normalized)
            self.save()
        return normalized

    def remove(self, value):
        if value in self.scope:
            self.scope.remove(value)
            self.save()

    def is_allowed(self, target):
        host = host_for_target(target)
        return any(host == item or host.endswith("." + item) for item in self.scope)


class ToggleSwitch(tk.Canvas):
    def __init__(self, parent, variable, enabled=True, command=None, width=54, height=28):
        super().__init__(
            parent,
            width=width,
            height=height,
            highlightthickness=0,
            bd=0,
            bg=THEME["panel"],
        )
        self.variable = variable
        self.enabled = enabled
        self.command = command
        self.width = width
        self.height = height
        self.bind("<Button-1>", self._toggle)
        self.bind("<space>", self._toggle)
        self.configure(cursor="hand2" if enabled else "arrow", takefocus=1 if enabled else 0)
        self.variable.trace_add("write", lambda *_: self._draw())
        self._draw()

    def _toggle(self, event=None):
        if not self.enabled:
            return
        self.variable.set(not bool(self.variable.get()))
        if self.command:
            self.command(bool(self.variable.get()))

    def _draw(self):
        self.delete("all")
        active = bool(self.variable.get())
        bg = THEME["accent"] if active else "#31384a"
        knob = THEME["bg"] if active else "#cbd5e1"
        if not self.enabled:
            bg = "#263042" if active else "#1f2533"
            knob = "#64748b"
        radius = self.height // 2
        self.create_oval(1, 1, self.height - 1, self.height - 1, fill=bg, outline=bg)
        self.create_oval(self.width - self.height + 1, 1, self.width - 1, self.height - 1, fill=bg, outline=bg)
        self.create_rectangle(radius, 1, self.width - radius, self.height - 1, fill=bg, outline=bg)
        pad = 4
        knob_size = self.height - pad * 2
        x = self.width - knob_size - pad if active else pad
        self.create_oval(x, pad, x + knob_size, pad + knob_size, fill=knob, outline=knob)


def normalize_target(value):
    value = value.strip().lower()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else "https://" + value)
    return parsed.hostname or value


def host_for_target(value):
    parsed = urlparse(value if "://" in value else "https://" + value)
    return (parsed.hostname or value).strip().lower()


def ensure_url(value):
    return value if "://" in value else "https://" + value


def contains_blocked_intent(text):
    lower = (text or "").lower()
    return any(pattern in lower for pattern in BLOCKED_INTENT_PATTERNS)


def phoenix_config_path(filename):
    root = os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~")
    path = os.path.join(root, "PhoenixGuardian")
    os.makedirs(path, exist_ok=True)
    return os.path.join(path, filename)


def load_local_secret(name):
    try:
        import keyring
        value = keyring.get_password(APP_NAME, name)
        if value:
            return value
    except Exception:
        pass
    path = phoenix_config_path(SECRET_FILE)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload.get(name, "")
    except Exception:
        return ""


def save_local_secret(name, value):
    value = (value or "").strip()
    if not value:
        return False, "No key value was provided."
    try:
        import keyring
        keyring.set_password(APP_NAME, name, value)
        return True, "Saved in the OS keyring."
    except Exception:
        pass
    path = phoenix_config_path(SECRET_FILE)
    payload = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception:
            payload = {}
    payload[name] = value
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return True, f"Saved in local Phoenix config: {path}"


def run_command(args):
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        return completed.stdout.strip() or completed.stderr.strip()
    except FileNotFoundError:
        return f"Command not available: {args[0]}"
    except subprocess.TimeoutExpired:
        return "Command timed out."


def windows_voice_command(timeout=8):
    script = rf"""
Add-Type -AssemblyName System.Speech
$culture = [System.Globalization.CultureInfo]::InstalledUICulture
try {{
    $recognizer = New-Object System.Speech.Recognition.SpeechRecognitionEngine($culture)
}} catch {{
    $recognizer = New-Object System.Speech.Recognition.SpeechRecognitionEngine
}}
$grammar = New-Object System.Speech.Recognition.DictationGrammar
$recognizer.LoadGrammar($grammar)
$recognizer.SetInputToDefaultAudioDevice()
$result = $recognizer.Recognize([TimeSpan]::FromSeconds({int(timeout)}))
if ($result -and $result.Text) {{
    Write-Output $result.Text
    $recognizer.Dispose()
    exit 0
}}
$recognizer.Dispose()
exit 2
"""
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout + 6,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        text = (completed.stdout or "").strip()
        if completed.returncode == 0 and text:
            return text.lower(), ""
        return "", (completed.stderr or completed.stdout or "Windows Speech did not recognize a command.").strip()
    except FileNotFoundError:
        return "", "powershell.exe was not found for Windows Speech fallback."
    except subprocess.TimeoutExpired:
        return "", "Windows Speech fallback timed out."


def voice_dependency_report():
    lines = [
        "Phoenix Guardian Voice Diagnostics",
        f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}",
        "",
    ]
    try:
        import speech_recognition as sr
        lines.append(f"Python SpeechRecognition: installed ({getattr(sr, '__version__', 'unknown version')})")
        try:
            microphones = sr.Microphone.list_microphone_names()
            lines.append(f"Python microphones detected: {len(microphones)}")
            for index, name in enumerate(microphones[:8]):
                lines.append(f"- {index}: {name}")
            if len(microphones) > 8:
                lines.append(f"- ... {len(microphones) - 8} more")
        except Exception as exc:
            lines.append(f"Python microphone check failed: {exc}")
    except ImportError:
        lines.append("Python SpeechRecognition: not installed. Phoenix will use Windows Speech fallback, then typed command fallback.")
    except Exception as exc:
        lines.append(f"Python SpeechRecognition check failed: {exc}")

    powershell = shutil.which("powershell.exe") or shutil.which("pwsh") or ""
    lines.append(f"PowerShell available: {powershell or 'not found'}")
    if powershell:
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", "Add-Type -AssemblyName System.Speech; 'System.Speech OK'"],
                capture_output=True,
                text=True,
                timeout=12,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            result = (completed.stdout or completed.stderr or "").strip()
            lines.append(f"Windows System.Speech: {result or 'no output'}")
        except Exception as exc:
            lines.append(f"Windows System.Speech check failed: {exc}")

    lines.extend([
        "",
        "Fallback order",
        "1. Python SpeechRecognition, when installed and microphone access works.",
        "2. Windows System.Speech through PowerShell.",
        "3. Typed command prompt, so voice controls still work without speech packages.",
    ])
    return "\n".join(lines)


def run_wsl_command(command, distro="kali-linux", timeout=45):
    args = ["wsl.exe", "-d", distro, "--", "bash", "-lc", command]
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        return completed.stdout.strip() or completed.stderr.strip()
    except FileNotFoundError:
        return "wsl.exe was not found. Install WSL2 and Kali first."
    except subprocess.TimeoutExpired:
        return "WSL command timed out."


def open_interactive_kali_terminal(distro="kali-linux"):
    safe_distro = re.sub(r"[^A-Za-z0-9_.-]", "", distro or "kali-linux") or "kali-linux"
    command = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        f"Start-Process PowerShell -ArgumentList '-NoExit','-Command','wsl.exe -d {safe_distro}'",
    ]
    return run_command(command)


def launch_admin_kali_powershell(distro="kali-linux"):
    safe_distro = re.sub(r"[^A-Za-z0-9_.-]", "", distro or "kali-linux") or "kali-linux"
    command = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        f"Start-Process PowerShell -Verb RunAs -ArgumentList '-NoExit','-Command','wsl.exe -d {safe_distro}'",
    ]
    return run_command(command)


def burp_suite_status():
    evidence = []
    checks = [
        "echo '[Kali Burp]'; command -v burpsuite || true",
        "echo '[Java]'; command -v java || true; java -version 2>&1 | head -3 || true",
        "echo '[Burp process]'; pgrep -af 'burp|Burp' || true",
        "echo '[Proxy listener]'; (timeout 2 bash -lc '</dev/tcp/127.0.0.1/8080' && echo '127.0.0.1:8080 open') || echo '127.0.0.1:8080 closed'",
    ]
    evidence.append(run_wsl_command("; ".join(checks), timeout=20))
    proxy_open = "127.0.0.1:8080 open" in evidence[0]
    findings = [Finding(
        target="Burp Suite",
        category="Burp Suite",
        severity="Info" if proxy_open else "Low",
        title="Burp proxy status checked",
        detail="Burp listener appears reachable on 127.0.0.1:8080." if proxy_open else "Burp listener was not reachable on 127.0.0.1:8080.",
        remediation="Start Burp Suite and configure browser/proxy traffic to 127.0.0.1:8080 for authorized manual testing.",
    )]
    return findings, evidence


def launch_burp_suite():
    command = (
        "if command -v burpsuite >/dev/null 2>&1; then "
        "nohup burpsuite >/tmp/phoenix_guardian_burp.log 2>&1 & echo 'Burp Suite launch requested.'; "
        "else echo 'burpsuite command not found in Kali PATH.'; fi"
    )
    return run_wsl_command(command, timeout=10)


def burp_proxy_probe(target):
    safe_url = shlex.quote(ensure_url(target))
    command = (
        "if timeout 2 bash -lc '</dev/tcp/127.0.0.1/8080'; then "
        f"curl -k -I --max-time 15 --proxy http://127.0.0.1:8080 {safe_url}; "
        "else echo 'Burp proxy is not listening on 127.0.0.1:8080.'; fi"
    )
    output = run_wsl_command(command, timeout=25)
    finding = Finding(
        target=target,
        category="Burp Suite",
        severity="Info",
        title="Burp proxy probe completed",
        detail="A header-only request was attempted through Burp's local proxy for manual interception and logging.",
        remediation="Use Burp Proxy/Logger/Repeater to manually validate findings. Keep testing within the program scope.",
    )
    return [finding], [output]


def wifi_monitor_snapshot():
    findings = []
    evidence = []
    networks = run_command(["netsh", "wlan", "show", "networks", "mode=bssid"])
    evidence.append(networks)

    current_ssid = None
    for line in networks.splitlines():
        stripped = line.strip()
        ssid_match = re.match(r"SSID\s+\d+\s+:\s+(.*)", stripped)
        if ssid_match:
            current_ssid = ssid_match.group(1) or "<hidden>"
            continue
        if stripped.lower().startswith("authentication"):
            auth = stripped.split(":", 1)[-1].strip()
            if auth.lower() in {"open", "shared", "wep"}:
                findings.append(Finding(
                    target=current_ssid or "Nearby Wi-Fi",
                    category="Wi-Fi Monitor",
                    severity="High",
                    title=f"Weak nearby Wi-Fi authentication: {auth}",
                    detail="A nearby network appears to use weak or open authentication.",
                    remediation="For owned networks, migrate to WPA2-AES or WPA3. For unknown networks, avoid connecting and document the observation.",
                ))

    if "SSID" not in networks:
        findings.append(Finding(
            target="Local Wi-Fi adapter",
            category="Wi-Fi Monitor",
            severity="Info",
            title="No Wi-Fi scan data returned",
            detail="Windows did not return nearby network data.",
            remediation="Confirm the Wi-Fi adapter is enabled and location/Wi-Fi permissions allow scans.",
        ))

    return findings, evidence


def kali_tool_inventory(distro="kali-linux"):
    checks = []
    for tool in KALI_TOOL_NAMES:
        safe_tool = shlex.quote(tool)
        checks.append(
            f"if command -v {safe_tool} >/dev/null 2>&1; "
            f"then printf '{tool}: installed: '; command -v {safe_tool}; "
            f"else printf '{tool}: missing\\n'; fi"
        )
    header = (
        "echo '[WSL]'; "
        "cat /etc/os-release 2>/dev/null | sed -n 's/^PRETTY_NAME=//p' | tr -d '\"' || true; "
        "printf 'user: '; id -un; "
        "echo; echo '[Kali tools]'; "
    )
    command = header + "; ".join(checks)
    return run_wsl_command(command, distro=distro, timeout=30)


def kali_full_tool_inventory(distro="kali-linux"):
    command = (
        "echo '[Installed command count]'; compgen -c | sort -u | wc -l; "
        "echo; echo '[Security-flavored commands]'; "
        "compgen -c | sort -u | grep -Ei 'burp|zap|nmap|masscan|sql|xss|http|dns|ssl|tls|sub|dir|fuzz|ffuf|gobuster|wfuzz|nikto|nuclei|amass|harvest|searchsploit|msf|metasploit|hydra|hash|john|aircrack|wifite|wps|forensic|volatility|ghidra|radare|binwalk|yara' | head -240"
    )
    return run_wsl_command(command, distro=distro, timeout=30)


def wordlist_catalog(distro="kali-linux"):
    quoted_paths = " ".join(shlex.quote(path) for path in WORDLIST_PATHS)
    command = (
        "echo '[Wordlist roots]'; "
        f"for p in {quoted_paths}; do if [ -d \"$p\" ]; then echo \"$p\"; find \"$p\" -maxdepth 2 -type f "
        "\\( -name '*.txt' -o -name '*.lst' -o -name '*.dic' -o -name '*.gz' \\) "
        "-printf '%p | %k KB\\n' 2>/dev/null | head -120; fi; done; "
        "echo; echo '[Password-list handling policy]'; "
        "echo 'Password lists are cataloged for offline auditing, lab testing, and defensive password-policy review only.'; "
        "echo 'Phoenix Guardian does not use them for credential stuffing, password spraying, or live login attacks.'"
    )
    return run_wsl_command(command, distro=distro, timeout=35)


def fetch_url_text(url, timeout=12, limit=120000):
    request = Request(url, headers={"User-Agent": f"{APP_NAME}/1.0 bug-bounty-osint"})
    with urlopen(request, timeout=timeout) as response:
        body = response.read(limit).decode("utf-8", errors="ignore")
        return response.status, response.headers.get("content-type", ""), body


def web_search(query, max_results=8):
    if contains_blocked_intent(query):
        return [("Blocked request", "", "This search request matched a hard-blocked unsafe intent.")]
    url = "https://duckduckgo.com/html/?" + urlencode({"q": query})
    try:
        status, content_type, body = fetch_url_text(url, timeout=15, limit=250000)
    except Exception as exc:
        return [("Search failed", "", str(exc))]

    results = []
    for match in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', body, re.I | re.S):
        href = html.unescape(match.group(1))
        title = re.sub(r"<.*?>", "", match.group(2), flags=re.S)
        title = html.unescape(re.sub(r"\s+", " ", title)).strip()
        parsed = urlparse(href)
        if "uddg" in parse_qs(parsed.query):
            href = unquote(parse_qs(parsed.query)["uddg"][0])
        if title and href:
            results.append((title, href, "DuckDuckGo result"))
        if len(results) >= max_results:
            break
    if not results:
        results.append(("No parsed results", url, f"Search returned HTTP {status} {content_type}, but no result links were parsed."))
    return results


def web_search_report(query):
    results = web_search(query)
    lines = [f"Web search: {query}", f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}", ""]
    for index, (title, url, snippet) in enumerate(results, start=1):
        lines.append(f"{index}. {title}\n   {url}\n   {snippet}")
    return "\n".join(lines)


def fetch_json_url(url, timeout=18, limit=8000000):
    request = Request(url, headers={"User-Agent": f"{APP_NAME}/1.0 current-vector-intel", "Accept": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        body = response.read(limit).decode("utf-8", errors="ignore")
        return response.status, json.loads(body) if body else {}


def _http_error_detail(exc):
    try:
        body = exc.read().decode("utf-8", errors="ignore")
    except Exception:
        body = ""
    if not body:
        return str(exc)
    try:
        payload = json.loads(body)
        if isinstance(payload, dict):
            error = payload.get("error", payload)
            if isinstance(error, dict):
                message = error.get("message") or error.get("type") or json.dumps(error)[:800]
                code = error.get("code") or error.get("type") or "api_error"
                return f"{code}: {message}"
            return json.dumps(payload)[:1200]
    except json.JSONDecodeError:
        pass
    return body[:1200]


def current_vectors_report(query="", target="", days=14):
    host = host_for_target(target) if target else ""
    topic = " ".join(part for part in [query.strip(), host] if part).strip() or "web application API bug bounty"
    lines = [
        "Phoenix Guardian Current Cyber Vectors",
        f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}",
        f"Topic: {topic}",
        "",
        "Live source status",
    ]
    for label, url in CURRENT_VECTOR_SOURCES:
        lines.append(f"- {label}: {url}")

    lines.extend(["", "CISA Known Exploited Vulnerabilities"])
    try:
        status, kev = fetch_json_url(CISA_KEV_JSON_URL, timeout=20, limit=8000000)
        vulns = kev.get("vulnerabilities", []) if isinstance(kev, dict) else []
        vulns = sorted(vulns, key=lambda item: item.get("dateAdded", ""), reverse=True)[:12]
        lines.append(f"- HTTP {status}; showing {len(vulns)} most recently added entries.")
        for item in vulns:
            lines.append(
                f"- {item.get('cveID', 'CVE-unknown')} | {item.get('vendorProject', 'unknown')} "
                f"{item.get('product', '')} | added {item.get('dateAdded', 'unknown')} | "
                f"due {item.get('dueDate', 'unknown')}"
            )
            name = item.get("vulnerabilityName") or item.get("shortDescription") or ""
            if name:
                lines.append(f"  Focus: {name[:220]}")
    except Exception as exc:
        lines.append(f"- CISA KEV fetch failed: {exc}")

    lines.extend(["", "NVD Recently Published CVEs"])
    try:
        end = dt.datetime.utcnow()
        start = end - dt.timedelta(days=max(1, int(days)))
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": "12",
        }
        if query.strip():
            params["keywordSearch"] = query.strip()[:120]
        status, nvd = fetch_json_url(NVD_CVE_API_URL + "?" + urlencode(params), timeout=25, limit=2400000)
        records = nvd.get("vulnerabilities", []) if isinstance(nvd, dict) else []
        if not records and "keywordSearch" in params:
            fallback_params = dict(params)
            fallback_params.pop("keywordSearch", None)
            status, nvd = fetch_json_url(NVD_CVE_API_URL + "?" + urlencode(fallback_params), timeout=25, limit=2400000)
            records = nvd.get("vulnerabilities", []) if isinstance(nvd, dict) else []
        lines.append(f"- HTTP {status}; showing {len(records)} recent CVE records.")
        for item in records[:12]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "CVE-unknown")
            published = cve.get("published", "unknown")
            descriptions = cve.get("descriptions", [])
            summary = next((entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"), "")
            severity = "unknown"
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
                if metrics.get(key):
                    severity = metrics[key][0].get("cvssData", {}).get("baseSeverity", severity)
                    break
            lines.append(f"- {cve_id} | {severity} | published {published}")
            if summary:
                lines.append(f"  Summary: {summary[:260]}")
    except Exception as exc:
        lines.append(f"- NVD fetch failed: {exc}")

    lines.extend(["", "Bug bounty validation playbooks"])
    for title, vectors, safe_work in BUG_BOUNTY_VECTOR_PLAYBOOKS:
        lines.extend([
            f"- {title}",
            f"  Current vectors to watch: {vectors}",
            f"  Safe validation path: {safe_work}",
        ])

    lines.extend(["", "Public web search"])
    search_query = f"{topic} latest vulnerability bug bounty writeup defensive validation"
    search = web_search_report(search_query)
    lines.append(search[:6000])
    lines.extend([
        "",
        "Professional boundary",
        "- Use this as a current research queue for authorized assets only.",
        "- Phoenix Guardian summarizes vectors, evidence goals, and safe validation paths; it does not run credential theft, rogue access point, exploit delivery, persistence, or destructive tests.",
    ])
    return "\n".join(lines)


def automatic_web_context(user_text, scope):
    scoped = list(scope or [])[:3]
    topic_parts = [user_text.strip()[:160]]
    if scoped:
        topic_parts.append(" ".join(scoped))
    topic = " ".join(part for part in topic_parts if part).strip() or "cybersecurity bug bounty"
    report = current_vectors_report(query=topic[:120], target=scoped[0] if scoped else "", days=14)
    return report[:9000]


def groq_chat_response(api_key, model, user_text, context="", web_context=""):
    api_key = (api_key or "").strip()
    if not api_key:
        return "Missing Groq API key. Set GROQ_API_KEY or paste a GroqCloud key in Settings/Groq Command."
    if api_key.startswith("sk-"):
        return "That looks like an OpenAI key. Groq chat needs a GroqCloud API key, usually starting with gsk_. Rotate any key that was pasted into chat."
    if contains_blocked_intent(user_text):
        return "Blocked: this request asks for theft, bypass, credential attacks, piracy, or unsafe exploitation. I can help reframe it as defensive testing or evidence handling."
    model = (model or GROQ_DEFAULT_MODEL).strip()
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are Phoenix Guardian's Groq-powered professional cybersecurity command assistant. "
                    "Help with authorized bug bounty, defensive testing, reporting, OSINT, and remediation. "
                    "Do not provide credential theft, token grabbing, license piracy, rogue AP attacks, exploit delivery, persistence, stealth, or guardrail bypasses. "
                    "Use the supplied web intelligence as current context. "
                    "When a safe app action would help, end with one line in this exact form: ACTION: none OR ACTION: web_search:<query> OR ACTION: current_vectors OR ACTION: kali_inventory OR ACTION: wordlists OR ACTION: burp_status OR ACTION: bug_bounty_autopilot."
                ),
            },
            {
                "role": "user",
                "content": f"App context:\n{context}\n\nAutomatic web intelligence:\n{web_context}\n\nUser request:\n{user_text}",
            },
        ],
        "temperature": 0.2,
        "max_tokens": 1800,
    }
    request = Request(
        f"{GROQ_API_BASE}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"{APP_NAME}/1.0 (Windows; Python urllib; Groq API client)",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=45) as response:
            body = json.loads(response.read().decode("utf-8", errors="ignore"))
    except HTTPError as exc:
        detail = _http_error_detail(exc)
        if exc.code == 401:
            next_step = "Check that the value is a valid GroqCloud API key and not an OpenAI key."
        elif exc.code == 429:
            next_step = "The Groq project is rate limited or out of quota; wait, reduce frequency, or check Groq billing/limits."
        elif exc.code in {400, 404}:
            next_step = f"Check the model name. Current default is {GROQ_DEFAULT_MODEL}."
        elif exc.code == 403 and "1010" in detail:
            next_step = "Groq's edge rejected the request fingerprint or network path. Phoenix now sends explicit API headers; if this persists, try a different network/VPN state or check security software blocking api.groq.com."
        else:
            next_step = "Review the Groq project permissions, model access, and network path."
        return f"Groq API request failed (HTTP {exc.code}): {detail}\nNext check: {next_step}"
    except URLError as exc:
        return f"Groq API network request failed: {exc}. Confirm this machine can reach api.groq.com."
    except Exception as exc:
        return f"Groq API request failed: {exc}"

    choices = body.get("choices", [])
    if choices:
        message = choices[0].get("message", {})
        content = message.get("content", "")
        if isinstance(content, str) and content.strip():
            return content.strip()
        if isinstance(content, list):
            parts = [item.get("text", "") for item in content if isinstance(item, dict)]
            text = "\n".join(part for part in parts if part).strip()
            if text:
                return text
    return json.dumps(body, indent=2)[:4000]


def hackerone_request(username, token, method, path, payload=None, timeout=30):
    if not username or not token:
        return 0, {"error": "Missing HackerOne API username or token."}
    url = HACKERONE_API_BASE + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    basic = base64.b64encode(f"{username}:{token}".encode("utf-8")).decode("ascii")
    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {basic}",
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            return response.status, json.loads(body) if body else {}
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"error": body or str(exc)}
        return exc.code, parsed
    except Exception as exc:
        return 0, {"error": str(exc)}


def hackerone_program(username, token, handle):
    return hackerone_request(username, token, "GET", f"/hackers/programs/{handle}")


def hackerone_structured_scopes(username, token, handle, max_pages=5):
    all_scopes = []
    page = 1
    last_status = 0
    last_payload = {}
    while page <= max_pages:
        path = f"/hackers/programs/{handle}/structured_scopes?" + urlencode({"page[number]": page, "page[size]": 100})
        status, payload = hackerone_request(username, token, "GET", path)
        last_status, last_payload = status, payload
        if status < 200 or status >= 300:
            break
        batch = payload.get("data", [])
        all_scopes.extend(batch)
        if not payload.get("links", {}).get("next") or not batch:
            break
        page += 1
    return last_status, {"data": all_scopes, "last_response": last_payload}


def hackerone_create_report_intent(username, token, team_handle, description):
    payload = {
        "data": {
            "type": "report-intent",
            "attributes": {
                "team_handle": team_handle,
                "description": description,
            },
        }
    }
    return hackerone_request(username, token, "POST", "/hackers/report_intents", payload=payload, timeout=45)


def hackerone_get_report_intent(username, token, intent_id):
    return hackerone_request(username, token, "GET", f"/hackers/report_intents/{intent_id}")


def hackerone_submit_report_intent(username, token, intent_id):
    return hackerone_request(username, token, "POST", f"/hackers/report_intents/{intent_id}/submit", timeout=45)


def scope_asset_to_target(scope_item):
    attrs = scope_item.get("attributes", {})
    asset = attrs.get("asset_identifier", "")
    if not asset:
        return ""
    if attrs.get("asset_type", "").lower() in {"url", "api"}:
        return asset
    return host_for_target(asset.replace("*.", ""))


def parse_scope_text(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    entries = []
    current = None
    for line in lines:
        if line.startswith("Environment:"):
            if current is not None:
                current["environment"] = line.split(":", 1)[1].strip()
            continue
        if line in {"Domain", "Wildcard", "Other", "Source code"}:
            if current is not None:
                current["asset_type"] = line
            continue
        if line in {"Critical", "High", "Medium", "Low", "None"}:
            if current is not None:
                current["max_severity"] = line
            continue
        if line in {"Eligible", "Ineligible"}:
            if current is not None:
                current["eligible"] = line == "Eligible"
            continue
        if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2},\s+\d{4}$", line):
            if current is not None:
                current["updated"] = line
            continue
        if re.match(r"^\d+\s+\(\d+%\)$", line):
            if current is not None:
                current["report_count"] = line
            continue

        looks_like_asset = (
            "." in line
            or line.startswith("https://")
            or line.startswith("Android:")
            or line.startswith("iOS:")
            or line in {"Authentication & ATO", "Other", "Shopify Mobile Applications", "Shopify Third Party Store", "Shopify Third Party Apps", "Shopify Developed Apps"}
        )
        if current is not None and "asset_type" not in current:
            current.setdefault("notes", []).append(line)
        elif looks_like_asset:
            if current is not None:
                entries.append(current)
            current = {"asset_identifier": line, "notes": []}
        elif current is not None:
            current.setdefault("notes", []).append(line)
    if current is not None:
        entries.append(current)
    return entries


def imported_scope_summary(entries):
    eligible = [item for item in entries if item.get("eligible")]
    bounty = [item for item in eligible if item.get("max_severity") not in {"None", None}]
    lines = [
        "Imported Scope Summary",
        f"Total parsed entries: {len(entries)}",
        f"Eligible entries: {len(eligible)}",
        f"Potential bounty-relevant entries: {len(bounty)}",
        "",
        "Top eligible assets:",
    ]
    for item in eligible[:40]:
        lines.append(
            f"- {item.get('asset_identifier')} | type={item.get('asset_type', 'unknown')} | "
            f"severity={item.get('max_severity', 'unknown')} | env={item.get('environment', 'unknown')}"
        )
        if item.get("notes"):
            lines.append(f"  Note: {' '.join(item['notes'])[:220]}")
    return "\n".join(lines)


def hackerone_policy_summary(program_payload, scopes_payload):
    data = program_payload.get("data", {})
    attrs = data.get("attributes", {})
    scopes = scopes_payload.get("data", [])
    eligible = [item for item in scopes if item.get("attributes", {}).get("eligible_for_submission")]
    bounty = [item for item in eligible if item.get("attributes", {}).get("eligible_for_bounty")]
    lines = [
        "HackerOne Program Readiness",
        f"Program: {attrs.get('name') or data.get('id') or 'unknown'}",
        f"Submission state: {attrs.get('submission_state', 'unknown')}",
        f"Offers bounties: {attrs.get('offers_bounties', 'unknown')}",
        f"Fast payments: {attrs.get('fast_payments', 'unknown')}",
        f"Safe harbor: {attrs.get('gold_standard_safe_harbor', 'unknown')}",
        f"Eligible scopes fetched: {len(eligible)}",
        f"Bounty-eligible scopes fetched: {len(bounty)}",
        "",
        "Policy excerpt:",
        str(attrs.get("policy", "No policy text returned."))[:5000],
        "",
        "Top eligible scope assets:",
    ]
    for item in eligible[:25]:
        item_attrs = item.get("attributes", {})
        lines.append(
            f"- {item_attrs.get('asset_identifier')} | type={item_attrs.get('asset_type')} | "
            f"bounty={item_attrs.get('eligible_for_bounty')} | max={item_attrs.get('max_severity')} | "
            f"note={item_attrs.get('instruction', '')[:160]}"
        )
    return "\n".join(lines)


def online_osint(target):
    host = host_for_target(target)
    base_url = ensure_url(host)
    findings = []
    evidence = []
    checks = [
        ("security.txt", f"https://{host}/.well-known/security.txt"),
        ("robots.txt", f"https://{host}/robots.txt"),
        ("sitemap.xml", f"https://{host}/sitemap.xml"),
        ("crt.sh certificates", f"https://crt.sh/?q=%25.{host}&output=json"),
    ]
    for label, url in checks:
        try:
            status, content_type, body = fetch_url_text(url)
            evidence.append(f"=== {label}: HTTP {status} {content_type} ===\n{body[:6000]}")
            if label == "security.txt" and status == 200:
                findings.append(Finding(
                    target=host,
                    category="Online OSINT",
                    severity="Info",
                    title="security.txt discovered",
                    detail="The target publishes a security.txt file that may include disclosure contacts and policy details.",
                    remediation="Use the published disclosure process and program policy before testing.",
                ))
            if label == "crt.sh certificates" and status == 200 and host in body.lower():
                findings.append(Finding(
                    target=host,
                    category="Online OSINT",
                    severity="Info",
                    title="Certificate transparency data collected",
                    detail="Certificate transparency records were collected to support subdomain and asset review.",
                    remediation="Confirm each discovered asset is in program scope before testing.",
                ))
        except Exception as exc:
            evidence.append(f"=== {label} failed ===\n{url}\n{exc}")

    try:
        parsed = urlparse(base_url)
        ip = socket.gethostbyname(parsed.hostname or host)
        evidence.append(f"=== DNS resolution ===\n{host} -> {ip}")
    except Exception as exc:
        evidence.append(f"=== DNS resolution failed ===\n{exc}")

    findings.append(Finding(
        target=host,
        category="Online OSINT",
        severity="Info",
        title="Online OSINT sweep completed",
        detail="Collected public security contacts, robots/sitemap hints, certificate transparency data, and DNS resolution for scope review.",
        remediation="Use OSINT only to confirm scope and prioritize authorized tests. Do not test assets outside the bug bounty policy.",
    ))
    return findings, evidence


def kali_drone_task(task, target, distro="kali-linux"):
    safe_target = shlex.quote(host_for_target(target))
    safe_url = shlex.quote(ensure_url(target))
    safe_domain = safe_target
    if task == "Recon Drone":
        command = f"set -o pipefail; echo '[DNS]'; getent hosts {safe_target} || true; echo; echo '[HTTP headers]'; curl -I --max-time 12 {safe_url} || true"
    elif task == "Port Posture Drone":
        command = f"nmap -Pn -T2 --top-ports 50 --reason {safe_target}"
    elif task == "Web Fingerprint Drone":
        command = f"if command -v whatweb >/dev/null 2>&1; then whatweb --no-errors --color=never {safe_url}; else curl -I --max-time 12 {safe_url}; fi"
    elif task in {"TLS Drone", "TLS Certificate Drone"}:
        command = f"echo | openssl s_client -connect {safe_target}:443 -servername {safe_target} 2>/dev/null | openssl x509 -noout -issuer -subject -dates"
    elif task == "DNS Records Drone":
        command = f"echo '[host]'; host {safe_domain} || true; echo; echo '[dig]'; if command -v dig >/dev/null 2>&1; then dig +short A {safe_domain}; dig +short AAAA {safe_domain}; dig +short MX {safe_domain}; dig +short TXT {safe_domain}; fi"
    elif task == "WHOIS Drone":
        command = f"if command -v whois >/dev/null 2>&1; then whois {safe_domain} | head -120; else echo 'whois missing'; fi"
    elif task == "WAF Fingerprint Drone":
        command = f"if command -v wafw00f >/dev/null 2>&1; then wafw00f -a {safe_url}; else echo 'wafw00f missing'; fi"
    elif task == "SSL Scan Drone":
        command = f"if command -v sslscan >/dev/null 2>&1; then sslscan --no-failed {safe_target}:443; elif command -v testssl.sh >/dev/null 2>&1; then testssl.sh --fast --warnings batch {safe_url}; else echo 'sslscan/testssl.sh missing'; fi"
    elif task == "HTTP Probe Drone":
        command = f"if command -v httpx >/dev/null 2>&1; then printf '%s\\n' {safe_url} | httpx -title -status-code -tech-detect -follow-host-redirects -silent; else curl -I --max-time 12 {safe_url}; fi"
    elif task == "Content Baseline Drone":
        wordlist = "/tmp/phoenix_guardian_content_words.txt"
        command = f"printf 'robots.txt\\nsitemap.xml\\nsecurity.txt\\.well-known/security.txt\\nlogin\\nadmin\\napi\\nhealth\\nstatus\\n' > {wordlist}; if command -v ffuf >/dev/null 2>&1; then ffuf -w {wordlist} -u {safe_url.rstrip('/')}/FUZZ -rate 5 -t 2 -mc all -of csv 2>/dev/null | head -40; elif command -v gobuster >/dev/null 2>&1; then gobuster dir -q -t 2 -w {wordlist} -u {safe_url}; else echo 'ffuf/gobuster missing'; fi; rm -f {wordlist}"
    elif task == "Subdomain Passive Drone":
        command = f"if command -v subfinder >/dev/null 2>&1; then subfinder -silent -all -d {safe_domain} | head -100; elif command -v amass >/dev/null 2>&1; then amass enum -passive -d {safe_domain} | head -100; else echo 'subfinder/amass missing'; fi"
    elif task == "Nikto Headers Drone":
        command = f"if command -v nikto >/dev/null 2>&1; then nikto -nointeractive -Tuning b -host {safe_url}; else echo 'nikto missing'; fi"
    elif task == "Burp Proxy Drone":
        findings, evidence = burp_proxy_probe(target)
        return "\n".join(evidence)
    elif task == "Online OSINT Drone":
        findings, evidence = online_osint(target)
        return "\n\n".join(evidence)
    elif task == "Wordlist Catalog Drone":
        return wordlist_catalog(distro=distro)
    elif task == "Bug Bounty Autopilot":
        findings, evidence = bug_bounty_autopilot(target, distro=distro)
        return "\n\n".join(evidence)
    else:
        return "Unknown drone task."
    return run_wsl_command(command, distro=distro, timeout=60)


def cybersecurity_drone(target, distro="kali-linux"):
    findings = []
    evidence = []
    task_plan = [
        "Recon Drone",
        "DNS Records Drone",
        "Web Fingerprint Drone",
        "TLS Certificate Drone",
        "HTTP Probe Drone",
        "WAF Fingerprint Drone",
        "Content Baseline Drone",
    ]
    for task in task_plan:
        evidence.append(f"=== {task} ===\n{kali_drone_task(task, target, distro=distro)}")

    web_findings, web_evidence = web_audit(target)
    val_findings, val_evidence = offensive_validation(target)
    findings.extend(web_findings)
    findings.extend(val_findings)
    evidence.append("=== Web Audit ===\n" + "\n".join(web_evidence))
    evidence.append("=== Harmless Validation ===\n" + "\n".join(val_evidence))
    findings.append(Finding(
        target=target,
        category="Cybersecurity Drone",
        severity="Info",
        title="Cybersecurity attack-path exploration completed",
        detail="Safe reconnaissance and harmless validation were run against an allowlisted target to map exposed services, web headers, TLS posture, WAF signals, and baseline content paths.",
        remediation="Use the evidence to harden exposed services. Do not convert these leads into exploitation unless you have explicit written authorization and a controlled test plan.",
    ))
    return findings, evidence


def monetary_estimate(findings):
    counts = Counter(item.severity for item in findings)
    if counts.get("High", 0):
        bounty = "$1,000-$7,500+ depending on program scope and validated impact"
        remediation = "$2,500-$25,000+ for engineering, validation, and retesting"
        exposure = "High-severity findings may affect revenue, customer trust, fraud losses, compliance posture, or incident-response cost."
    elif counts.get("Medium", 0):
        bounty = "$250-$2,500 depending on duplicate status and program policy"
        remediation = "$750-$7,500 for configuration, code fix, testing, and deployment"
        exposure = "Medium findings can still create meaningful business risk when chained or left unpatched."
    elif counts.get("Low", 0):
        bounty = "$50-$500 or informational depending on program policy"
        remediation = "$250-$2,000 for hardening and verification"
        exposure = "Low findings are useful hygiene signals and can reduce future attack surface."
    else:
        bounty = "Informational; payout unlikely unless program rewards high-quality reconnaissance."
        remediation = "$0-$1,000 for documentation, scope review, or configuration cleanup"
        exposure = "No concrete monetary exposure is established yet."
    return {
        "bounty_band": bounty,
        "remediation_cost": remediation,
        "exposure_note": exposure,
    }


def vulnerability_checklist_text():
    lines = [
        "Bug bounty vulnerability checklist",
        "Use this as a professional test plan. Confirm program scope, authorization, rate limits, and prohibited techniques before testing.",
        "",
    ]
    for index, name in enumerate(VULNERABILITY_TAXONOMY, start=1):
        safe_method = "Review manually, use harmless canaries where applicable, and preserve evidence without accessing other users' data."
        if any(token in name for token in ("Brute Force", "SSRF", "Command Injection", "Code Injection", "XXE", "Request Smuggling")):
            safe_method = "Plan only or test in an explicit lab/authorized environment; avoid destructive payloads, internal scanning, credential attacks, or exploit delivery."
        if any(token in name for token in ("IDOR", "BOLA", "BFLA", "Privilege", "Access Control")):
            safe_method = "Use only accounts and data you own or that the program explicitly provides for testing."
        lines.append(f"{index}. {name}\n   Safe testing note: {safe_method}")
    return "\n".join(lines)


def bug_bounty_report(target, findings, evidence):
    rank = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    ordered = sorted(findings, key=lambda item: rank.get(item.severity, 99))
    money = monetary_estimate(findings)
    top = ordered[0] if ordered else None
    lines = [
        "Phoenix Guardian Bug Bounty Report Draft",
        f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}",
        f"Target: {target}",
        "",
        "Ready-to-submit report",
        f"Title: {top.title + ' on ' + top.target if top else 'Security posture review for ' + target}",
        "",
        "Summary:",
        (f"Phoenix Guardian observed {top.title.lower()} affecting {top.target}. {top.detail}" if top else f"Phoenix Guardian completed an authorized review of {target} and did not identify a high-confidence reportable issue yet."),
        "",
        "Business / monetary impact:",
        f"- Estimated bounty band: {money['bounty_band']}",
        f"- Estimated remediation effort: {money['remediation_cost']}",
        f"- Estimated exposure note: {money['exposure_note']}",
        "- These numbers are planning estimates, not a demand or guarantee of payout.",
        "",
        "Steps to reproduce:",
        "1. Confirm the target asset is in the bug bounty program scope.",
        "2. Run Phoenix Guardian Bug Bounty Autopilot against the exact target.",
        "3. Review the Evidence Index below and attach only the relevant non-sensitive excerpts.",
        "4. Reproduce manually with Burp, browser developer tools, or safe header-only/canary checks.",
        "5. Stop if testing would require credentials, destructive actions, exploit payloads, or access to data that is not yours.",
        "",
        "Expected result:",
        "- The application should enforce secure defaults, disclose minimal metadata, validate redirects and reflected input safely, and expose only intended public assets.",
        "",
        "Actual result:",
        (f"- {top.detail}" if top else "- No concrete vulnerable behavior has been manually confirmed yet."),
        "",
        "Recommended remediation:",
        (f"- {top.remediation}" if top else "- Continue hardening headers, cookies, TLS, asset inventory, and disclosure workflow."),
        "",
        "Scope and authorization",
        "- Test only assets explicitly allowed by the target's bug bounty policy.",
        "- Do not perform credential attacks, destructive testing, persistence, stealth, data exfiltration, or exploit chaining without written authorization.",
        "- Burp, Kali, OSINT, and wordlist discovery are used for evidence collection and defensive validation.",
        "",
        "Vulnerability classes considered",
    ]
    lines.extend(f"- {item}" for item in VULNERABILITY_TAXONOMY)
    lines.extend([
        "",
        "Top findings",
    ])
    if ordered:
        for item in ordered[:12]:
            lines.extend([
                f"- [{item.severity}] {item.title}",
                f"  Target: {item.target}",
                f"  Impact: {item.detail}",
                f"  Remediation: {item.remediation}",
            ])
    else:
        lines.append("- No reportable findings generated yet.")
    lines.extend([
        "",
        "Suggested submission structure",
        "- Summary: copy the Summary section above and tighten it to the confirmed issue.",
        "- Impact: use the Business / monetary impact section, then adjust based on program severity rules.",
        "- Steps to reproduce: keep the safe reproduction steps and remove anything not used.",
        "- Evidence: include headers, screenshots, timestamps, and tool output excerpts with secrets redacted.",
        "- Remediation: propose a practical fix and reference vendor documentation where useful.",
        "",
        "Evidence index",
    ])
    for index, item in enumerate(evidence[:20], start=1):
        header = item.splitlines()[0] if item else "Evidence"
        lines.append(f"- E{index}: {header[:120]}")
    return "\n".join(lines)


def bug_bounty_autopilot(target, distro="kali-linux"):
    findings = []
    evidence = []

    inventory = kali_tool_inventory(distro=distro)
    full_inventory = kali_full_tool_inventory(distro=distro)
    wordlists = wordlist_catalog(distro=distro)
    burp_findings, burp_evidence = burp_suite_status()
    osint_findings, osint_evidence = online_osint(target)
    cyber_findings, cyber_evidence = cybersecurity_drone(target, distro=distro)
    vector_report = current_vectors_report(query=f"{host_for_target(target)} bug bounty web api", target=target, days=14)

    findings.extend(burp_findings)
    findings.extend(osint_findings)
    findings.extend(cyber_findings)
    evidence.extend([
        "=== Curated Kali inventory ===\n" + inventory,
        "=== Broad cybersecurity tool inventory ===\n" + full_inventory,
        "=== Wordlist and password-list catalog ===\n" + wordlists,
        "=== Current cyber vectors ===\n" + vector_report,
    ])
    evidence.extend(burp_evidence)
    evidence.extend(osint_evidence)
    evidence.extend(cyber_evidence)
    evidence.append("=== Bug bounty report draft ===\n" + bug_bounty_report(target, findings, evidence))
    findings.append(Finding(
        target=target,
        category="Bug Bounty",
        severity="Info",
        title="Bug bounty autopilot completed",
        detail="Collected scoped OSINT, Burp status, Kali inventory, wordlist catalog, safe attack-path evidence, and a report draft.",
        remediation="Review the evidence manually, remove out-of-scope assets, and submit only validated, policy-compliant findings.",
    ))
    return findings, evidence


def defensive_response_drone(target="", fraud_path=""):
    findings = []
    evidence = []

    wifi_findings, wifi_evidence = wifi_audit()
    wps_findings, wps_evidence = wps_defense_review()
    device_findings, device_evidence = device_defensive_posture()
    findings.extend(wifi_findings)
    findings.extend(wps_findings)
    findings.extend(device_findings)
    evidence.append("=== Wi-Fi posture ===\n" + "\n".join(wifi_evidence))
    evidence.append("=== Wi-Fi/WPS review ===\n" + "\n".join(wps_evidence))
    evidence.append("=== Device invasion posture ===\n" + "\n\n".join(device_evidence))

    if fraud_path and os.path.exists(fraud_path):
        fraud_findings, fraud_evidence, fraud_report = fraud_forensic_analysis(fraud_path)
        findings.extend(fraud_findings)
        evidence.append("=== Card theft/fraud trail ===\n" + "\n".join(fraud_evidence))
        evidence.append("=== Evidence handoff report ===\n" + fraud_report)
    else:
        findings.append(Finding(
            target="Card fraud evidence",
            category="Defensive Response Drone",
            severity="Info",
            title="No card transaction dataset selected",
            detail="The defensive drone could not build a stolen-card trail because no transaction CSV is selected.",
            remediation="Use Card Fraud Lab to select an authorized debit/credit transaction export, then rerun the Defensive Response Drone.",
        ))

    if target:
        web_findings, web_evidence = web_audit(target)
        findings.extend(web_findings)
        evidence.append(f"=== Defensive web posture: {target} ===\n" + "\n".join(web_evidence))

    findings.append(Finding(
        target=target or "Local defensive posture",
        category="Defensive Response Drone",
        severity="Info",
        title="Defensive response sweep completed",
        detail="Combined card-fraud evidence, Wi-Fi/WPS posture, and local device-invasion indicators into one defensive case trail.",
        remediation="Preserve evidence, isolate affected devices if compromise is suspected, rotate credentials from a known-clean device, contact issuer/processor for card abuse, and involve police through lawful reporting channels.",
    ))
    return findings, evidence


def web_audit(target):
    url = ensure_url(target.strip())
    parsed = urlparse(url)
    host = parsed.hostname
    findings = []
    evidence = []

    request = Request(url, headers={"User-Agent": f"{APP_NAME}/1.0 authorized-audit"})
    try:
        with urlopen(request, timeout=15) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            evidence.append(f"HTTP status: {response.status}")
            evidence.append(f"Server: {headers.get('server', 'not disclosed')}")

            for header, purpose in SECURITY_HEADERS.items():
                if header not in headers:
                    findings.append(Finding(
                        target=url,
                        category="Web",
                        severity="Medium" if header in {"content-security-policy", "strict-transport-security"} else "Low",
                        title=f"Missing {header}",
                        detail=f"The response did not include {header}. {purpose}",
                        remediation=f"Configure {header} according to the application's risk profile.",
                    ))

            cookies = response.headers.get_all("Set-Cookie") or []
            for cookie in cookies:
                lower = cookie.lower()
                name = cookie.split("=", 1)[0]
                if "secure" not in lower:
                    findings.append(Finding(
                        target=url,
                        category="Web",
                        severity="Medium",
                        title=f"Cookie missing Secure: {name}",
                        detail="A cookie was set without the Secure attribute.",
                        remediation="Set Secure on cookies that should only be sent over HTTPS.",
                    ))
                if "httponly" not in lower:
                    findings.append(Finding(
                        target=url,
                        category="Web",
                        severity="Low",
                        title=f"Cookie missing HttpOnly: {name}",
                        detail="A cookie was set without the HttpOnly attribute.",
                        remediation="Set HttpOnly on cookies that do not need JavaScript access.",
                    ))
                if "samesite" not in lower:
                    findings.append(Finding(
                        target=url,
                        category="Web",
                        severity="Low",
                        title=f"Cookie missing SameSite: {name}",
                        detail="A cookie was set without an explicit SameSite attribute.",
                        remediation="Set SameSite=Lax or SameSite=Strict where compatible.",
                    ))
    except Exception as exc:
        findings.append(Finding(
            target=url,
            category="Web",
            severity="Info",
            title="Request failed",
            detail=str(exc),
            remediation="Confirm the target is reachable and in scope.",
        ))

    if host:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    expires = cert.get("notAfter", "unknown")
                    evidence.append(f"TLS certificate expires: {expires}")
        except Exception as exc:
            evidence.append(f"TLS check failed: {exc}")

    return findings, evidence


def offensive_validation(target):
    url = ensure_url(target.strip())
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    canary = "phoenix_guardian_canary_2026"
    findings = []
    evidence = []

    probes = [
        ("Reflection canary", {"q": canary}),
        ("Open redirect canary", {"next": f"https://example.invalid/{canary}"}),
    ]

    for name, params in probes:
        probe_url = f"{base}?{urlencode(params)}"
        request = Request(probe_url, headers={"User-Agent": f"{APP_NAME}/1.0 authorized-validation"})
        try:
            with urlopen(request, timeout=12) as response:
                body = response.read(120000).decode("utf-8", errors="ignore")
                location = response.headers.get("Location", "")
                evidence.append(f"{name}: HTTP {response.status} {probe_url}")

                if canary in body:
                    findings.append(Finding(
                        target=probe_url,
                        category="Offensive Validation",
                        severity="Low",
                        title="Input reflection observed",
                        detail="A harmless canary value was reflected in the response body. This is not a vulnerability by itself, but it marks a useful manual review point for output encoding.",
                        remediation="Confirm reflected values are contextually encoded and protected by a restrictive Content Security Policy.",
                    ))

                if canary in location or "example.invalid" in location:
                    findings.append(Finding(
                        target=probe_url,
                        category="Offensive Validation",
                        severity="Medium",
                        title="Redirect parameter may be controllable",
                        detail="A harmless redirect canary appeared in the Location header.",
                        remediation="Allow only relative redirects or validate redirects against a strict trusted-domain allowlist.",
                    ))
        except Exception as exc:
            evidence.append(f"{name}: {exc}")

    return findings, evidence


def wifi_audit():
    findings = []
    evidence = []
    interfaces = run_command(["netsh", "wlan", "show", "interfaces"])
    profiles = run_command(["netsh", "wlan", "show", "profiles"])
    evidence.extend(["=== Interfaces ===", interfaces, "", "=== Saved Profiles ===", profiles])

    if "Authentication" in interfaces and "WPA2" not in interfaces and "WPA3" not in interfaces:
        findings.append(Finding(
            target="Local Wi-Fi",
            category="Wi-Fi Defense",
            severity="High",
            title="Weak active Wi-Fi authentication may be in use",
            detail="The active interface output did not show WPA2 or WPA3.",
            remediation="Use WPA2-Personal AES or WPA3-Personal with a strong passphrase.",
        ))

    if "All User Profile" in profiles:
        findings.append(Finding(
            target="Local Wi-Fi",
            category="Wi-Fi Defense",
            severity="Info",
            title="Saved Wi-Fi profiles found",
            detail="Windows has saved Wi-Fi profiles. Review and remove stale networks.",
            remediation="Run Windows Wi-Fi settings cleanup for networks you no longer trust.",
        ))

    return findings, evidence


def device_defensive_posture():
    findings = []
    evidence = []
    commands = [
        ("Identity", ["whoami"]),
        ("Hostname", ["hostname"]),
        ("Listening ports", ["netstat", "-ano"]),
        ("Local administrators", ["net", "localgroup", "administrators"]),
        ("Scheduled tasks", ["schtasks", "/query", "/fo", "LIST", "/v"]),
        ("Windows Defender services", ["powershell.exe", "-NoProfile", "-Command", "Get-Service WinDefend,SecurityHealthService -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String"]),
        ("Firewall profiles", ["powershell.exe", "-NoProfile", "-Command", "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize | Out-String"]),
        ("Recent failed logons", ["powershell.exe", "-NoProfile", "-Command", "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 8 -ErrorAction SilentlyContinue | Select-Object TimeCreated,ProviderName,Id,Message | Format-List | Out-String"]),
    ]
    for label, args in commands:
        output = run_command(args)
        evidence.append(f"=== {label} ===\n{output[:8000]}")

    netstat_output = next((item for item in evidence if item.startswith("=== Listening ports ===")), "")
    if ":3389" in netstat_output and "LISTENING" in netstat_output:
        findings.append(Finding(
            target="Local device",
            category="Device Defense",
            severity="Medium",
            title="Remote Desktop listener observed",
            detail="Port 3389 appears to be listening. Exposed or weakly protected RDP can be abused during device invasions.",
            remediation="Disable RDP if not needed. If needed, require VPN, strong MFA, account lockout, and review Security event logs for failed logons.",
        ))
    listening_count = netstat_output.count("LISTENING")
    if listening_count >= 25:
        findings.append(Finding(
            target="Local device",
            category="Device Defense",
            severity="Low",
            title="Large number of listening services",
            detail=f"Observed approximately {listening_count} listening sockets in netstat output.",
            remediation="Review listening services, disable unneeded services, and confirm each exposed port has a business reason.",
        ))

    defender_output = next((item for item in evidence if item.startswith("=== Windows Defender services ===")), "").lower()
    if "stopped" in defender_output:
        findings.append(Finding(
            target="Local device",
            category="Device Defense",
            severity="High",
            title="Windows Defender-related service may be stopped",
            detail="One or more Windows Defender/Security Health services appears stopped or unavailable.",
            remediation="Open Windows Security, restore protections, run an offline scan, and preserve logs if compromise is suspected.",
        ))

    firewall_output = next((item for item in evidence if item.startswith("=== Firewall profiles ===")), "").lower()
    if "false" in firewall_output:
        findings.append(Finding(
            target="Local device",
            category="Device Defense",
            severity="High",
            title="A Windows Firewall profile may be disabled",
            detail="The firewall profile summary includes a disabled profile.",
            remediation="Enable all firewall profiles unless a documented control replaces them.",
        ))

    return findings, evidence


def wps_defense_review():
    findings, evidence = wifi_monitor_snapshot()
    joined = "\n".join(evidence).lower()
    if "wps" in joined:
        findings.append(Finding(
            target="Nearby Wi-Fi",
            category="Wi-Fi WPS Defense",
            severity="Medium",
            title="WPS indicator observed in Wi-Fi metadata",
            detail="Windows-visible Wi-Fi metadata included WPS-related text. WPS PIN mode can weaken router security when enabled.",
            remediation="For owned routers, disable WPS PIN/push-button pairing, use WPA2-AES or WPA3, and rotate the Wi-Fi passphrase if abuse is suspected.",
        ))
    else:
        findings.append(Finding(
            target="Nearby Wi-Fi",
            category="Wi-Fi WPS Defense",
            severity="Info",
            title="No WPS indicator observed in passive snapshot",
            detail="The passive Windows Wi-Fi snapshot did not expose WPS metadata. Some adapters/drivers do not report WPS state.",
            remediation="Verify WPS is disabled directly in your router admin panel. Do not run WPS brute-force tools against networks you do not own.",
        ))
    return findings, evidence


def ai_summary(findings):
    if not findings:
        return "No findings recorded yet."

    rank = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    by_severity = {}
    for item in findings:
        by_severity[item.severity] = by_severity.get(item.severity, 0) + 1

    ordered = ", ".join(f"{key}: {value}" for key, value in sorted(by_severity.items()))
    top = sorted(findings, key=lambda f: rank.get(f.severity, 99))[0]
    return (
        f"Finding count by severity: {ordered}\n\n"
        f"Highest priority: {top.title}\n"
        f"Why it matters: {top.detail}\n"
        f"Suggested fix: {top.remediation}\n\n"
        "Bug bounty report draft:\n"
        f"Title: {top.title} on {top.target}\n"
        f"Impact: {top.detail}\n"
        f"Remediation: {top.remediation}"
    )


def predictive_threat_model(findings):
    if not findings:
        return "No telemetry yet. Run web, Wi-Fi, or authorized validation checks to build a threat forecast."

    score = min(100, sum(SEVERITY_POINTS.get(item.severity, 1) for item in findings))
    categories = {}
    for item in findings:
        categories[item.category] = categories.get(item.category, 0) + 1

    likely_paths = []
    titles = " ".join(item.title.lower() for item in findings)
    if "content-security-policy" in titles or "input reflection" in titles:
        likely_paths.append("Client-side injection review should be prioritized.")
    if "cookie missing" in titles:
        likely_paths.append("Session handling and cookie hardening are likely weak points.")
    if "strict-transport-security" in titles or "tls" in titles:
        likely_paths.append("Transport downgrade and certificate hygiene deserve review.")
    if "wi-fi" in " ".join(item.category.lower() for item in findings):
        likely_paths.append("Local network exposure and stale trusted Wi-Fi profiles may increase device risk.")
    if "card fraud" in " ".join(item.category.lower() for item in findings):
        likely_paths.append("Payment abuse signals should be packaged for issuer, processor, merchant-security, and police handoff.")
    if "device defense" in " ".join(item.category.lower() for item in findings):
        likely_paths.append("Local device invasion posture needs review for exposed services, firewall status, and endpoint protection.")
    if not likely_paths:
        likely_paths.append("Current signals are low confidence. Collect more evidence before prioritizing fixes.")

    category_text = ", ".join(f"{name}: {count}" for name, count in sorted(categories.items()))
    path_text = "\n".join(f"- {path}" for path in likely_paths)
    return (
        f"Predicted risk score: {score}/100\n"
        f"Signal categories: {category_text}\n\n"
        f"Likely threat paths:\n{path_text}\n\n"
        "Recommended defensive move: fix High and Medium findings first, then retest the exact same scoped target."
    )


FRAUD_COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date", "created_at", "transaction_time", "txn_time"],
    "transaction_id": ["transaction_id", "txn_id", "id", "auth_id", "authorization_id"],
    "card": ["card_id", "card", "pan_token", "account_token", "payment_token", "masked_pan", "last4"],
    "amount": ["amount", "transaction_amount", "amt", "total", "value"],
    "merchant": ["merchant", "merchant_name", "merchant_id", "mid"],
    "terminal": ["terminal", "terminal_id", "tid", "pos_id", "atm_id"],
    "device": ["device", "device_id", "fingerprint", "device_fingerprint"],
    "ip": ["ip", "ip_address", "client_ip", "source_ip"],
    "location": ["location", "city", "region", "country", "merchant_location"],
    "entry_mode": ["entry_mode", "pos_entry_mode", "channel", "card_present"],
    "pin_result": ["pin_result", "pin_status", "pin", "pin_verified", "cvv_result"],
    "status": ["status", "result", "response", "approved", "decline_reason", "auth_result"],
}


def normalize_header(value):
    return re.sub(r"[^a-z0-9]+", "_", (value or "").strip().lower()).strip("_")


def detect_fraud_columns(fieldnames):
    normalized = {normalize_header(name): name for name in (fieldnames or [])}
    detected = {}
    for logical, aliases in FRAUD_COLUMN_ALIASES.items():
        for alias in aliases:
            key = normalize_header(alias)
            if key in normalized:
                detected[logical] = normalized[key]
                break
    return detected


def get_cell(row, columns, logical, default=""):
    column = columns.get(logical)
    if not column:
        return default
    return str(row.get(column, default) or default).strip()


def parse_amount(value):
    cleaned = re.sub(r"[^0-9.\-]", "", str(value or ""))
    try:
        return float(cleaned) if cleaned not in {"", ".", "-", "-."} else 0.0
    except ValueError:
        return 0.0


def parse_transaction_time(value):
    text = str(value or "").strip()
    if not text:
        return None
    candidates = [
        text,
        text.replace("Z", "+00:00"),
    ]
    for candidate in candidates:
        try:
            return dt.datetime.fromisoformat(candidate)
        except ValueError:
            pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(text, fmt)
        except ValueError:
            pass
    return None


def is_declined(value):
    text = str(value or "").strip().lower()
    return any(token in text for token in ("declin", "denied", "fail", "rejected", "insufficient", "invalid", "false", "no"))


def is_pin_failure(value):
    text = str(value or "").strip().lower()
    return "pin" in text and any(token in text for token in ("fail", "bad", "invalid", "incorrect", "wrong", "declin", "false"))


def load_transaction_csv(path):
    with open(path, "r", newline="", encoding="utf-8-sig") as handle:
        sample = handle.read(4096)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample)
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(handle, dialect=dialect)
        rows = list(reader)
    return rows, detect_fraud_columns(reader.fieldnames)


def build_entity_case(entity_type, entity_value, signals, rows, score):
    evidence_ids = []
    for row in rows[:8]:
        txn = row.get("_txn") or "<no transaction id>"
        card = row.get("_card") or "<no card token>"
        amount = row.get("_amount", 0.0)
        status = row.get("_status") or "unknown status"
        evidence_ids.append(f"{txn} card={card} amount={amount:.2f} status={status}")
    signal_text = "; ".join(signals)
    evidence_text = " | ".join(evidence_ids)
    return Finding(
        target=f"{entity_type}: {entity_value}",
        category="Card Fraud Forensics",
        severity="High" if score >= 24 else "Medium" if score >= 12 else "Low",
        title=f"Suspicious payment activity cluster around {entity_type} {entity_value}",
        detail=f"Signals: {signal_text}. Evidence transactions: {evidence_text}",
        remediation=(
            "Preserve source CSV, processor logs, receipts, camera/time-location evidence where lawful, and account-holder reports. "
            "Do not publicly identify a person from this score alone; send the evidence package to the bank, processor, merchant security team, or police."
        ),
    )


def fraud_forensic_analysis(path):
    rows, columns = load_transaction_csv(path)
    if not rows:
        return [], [f"No rows found in {path}"], "No transaction records were found."

    enriched = []
    for index, row in enumerate(rows, start=1):
        item = dict(row)
        item["_index"] = index
        item["_txn"] = get_cell(row, columns, "transaction_id", f"row-{index}")
        item["_card"] = get_cell(row, columns, "card", "unknown-card")
        item["_merchant"] = get_cell(row, columns, "merchant", "unknown-merchant")
        item["_terminal"] = get_cell(row, columns, "terminal", "unknown-terminal")
        item["_device"] = get_cell(row, columns, "device", "")
        item["_ip"] = get_cell(row, columns, "ip", "")
        item["_location"] = get_cell(row, columns, "location", "")
        item["_entry_mode"] = get_cell(row, columns, "entry_mode", "")
        item["_pin_result"] = get_cell(row, columns, "pin_result", "")
        item["_status"] = get_cell(row, columns, "status", "")
        item["_amount"] = parse_amount(get_cell(row, columns, "amount", "0"))
        item["_time"] = parse_transaction_time(get_cell(row, columns, "timestamp", ""))
        item["_declined"] = is_declined(item["_status"])
        item["_pin_failed"] = is_pin_failure(item["_pin_result"])
        enriched.append(item)

    amounts = [row["_amount"] for row in enriched if row["_amount"] > 0]
    mean_amount = sum(amounts) / len(amounts) if amounts else 0.0
    variance = sum((value - mean_amount) ** 2 for value in amounts) / len(amounts) if amounts else 0.0
    std_amount = math.sqrt(variance)
    high_amount_threshold = max(mean_amount + (2 * std_amount), 500.0)

    entity_rows = defaultdict(list)
    for row in enriched:
        for logical, prefix in (("_terminal", "terminal"), ("_merchant", "merchant"), ("_ip", "ip"), ("_device", "device")):
            value = row.get(logical)
            if value and not value.startswith("unknown"):
                entity_rows[(prefix, value)].append(row)

    findings = []
    entity_scores = Counter()
    entity_signals = defaultdict(list)

    for (entity_type, entity_value), group in entity_rows.items():
        cards = {row["_card"] for row in group if row["_card"] != "unknown-card"}
        declined = [row for row in group if row["_declined"]]
        pin_failed = [row for row in group if row["_pin_failed"]]
        high_amounts = [row for row in group if row["_amount"] >= high_amount_threshold and row["_amount"] > 0]
        small_amounts = [row for row in group if 0 < row["_amount"] <= 3.00]

        if len(cards) >= 5 and len(group) >= 8:
            entity_scores[(entity_type, entity_value)] += 10 + len(cards)
            entity_signals[(entity_type, entity_value)].append(f"{len(cards)} distinct cards across {len(group)} transactions")
        if len(declined) >= 4 and len(declined) / max(1, len(group)) >= 0.35:
            entity_scores[(entity_type, entity_value)] += 8 + len(declined)
            entity_signals[(entity_type, entity_value)].append(f"{len(declined)} declined or failed authorizations")
        if len(pin_failed) >= 3:
            entity_scores[(entity_type, entity_value)] += 9 + len(pin_failed)
            entity_signals[(entity_type, entity_value)].append(f"{len(pin_failed)} PIN/CVV verification failures")
        if len(high_amounts) >= 2:
            entity_scores[(entity_type, entity_value)] += 6 + len(high_amounts)
            entity_signals[(entity_type, entity_value)].append(f"{len(high_amounts)} unusually high-value transactions")
        if len(small_amounts) >= 5 and len(cards) >= 3:
            entity_scores[(entity_type, entity_value)] += 8 + len(small_amounts)
            entity_signals[(entity_type, entity_value)].append(f"{len(small_amounts)} low-dollar card-testing style attempts")

    by_card = defaultdict(list)
    for row in enriched:
        if row["_card"] != "unknown-card":
            by_card[row["_card"]].append(row)

    for card, group in by_card.items():
        timed = sorted([row for row in group if row["_time"]], key=lambda row: row["_time"])
        for start in range(len(timed)):
            window = [timed[start]]
            for row in timed[start + 1:]:
                if (row["_time"] - timed[start]["_time"]).total_seconds() <= 600:
                    window.append(row)
            if len(window) >= 4:
                merchants = {row["_merchant"] for row in window}
                locations = {row["_location"] for row in window if row["_location"]}
                signals = [f"{len(window)} transactions for one card inside 10 minutes"]
                if len(merchants) >= 3:
                    signals.append(f"{len(merchants)} merchants in the same velocity window")
                if len(locations) >= 2:
                    signals.append(f"{len(locations)} locations in the same velocity window")
                findings.append(Finding(
                    target=f"card token: {card}",
                    category="Card Fraud Forensics",
                    severity="High" if len(window) >= 6 else "Medium",
                    title="Card velocity anomaly",
                    detail="; ".join(signals) + ". Evidence transactions: " + ", ".join(row["_txn"] for row in window[:10]),
                    remediation="Contact issuer/processor fraud operations, preserve authorization logs, and verify with the account holder before taking enforcement action.",
                ))
                break

    for entity, score in entity_scores.most_common(12):
        entity_type, entity_value = entity
        findings.append(build_entity_case(entity_type, entity_value, entity_signals[entity], entity_rows[entity], score))

    detected_columns = ", ".join(f"{key}={value}" for key, value in sorted(columns.items())) or "none"
    high_risk = [item for item in findings if item.severity == "High"]
    medium_risk = [item for item in findings if item.severity == "Medium"]
    evidence = [
        f"Dataset: {path}",
        f"Rows analyzed: {len(rows)}",
        f"Detected columns: {detected_columns}",
        f"Average amount: {mean_amount:.2f}",
        f"High amount threshold: {high_amount_threshold:.2f}",
        f"High-risk findings: {len(high_risk)}",
        f"Medium-risk findings: {len(medium_risk)}",
    ]
    report = fraud_case_report(path, enriched, columns, findings, evidence)
    return findings, evidence, report


def fraud_case_report(path, rows, columns, findings, evidence):
    lines = [
        "Phoenix Guardian Card Fraud Forensic Report",
        f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}",
        f"Dataset: {path}",
        "",
        "Executive summary",
        f"- Transactions analyzed: {len(rows)}",
        f"- Findings generated: {len(findings)}",
        f"- High severity: {sum(1 for item in findings if item.severity == 'High')}",
        f"- Medium severity: {sum(1 for item in findings if item.severity == 'Medium')}",
        "",
        "Detected data fields",
    ]
    if columns:
        lines.extend(f"- {logical}: {source}" for logical, source in sorted(columns.items()))
    else:
        lines.append("- No recognized payment-forensics columns were detected.")

    lines.extend([
        "",
        "Top investigative leads",
    ])
    if findings:
        for item in findings[:15]:
            lines.extend([
                f"- [{item.severity}] {item.title}",
                f"  Lead: {item.target}",
                f"  Basis: {item.detail}",
                f"  Handoff: {item.remediation}",
            ])
    else:
        lines.append("- No suspicious clusters met the configured thresholds.")

    lines.extend([
        "",
        "Bad-actor trail leads",
        "- Treat terminals, merchants, IPs, devices, transaction IDs, timestamps, and card tokens as leads for lawful follow-up.",
        "- Correlate these leads with issuer records, processor logs, merchant records, camera/access logs, delivery records, and account-holder statements.",
        "- Do not name or confront a person from Phoenix Guardian scoring alone; use the package for bank, processor, merchant-security, or police handoff.",
        "",
        "Evidence preservation checklist",
        "- Keep the original CSV unchanged and record its SHA256 hash.",
        "- Preserve processor authorization logs, chargeback notices, device/terminal logs, receipts, and account-holder statements.",
        "- Preserve merchant surveillance or access logs only through lawful, authorized channels.",
        "- Document who handled the evidence, when, and why.",
        "- Treat entity scores as leads. Human review and lawful records are required before naming a person as responsible.",
        "",
        "Recommended escalation path",
        "- High confidence payment abuse: issuer fraud team, payment processor risk team, affected merchant security, and local police or financial-crimes unit.",
        "- Suspected compromised terminal/device: isolate the device, preserve it, rotate credentials, and request forensic support.",
        "- Card-testing pattern: rate-limit, block the implicated terminal/IP/device where authorized, and notify the processor.",
        "",
        "Run evidence",
    ])
    lines.extend(f"- {item}" for item in evidence)
    return "\n".join(lines)


class PhoenixGuardian(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1360x860")
        self.minsize(1120, 720)
        self.scope = ScopeManager(DATA_FILE)
        self.findings = []
        self.work_queue = queue.Queue()
        self.status_text = tk.StringVar(value="Ready")
        self.command_target = tk.StringVar(value="")
        self.autonomous_enabled = tk.BooleanVar(value=False)
        self.autonomous_all_tabs = tk.BooleanVar(value=True)
        self.autonomous_bug_bounty = tk.BooleanVar(value=True)
        self.autonomous_interval = tk.IntVar(value=15)
        self.auto_web_intel = tk.BooleanVar(value=True)
        self.local_full_access = tk.BooleanVar(value=False)
        self.fraud_dataset_path = tk.StringVar(value="")
        self.burp_proxy_url = tk.StringVar(value="http://127.0.0.1:8080")
        self.theme_name = tk.StringVar(value="Phoenix HUD")
        self.groq_api_key = tk.StringVar(value=os.environ.get("GROQ_API_KEY", load_local_secret("GROQ_API_KEY")))
        self.groq_model = tk.StringVar(value=os.environ.get("GROQ_MODEL", GROQ_DEFAULT_MODEL))
        self.chat_preapprove = tk.BooleanVar(value=False)
        self.browser_url = tk.StringVar(value="https://hackerone.com/shopify?type=team")
        self.project_name = tk.StringVar(value="Shopify Bug Bounty")
        self.project_notes = tk.StringVar(value="Scoped bug bounty workspace")
        self.web_search_query = tk.StringVar(value="")
        self.current_vector_query = tk.StringVar(value="web application API cloud auth bug bounty")
        self.wsl_command_text = tk.StringVar(value="pwd && whoami && uname -a")
        self.wsl_distro = tk.StringVar(value=os.environ.get("PHOENIX_WSL_DISTRO", "kali-linux"))
        self.code_lab_query = tk.StringVar(value="secure audit helpers, scripts, SBOM, IaC, LLM app security")
        self.h1_username = tk.StringVar(value=os.environ.get("HACKERONE_USERNAME", "james1956"))
        self.h1_token = tk.StringVar(value=os.environ.get("HACKERONE_API_TOKEN", ""))
        self.h1_program_handle = tk.StringVar(value="shopify")
        self.h1_researcher_tag = tk.StringVar(value="james1956")
        self.h1_scope_limit = tk.IntVar(value=3)
        self.h1_auto_create_intents = tk.BooleanVar(value=True)
        self.h1_last_intent_id = tk.StringVar(value="")
        self.guardrail_vars = {key: tk.BooleanVar(value=default) for key, label, default, editable, detail in GUARDRAIL_ITEMS}
        self.pending_chat_action = None
        self.imported_scope_entries = []
        self.last_bug_bounty_report = ""
        self.last_fraud_report = ""
        self.last_vector_report = ""
        self.chat_memory = self._load_chat_memory()
        self.projects = []
        self.plugin_vars = {}
        self.voice_listening = False
        self._build_ui()
        self._refresh_scope()
        self.after(150, self._drain_queue)
        self.after(1000, self._autonomous_tick)

    def _build_ui(self):
        self._configure_style()
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        header = ttk.Frame(self, style="Header.TFrame", padding=(16, 12))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)
        brand = ttk.Frame(header, style="Header.TFrame")
        brand.grid(row=0, column=0, sticky="w")
        self.phoenix_mark = tk.Canvas(brand, width=54, height=58, highlightthickness=0, bd=0, bg=THEME["bg"])
        self.phoenix_mark.grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, 10))
        ttk.Label(brand, text=APP_NAME, style="Title.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Label(
            brand,
            text="Scoped security operations, Kali WSL, Groq command, fraud forensics, and report-ready evidence",
            style="Subtle.TLabel",
            wraplength=520,
        ).grid(row=1, column=1, sticky="w")
        command = ttk.Frame(header, style="Command.TFrame")
        command.grid(row=0, column=1, sticky="ew", padx=(24, 0))
        command.columnconfigure(1, weight=1)
        ttk.Label(command, text="Target", style="Subtle.TLabel").grid(row=0, column=0, sticky="w", padx=(10, 6), pady=8)
        ttk.Entry(command, textvariable=self.command_target).grid(row=0, column=1, sticky="ew", pady=8)
        ttk.Button(command, text="Scope+", command=self._add_command_target_to_scope).grid(row=0, column=2, padx=(8, 0), pady=8)
        ttk.Button(command, text="Intel", command=self._run_current_vectors).grid(row=0, column=3, padx=(8, 0), pady=8)
        ttk.Button(command, text="Autopilot", command=self._run_command_target_autopilot).grid(row=0, column=4, padx=(8, 10), pady=8)
        quick = ttk.Frame(header, style="Header.TFrame")
        quick.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        quick.columnconfigure(10, weight=1)
        ttk.Button(quick, text="Voice Cmd", style="Primary.TButton", command=self._listen_for_voice_command).grid(row=0, column=0, sticky="w")
        ttk.Button(quick, text="Type Cmd", command=self._prompt_voice_command).grid(row=0, column=1, sticky="w", padx=(8, 0))
        ttk.Button(quick, text="Voice Panel", command=self._select_voice_panel).grid(row=0, column=2, sticky="w", padx=(8, 0))
        ttk.Button(quick, text="Settings", command=self._select_settings).grid(row=0, column=3, sticky="w", padx=(8, 0))
        ttk.Label(quick, text="Theme", style="Subtle.TLabel").grid(row=0, column=4, sticky="w", padx=(18, 6))
        ttk.Combobox(quick, textvariable=self.theme_name, values=tuple(THEME_PRESETS), state="readonly", width=14).grid(row=0, column=5, sticky="w")
        ttk.Button(quick, text="Apply", command=self._apply_theme).grid(row=0, column=6, sticky="w", padx=(6, 0))
        ttk.Label(quick, text="Full access", style="Subtle.TLabel").grid(row=0, column=7, sticky="w", padx=(18, 6))
        ToggleSwitch(quick, self.local_full_access, enabled=True, command=self._toggle_full_access).grid(row=0, column=8, sticky="w")
        ttk.Label(quick, text="Auto web", style="Subtle.TLabel").grid(row=0, column=9, sticky="w", padx=(18, 6))
        ToggleSwitch(quick, self.auto_web_intel, enabled=True).grid(row=0, column=10, sticky="w")

        tabs = ttk.Notebook(self)
        self.main_tabs = tabs
        tabs.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 8))

        self.command_center_tab = ttk.Frame(tabs, padding=12)
        self.bounty_tab = ttk.Frame(tabs, padding=12)
        self.operations_tab = ttk.Frame(tabs, padding=0)
        self.intelligence_tab = ttk.Frame(tabs, padding=0)
        self.report_tab = ttk.Frame(tabs, padding=12)
        self.privacy_tab = ttk.Frame(tabs, padding=12)

        tabs.add(self.command_center_tab, text="Command")
        tabs.add(self.bounty_tab, text="Bug Bounty")
        tabs.add(self.operations_tab, text="Operations")
        tabs.add(self.intelligence_tab, text="Intelligence")
        tabs.add(self.report_tab, text="Reports")
        tabs.add(self.privacy_tab, text="Settings")

        self.dashboard_tab = self.command_center_tab

        ops_tabs = ttk.Notebook(self.operations_tab)
        ops_tabs.pack(fill="both", expand=True, padx=12, pady=12)
        self.scope_tab = ttk.Frame(ops_tabs, padding=12)
        self.web_tab = ttk.Frame(ops_tabs, padding=12)
        self.offense_tab = ttk.Frame(ops_tabs, padding=12)
        self.wifi_tab = ttk.Frame(ops_tabs, padding=12)
        self.monitor_tab = ttk.Frame(ops_tabs, padding=12)
        self.fraud_tab = ttk.Frame(ops_tabs, padding=12)
        self.drones_tab = ttk.Frame(ops_tabs, padding=12)
        self.ghidra_tab = ttk.Frame(ops_tabs, padding=12)
        ops_tabs.add(self.scope_tab, text="Scope")
        ops_tabs.add(self.web_tab, text="Web")
        ops_tabs.add(self.offense_tab, text="Validation")
        ops_tabs.add(self.wifi_tab, text="Wi-Fi")
        ops_tabs.add(self.monitor_tab, text="Monitor")
        ops_tabs.add(self.fraud_tab, text="Fraud Lab")
        ops_tabs.add(self.drones_tab, text="Drones")
        ops_tabs.add(self.ghidra_tab, text="Ghidra")

        intel_tabs = ttk.Notebook(self.intelligence_tab)
        self.intel_tabs = intel_tabs
        intel_tabs.pack(fill="both", expand=True, padx=12, pady=12)
        self.vectors_tab = ttk.Frame(intel_tabs, padding=12)
        self.webintel_tab = ttk.Frame(intel_tabs, padding=12)
        self.browser_tab = ttk.Frame(intel_tabs, padding=12)
        self.chat_tab = ttk.Frame(intel_tabs, padding=12)
        self.voice_tab = ttk.Frame(intel_tabs, padding=12)
        self.terminal_tab = ttk.Frame(intel_tabs, padding=12)
        self.code_tab = ttk.Frame(intel_tabs, padding=12)
        self.projects_tab = ttk.Frame(intel_tabs, padding=12)
        self.plugins_tab = ttk.Frame(intel_tabs, padding=12)
        self.autonomous_tab = ttk.Frame(intel_tabs, padding=12)
        self.threat_tab = ttk.Frame(intel_tabs, padding=12)
        intel_tabs.add(self.vectors_tab, text="Current Vectors")
        intel_tabs.add(self.webintel_tab, text="Web Intel")
        intel_tabs.add(self.browser_tab, text="Browser Bridge")
        intel_tabs.add(self.chat_tab, text="Groq")
        intel_tabs.add(self.voice_tab, text="Voice")
        intel_tabs.add(self.terminal_tab, text="Kali Terminal")
        intel_tabs.add(self.code_tab, text="Code Lab")
        intel_tabs.add(self.projects_tab, text="Projects")
        intel_tabs.add(self.plugins_tab, text="Plugins")
        intel_tabs.add(self.autonomous_tab, text="Automation")
        intel_tabs.add(self.threat_tab, text="Forecast")

        self._scope_ui()
        self._web_ui()
        self._offense_ui()
        self._wifi_ui()
        self._monitor_ui()
        self._fraud_ui()
        self._bounty_ui()
        self._vectors_ui()
        self._webintel_ui()
        self._browser_ui()
        self._terminal_ui()
        self._chat_ui()
        self._voice_ui()
        self._code_lab_ui()
        self._projects_ui()
        self._plugins_ui()
        self._drones_ui()
        self._ghidra_ui()
        self._dashboard_ui()
        self._autonomous_ui()
        self._threat_ui()
        self._privacy_ui()
        self._report_ui()

        status = ttk.Label(self, textvariable=self.status_text, style="Status.TLabel", anchor="w", padding=(12, 6))
        status.grid(row=2, column=0, sticky="ew")
        self._style_text_widgets()
        self._attach_text_scrollbars()
        self._draw_phoenix_mark()

    def _configure_style(self):
        THEME.clear()
        THEME.update(THEME_PRESETS.get(self.theme_name.get(), THEME_PRESETS["Codex Dark"]))
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        self.configure(bg=THEME["bg"])
        style.configure("Header.TFrame", background=THEME["bg"])
        style.configure("Command.TFrame", background=THEME["panel_alt"], borderwidth=1, relief="solid")
        style.configure("Card.TFrame", background=THEME["panel_alt"], borderwidth=1, relief="solid")
        style.configure("Hud.TFrame", background=THEME["panel"], borderwidth=1, relief="solid")
        style.configure("Title.TLabel", background=THEME["bg"], foreground=THEME["text"], font=("Segoe UI", 20, "bold"))
        style.configure("Hero.TLabel", background=THEME["panel"], foreground=THEME["text"], font=("Segoe UI", 18, "bold"))
        style.configure("SectionTitle.TLabel", background=THEME["panel"], foreground=THEME["text"], font=("Segoe UI", 14, "bold"))
        style.configure("Subtle.TLabel", background=THEME["bg"], foreground=THEME["muted"], font=("Segoe UI", 10))
        style.configure("PanelSubtle.TLabel", background=THEME["panel"], foreground=THEME["muted"], font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background=THEME["panel_alt"], foreground=THEME["text"], font=("Segoe UI", 10, "bold"))
        style.configure("CardSubtle.TLabel", background=THEME["panel_alt"], foreground=THEME["muted"], font=("Segoe UI", 10))
        style.configure("StatCard.TFrame", background=THEME["panel_alt"], borderwidth=1, relief="solid")
        style.configure("StatValue.TLabel", background=THEME["panel_alt"], foreground=THEME["text"], font=("Segoe UI", 20, "bold"))
        style.configure("StatName.TLabel", background=THEME["panel_alt"], foreground=THEME["muted"], font=("Segoe UI", 9, "bold"))
        style.configure("HudLabel.TLabel", background=THEME["panel"], foreground=THEME["accent"], font=("Segoe UI", 9, "bold"))
        style.configure("Badge.TLabel", background=THEME["glow"], foreground=THEME["accent"], font=("Segoe UI", 9, "bold"), padding=(8, 3))
        style.configure("LockedBadge.TLabel", background="#3b2432", foreground=THEME["bad"], font=("Segoe UI", 9, "bold"), padding=(8, 3))
        style.configure("Status.TLabel", background=THEME["panel_alt"], foreground=THEME["muted"])
        style.configure("TNotebook", background=THEME["bg"], borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background=THEME["panel"], foreground=THEME["muted"], padding=(18, 9), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", THEME["panel_soft"])], foreground=[("selected", THEME["accent"])])
        style.configure("TFrame", background=THEME["panel"])
        style.configure("TLabel", background=THEME["panel"], foreground=THEME["text"], font=("Segoe UI", 10))
        style.configure("TButton", background=THEME["panel_soft"], foreground=THEME["text"], font=("Segoe UI", 10), padding=(11, 7), borderwidth=0)
        style.map("TButton", background=[("active", THEME["glow"])], foreground=[("disabled", "#6b7280")])
        style.configure("Primary.TButton", background=THEME["accent"], foreground=THEME["bg"], font=("Segoe UI", 10, "bold"), padding=(12, 7), borderwidth=0)
        style.map("Primary.TButton", background=[("active", THEME["accent_2"])])
        style.configure("TCheckbutton", background=THEME["panel"], foreground=THEME["text"], font=("Segoe UI", 10))
        style.map("TCheckbutton", background=[("active", THEME["panel"])])
        style.configure("TEntry", fieldbackground=THEME["field"], foreground=THEME["text"], bordercolor=THEME["line"], lightcolor=THEME["line"], darkcolor=THEME["line"], insertcolor=THEME["text"], borderwidth=1)
        style.configure("TCombobox", fieldbackground=THEME["field"], foreground=THEME["text"], background=THEME["panel_soft"])
        style.configure("TSpinbox", fieldbackground=THEME["field"], foreground=THEME["text"], background=THEME["panel_soft"])
        style.configure("TLabelframe", background=THEME["panel"], foreground=THEME["text"], bordercolor=THEME["line"])
        style.configure("TLabelframe.Label", background=THEME["panel"], foreground=THEME["accent"], font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", background=THEME["field"], foreground="#e5e7eb", fieldbackground=THEME["field"], rowheight=27, font=("Segoe UI", 9), borderwidth=0)
        style.configure("Treeview.Heading", background=THEME["panel_soft"], foreground=THEME["text"], font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#1f3b57")], foreground=[("selected", THEME["text"])])

    def _apply_theme(self, event=None):
        self._configure_style()
        self._style_text_widgets()
        self._draw_phoenix_mark()
        self._refresh_dashboard()
        self.status_text.set(f"Theme applied: {self.theme_name.get()}")

    def _draw_phoenix_mark(self):
        if not hasattr(self, "phoenix_mark"):
            return
        canvas = self.phoenix_mark
        canvas.configure(bg=THEME["bg"])
        canvas.delete("all")
        accent = THEME["accent"]
        accent2 = THEME["accent_2"]
        canvas.create_oval(19, 8, 33, 22, fill=accent2, outline="")
        canvas.create_arc(4, 8, 40, 54, start=20, extent=120, style="arc", outline=accent, width=4)
        canvas.create_arc(12, 6, 50, 54, start=40, extent=120, style="arc", outline=accent2, width=3)
        canvas.create_polygon(26, 18, 14, 46, 26, 38, 38, 46, fill=accent, outline="")
        canvas.create_line(26, 20, 26, 48, fill=THEME["text"], width=2)

    def _draw_panel(self, canvas, x0, y0, x1, y1, title="", accent=None):
        accent = accent or THEME["accent"]
        canvas.create_rectangle(x0 + 4, y0 + 5, x1 + 4, y1 + 5, fill="#02040a", outline="")
        canvas.create_rectangle(x0, y0, x1, y1, fill=THEME["panel"], outline=THEME["line"], width=1)
        canvas.create_line(x0, y0, x0 + 60, y0, fill=accent, width=2)
        canvas.create_line(x0, y0, x0, y0 + 34, fill=accent, width=2)
        canvas.create_line(x1 - 60, y1, x1, y1, fill=accent, width=2)
        canvas.create_line(x1, y1 - 34, x1, y1, fill=accent, width=2)
        if title:
            canvas.create_text(x0 + 16, y0 + 18, text=title.upper(), fill=accent, anchor="w", font=("Segoe UI", 9, "bold"))

    def _draw_mini_phoenix(self, canvas, cx, cy, scale=1.0):
        accent = THEME["accent_3"]
        accent2 = THEME["accent"]
        points = [
            cx, cy - 26 * scale,
            cx - 12 * scale, cy + 8 * scale,
            cx - 34 * scale, cy + 20 * scale,
            cx - 10 * scale, cy + 18 * scale,
            cx, cy + 38 * scale,
            cx + 10 * scale, cy + 18 * scale,
            cx + 34 * scale, cy + 20 * scale,
            cx + 12 * scale, cy + 8 * scale,
        ]
        canvas.create_polygon(points, fill=accent, outline="")
        canvas.create_arc(cx - 46 * scale, cy - 18 * scale, cx + 4 * scale, cy + 42 * scale, start=32, extent=118, style="arc", outline=accent2, width=max(2, int(3 * scale)))
        canvas.create_arc(cx - 4 * scale, cy - 18 * scale, cx + 46 * scale, cy + 42 * scale, start=30, extent=118, style="arc", outline=THEME["accent_2"], width=max(2, int(3 * scale)))
        canvas.create_oval(cx - 5 * scale, cy - 34 * scale, cx + 5 * scale, cy - 24 * scale, fill=THEME["accent_2"], outline="")

    def _style_text_widgets(self):
        for widget in self.winfo_children():
            self._style_text_widget_tree(widget)

    def _style_text_widget_tree(self, widget):
        if isinstance(widget, tk.Text):
            widget.configure(bg=THEME["field"], fg="#e5e7eb", insertbackground="#e5e7eb", relief="flat", borderwidth=8, selectbackground="#1f3b57")
            widget.bind("<MouseWheel>", lambda event, text=widget: text.yview_scroll(int(-1 * (event.delta / 120)), "units"))
            widget.bind("<Button-4>", lambda event, text=widget: text.yview_scroll(-3, "units"))
            widget.bind("<Button-5>", lambda event, text=widget: text.yview_scroll(3, "units"))
        elif isinstance(widget, tk.Listbox):
            widget.configure(bg=THEME["field"], fg="#e5e7eb", selectbackground="#1f3b57", relief="flat", borderwidth=8)
        for child in widget.winfo_children():
            self._style_text_widget_tree(child)

    def _attach_text_scrollbars(self):
        for widget in self._walk_widgets(self):
            if isinstance(widget, tk.Text):
                self._attach_text_scrollbar(widget)

    def _walk_widgets(self, widget):
        for child in widget.winfo_children():
            yield child
            yield from self._walk_widgets(child)

    def _attach_text_scrollbar(self, widget):
        if getattr(widget, "_phoenix_scrollbar_attached", False):
            return
        info = widget.grid_info()
        if not info:
            return
        parent = widget.master
        row = int(info.get("row", 0))
        column = int(info.get("column", 0))
        rowspan = int(info.get("rowspan", 1))
        colspan = int(info.get("columnspan", 1))
        target_column = column + colspan
        for sibling in parent.grid_slaves():
            if sibling is widget:
                continue
            sibling_info = sibling.grid_info()
            sibling_row = int(sibling_info.get("row", -999))
            sibling_column = int(sibling_info.get("column", -999))
            sibling_rowspan = int(sibling_info.get("rowspan", 1))
            row_overlap = sibling_row < row + rowspan and row < sibling_row + sibling_rowspan
            if row_overlap and sibling_column == target_column:
                return
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=widget.yview)
        scrollbar.grid(row=row, column=target_column, rowspan=rowspan, sticky="ns", pady=info.get("pady", 0))
        widget.configure(yscrollcommand=scrollbar.set)
        widget._phoenix_scrollbar_attached = True
        widget._phoenix_scrollbar = scrollbar

    def _command_target_value(self):
        bounty_target = self.bounty_target_entry.get().strip() if hasattr(self, "bounty_target_entry") else ""
        web_target = self.target_entry.get().strip() if hasattr(self, "target_entry") else ""
        return self.command_target.get().strip() or bounty_target or web_target

    def _add_command_target_to_scope(self):
        target = self._command_target_value()
        if not target:
            messagebox.showinfo(APP_NAME, "Enter a target in the command bar first.")
            return
        normalized = self.scope.add(target)
        if normalized:
            self.scope_entry.delete(0, tk.END)
            self._refresh_scope()
            self.status_text.set(f"Added {normalized} to authorized scope")

    def _run_command_target_autopilot(self):
        target = self._command_target_value()
        if not target:
            messagebox.showinfo(APP_NAME, "Enter a command-bar target first.")
            return
        if not self.scope.is_allowed(target):
            messagebox.showwarning(APP_NAME, "Add this target to authorized scope before autopilot.")
            return
        if hasattr(self, "bounty_target_entry"):
            self.bounty_target_entry.delete(0, tk.END)
            self.bounty_target_entry.insert(0, target)
        self._run_bug_bounty_autopilot()

    def _select_settings(self):
        if hasattr(self, "main_tabs"):
            self.main_tabs.select(self.privacy_tab)

    def _select_voice_panel(self):
        if hasattr(self, "main_tabs") and hasattr(self, "intelligence_tab"):
            self.main_tabs.select(self.intelligence_tab)
        if hasattr(self, "intel_tabs") and hasattr(self, "voice_tab"):
            self.intel_tabs.select(self.voice_tab)

    def _toggle_full_access(self, enabled):
        self.auto_web_intel.set(enabled)
        self.chat_preapprove.set(enabled)
        self.autonomous_enabled.set(enabled)
        self.autonomous_all_tabs.set(True)
        self.autonomous_bug_bounty.set(True)
        self.h1_auto_create_intents.set(enabled)
        for key, label, default, editable, detail in GUARDRAIL_ITEMS:
            if editable:
                self.guardrail_vars[key].set(True if enabled else default)
        if enabled:
            self.status_text.set("Full local access enabled for authorized automation")
            if hasattr(self, "privacy_output"):
                self.privacy_output.insert(tk.END, f"{dt.datetime.now().isoformat(timespec='seconds')} full local access enabled.\n")
        else:
            self.status_text.set("Full local access disabled")
            if hasattr(self, "privacy_output"):
                self.privacy_output.insert(tk.END, f"{dt.datetime.now().isoformat(timespec='seconds')} full local access disabled.\n")

    def _guardrail_changed(self, key, enabled):
        if hasattr(self, "privacy_output"):
            state = "enabled" if enabled else "disabled"
            self.privacy_output.insert(tk.END, f"{dt.datetime.now().isoformat(timespec='seconds')} {key} {state}.\n")

    def _load_chat_memory(self):
        if not os.path.exists(CHAT_MEMORY_FILE):
            return []
        try:
            with open(CHAT_MEMORY_FILE, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            return payload.get("history", [])[-100:]
        except Exception:
            return []

    def _save_chat_memory(self):
        try:
            with open(CHAT_MEMORY_FILE, "w", encoding="utf-8") as handle:
                json.dump({"history": self.chat_memory[-100:]}, handle, indent=2)
        except Exception:
            pass

    def _remember_chat(self, user_text, response):
        item = {
            "time": dt.datetime.now().isoformat(timespec="seconds"),
            "user": user_text[:2000],
            "response": (response or "")[:4000],
        }
        self.chat_memory.append(item)
        self.chat_memory = self.chat_memory[-100:]
        self._save_chat_memory()
        self._refresh_chat_memory_list()

    def _refresh_chat_memory_list(self):
        if not hasattr(self, "chat_memory_list"):
            return
        self.chat_memory_list.delete(0, tk.END)
        for item in reversed(self.chat_memory[-100:]):
            prompt = re.sub(r"\s+", " ", item.get("user", "")).strip()[:42] or "Groq exchange"
            self.chat_memory_list.insert(tk.END, f"{item.get('time', '')}  {prompt}")

    def _load_selected_chat_memory(self, event=None):
        if not hasattr(self, "chat_memory_list"):
            return
        selection = self.chat_memory_list.curselection()
        if not selection:
            return
        index = len(self.chat_memory) - 1 - selection[0]
        if 0 <= index < len(self.chat_memory):
            item = self.chat_memory[index]
            self.chat_output.insert(tk.END, f"\nMemory {item.get('time', '')}\nYou:\n{item.get('user', '')}\n\nPhoenix Guardian:\n{item.get('response', '')}\n")

    def _clear_chat_memory(self):
        if not messagebox.askyesno(APP_NAME, "Clear local Groq chat memory?"):
            return
        self.chat_memory.clear()
        self._save_chat_memory()
        self._refresh_chat_memory_list()
        self.status_text.set("Groq chat memory cleared")

    def _new_chat(self):
        self.pending_chat_action = None
        self.chat_input.delete("1.0", tk.END)
        self.chat_output.delete("1.0", tk.END)
        self.chat_output.insert(tk.END, "New Groq chat started. Memory remains available in the side panel.\n")
        self.status_text.set("New Groq chat started")

    def _save_groq_key(self):
        key = self.groq_api_key.get().strip()
        ok, message = save_local_secret("GROQ_API_KEY", key)
        if ok:
            self.status_text.set("Groq key saved")
            messagebox.showinfo(APP_NAME, message)
        else:
            messagebox.showwarning(APP_NAME, message)

    def _load_groq_key(self):
        key = os.environ.get("GROQ_API_KEY", "") or load_local_secret("GROQ_API_KEY")
        if not key:
            messagebox.showinfo(APP_NAME, "No saved Groq key was found.")
            return
        self.groq_api_key.set(key)
        self.status_text.set("Groq key loaded")

    def _new_project(self):
        target = self._command_target_value()
        project = {
            "name": self.project_name.get().strip() or f"Project {len(self.projects) + 1}",
            "target": target,
            "scope": len(self.scope.scope),
            "notes": self.project_notes.get().strip(),
            "created": dt.datetime.now().isoformat(timespec="seconds"),
            "hackerone_program": self.h1_program_handle.get().strip(),
            "wsl_distro": self.wsl_distro.get().strip() or "kali-linux",
        }
        self.projects.append(project)
        if hasattr(self, "projects_table"):
            self.projects_table.insert(
                "",
                tk.END,
                values=(project["name"], project["target"], project["scope"], project["notes"], project["created"]),
            )
        if hasattr(self, "projects_output"):
            self.projects_output.insert(tk.END, f"Created project: {project['name']} | target={project['target'] or 'none'} | scope={project['scope']}\n")
        self.status_text.set(f"Project created: {project['name']}")

    def _load_selected_project(self):
        if not hasattr(self, "projects_table"):
            return
        selection = self.projects_table.selection()
        if not selection:
            messagebox.showinfo(APP_NAME, "Select a project first.")
            return
        index = self.projects_table.index(selection[0])
        if not (0 <= index < len(self.projects)):
            return
        project = self.projects[index]
        self.project_name.set(project.get("name", ""))
        self.project_notes.set(project.get("notes", ""))
        if project.get("target"):
            self.command_target.set(project["target"])
            if hasattr(self, "bounty_target_entry"):
                self.bounty_target_entry.delete(0, tk.END)
                self.bounty_target_entry.insert(0, project["target"])
            if hasattr(self, "target_entry"):
                self.target_entry.delete(0, tk.END)
                self.target_entry.insert(0, project["target"])
        self.h1_program_handle.set(project.get("hackerone_program") or self.h1_program_handle.get())
        self.wsl_distro.set(project.get("wsl_distro") or self.wsl_distro.get())
        self.current_vector_query.set(f"{project.get('target', '')} {project.get('name', '')} bug bounty security".strip())
        if hasattr(self, "projects_output"):
            self.projects_output.insert(tk.END, f"Loaded project: {project.get('name', '')}\n")
        self.status_text.set(f"Project loaded: {project.get('name', '')}")

    def _plugin_changed(self, key, enabled):
        if hasattr(self, "plugins_output"):
            state = "enabled" if enabled else "disabled"
            self.plugins_output.insert(tk.END, f"{dt.datetime.now().isoformat(timespec='seconds')} plugin {key} {state}.\n")
        self.status_text.set(f"Plugin {key} {'enabled' if enabled else 'disabled'}")

    def _scope_ui(self):
        self.scope_tab.columnconfigure(0, weight=1)
        ttk.Label(self.scope_tab, text="Authorized domains").grid(row=0, column=0, sticky="w")
        entry_row = ttk.Frame(self.scope_tab)
        entry_row.grid(row=1, column=0, sticky="ew", pady=8)
        entry_row.columnconfigure(0, weight=1)
        self.scope_entry = ttk.Entry(entry_row)
        self.scope_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(entry_row, text="Add", command=self._add_scope).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(entry_row, text="Remove Selected", command=self._remove_scope).grid(row=0, column=2, padx=(8, 0))

        self.scope_list = tk.Listbox(self.scope_tab, height=16)
        self.scope_list.grid(row=2, column=0, sticky="nsew")
        self.scope_tab.rowconfigure(2, weight=1)

        note = (
            "Only add domains and systems you own or are explicitly authorized to test. "
            "The app refuses web audits outside this allowlist."
        )
        ttk.Label(self.scope_tab, text=note, wraplength=900).grid(row=3, column=0, sticky="w", pady=(12, 0))

    def _web_ui(self):
        self.web_tab.columnconfigure(0, weight=1)
        row = ttk.Frame(self.web_tab)
        row.grid(row=0, column=0, sticky="ew")
        row.columnconfigure(0, weight=1)
        self.target_entry = ttk.Entry(row)
        self.target_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(row, text="Run Safe Audit", command=self._run_web_audit).grid(row=0, column=1, padx=(8, 0))

        self.web_output = tk.Text(self.web_tab, wrap="word", height=28)
        self.web_output.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self.web_tab.rowconfigure(1, weight=1)

    def _wifi_ui(self):
        self.wifi_tab.columnconfigure(0, weight=1)
        ttk.Button(self.wifi_tab, text="Review Local Wi-Fi Posture", command=self._run_wifi_audit).grid(row=0, column=0, sticky="w")
        self.wifi_output = tk.Text(self.wifi_tab, wrap="word", height=30)
        self.wifi_output.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self.wifi_tab.rowconfigure(1, weight=1)

    def _offense_ui(self):
        self.offense_tab.columnconfigure(0, weight=1)
        row = ttk.Frame(self.offense_tab)
        row.grid(row=0, column=0, sticky="ew")
        row.columnconfigure(0, weight=1)
        self.offense_target_entry = ttk.Entry(row)
        self.offense_target_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(row, text="Run Authorized Validation", command=self._run_offense_validation).grid(row=0, column=1, padx=(8, 0))

        notice = (
            "This tab uses harmless canaries to validate risk signals on allowlisted targets. "
            "It does not exploit, bypass authentication, evade detection, brute force, or alter remote systems."
        )
        ttk.Label(self.offense_tab, text=notice, wraplength=900).grid(row=1, column=0, sticky="w", pady=(10, 0))

        self.offense_output = tk.Text(self.offense_tab, wrap="word", height=26)
        self.offense_output.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.offense_tab.rowconfigure(2, weight=1)

    def _threat_ui(self):
        self.threat_tab.columnconfigure(0, weight=1)
        ttk.Button(self.threat_tab, text="Refresh Forecast", command=self._refresh_threat_model).grid(row=0, column=0, sticky="w")
        self.threat_output = tk.Text(self.threat_tab, wrap="word", height=32)
        self.threat_output.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self.threat_tab.rowconfigure(1, weight=1)

    def _report_ui(self):
        self.report_tab.columnconfigure(0, weight=1)
        controls = ttk.Frame(self.report_tab)
        controls.grid(row=0, column=0, sticky="ew")
        ttk.Button(controls, text="Refresh AI Summary", command=self._refresh_summary).grid(row=0, column=0)
        ttk.Button(controls, text="Export CSV", command=self._export_csv).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(controls, text="Export Fraud Report", command=self._export_fraud_report).grid(row=0, column=2, padx=(8, 0))
        ttk.Button(controls, text="Export Bug Bounty Report", command=self._export_bug_bounty_report).grid(row=0, column=3, padx=(8, 0))

        self.finding_table = ttk.Treeview(
            self.report_tab,
            columns=("time", "severity", "category", "target", "title"),
            show="headings",
        )
        for column, width in {
            "time": 140,
            "severity": 80,
            "category": 120,
            "target": 210,
            "title": 420,
        }.items():
            self.finding_table.heading(column, text=column.title())
            self.finding_table.column(column, width=width, anchor="w")
        self.finding_table.grid(row=1, column=0, sticky="nsew", pady=10)

        self.summary_output = tk.Text(self.report_tab, wrap="word", height=10)
        self.summary_output.grid(row=2, column=0, sticky="ew")
        self.report_tab.rowconfigure(1, weight=1)

    def _monitor_ui(self):
        self.monitor_tab.columnconfigure(0, weight=1)
        controls = ttk.Frame(self.monitor_tab)
        controls.grid(row=0, column=0, sticky="ew")
        ttk.Button(controls, text="Snapshot Nearby Wi-Fi", command=self._run_wifi_monitor).grid(row=0, column=0, sticky="w")
        ttk.Button(controls, text="Create Incident Draft", command=self._incident_draft).grid(row=0, column=1, padx=(8, 0))
        note = (
            "Bettercap-style visibility without disruption: this uses Windows-visible Wi-Fi metadata for monitoring and reporting. "
            "It does not deauth, jam, or force devices offline."
        )
        ttk.Label(self.monitor_tab, text=note, wraplength=950).grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.monitor_output = tk.Text(self.monitor_tab, wrap="word", height=28)
        self.monitor_output.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.monitor_tab.rowconfigure(2, weight=1)

    def _fraud_ui(self):
        self.fraud_tab.columnconfigure(0, weight=1)
        controls = ttk.Frame(self.fraud_tab)
        controls.grid(row=0, column=0, sticky="ew")
        controls.columnconfigure(1, weight=1)
        ttk.Button(controls, text="Choose Transaction CSV", command=self._choose_fraud_csv).grid(row=0, column=0, sticky="w")
        ttk.Label(controls, textvariable=self.fraud_dataset_path).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(controls, text="Run Forensic Analysis", command=self._run_fraud_analysis).grid(row=0, column=2)
        ttk.Button(controls, text="Export Detailed Report", command=self._export_fraud_report).grid(row=0, column=3, padx=(8, 0))
        note = (
            "Analyze authorized debit/credit card transaction exports for velocity, card testing, repeated PIN/CVV failures, "
            "unusual terminal/merchant/IP/device clusters, and evidence-ready handoff notes. "
            "The app produces investigative leads; police, issuer, processor, and merchant records are needed to identify a person."
        )
        ttk.Label(self.fraud_tab, text=note, wraplength=950).grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.fraud_output = tk.Text(self.fraud_tab, wrap="word", height=28)
        self.fraud_output.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.fraud_tab.rowconfigure(2, weight=1)

    def _bounty_ui(self):
        self.bounty_tab.columnconfigure(0, weight=1)
        target_row = ttk.Frame(self.bounty_tab)
        target_row.grid(row=0, column=0, sticky="ew")
        target_row.columnconfigure(1, weight=1)
        ttk.Label(target_row, text="Target").grid(row=0, column=0, sticky="w")
        self.bounty_target_entry = ttk.Entry(target_row)
        self.bounty_target_entry.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Label(target_row, text="Burp").grid(row=0, column=2, sticky="w")
        ttk.Entry(target_row, textvariable=self.burp_proxy_url, width=22).grid(row=0, column=3, sticky="w", padx=(6, 0))

        h1_row = ttk.Frame(self.bounty_tab)
        h1_row.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        h1_row.columnconfigure(1, weight=1)
        ttk.Label(h1_row, text="H1 user").grid(row=0, column=0, sticky="w")
        ttk.Entry(h1_row, textvariable=self.h1_username, width=18).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Label(h1_row, text="Token").grid(row=0, column=2, sticky="w")
        ttk.Entry(h1_row, textvariable=self.h1_token, show="*", width=24).grid(row=0, column=3, padx=(8, 8))
        ttk.Label(h1_row, text="Program").grid(row=0, column=4, sticky="w")
        ttk.Entry(h1_row, textvariable=self.h1_program_handle, width=18).grid(row=0, column=5, padx=(8, 8))
        ttk.Label(h1_row, text="Tag").grid(row=0, column=6, sticky="w")
        ttk.Entry(h1_row, textvariable=self.h1_researcher_tag, width=18).grid(row=0, column=7, padx=(8, 0))

        controls = ttk.Frame(self.bounty_tab)
        controls.grid(row=2, column=0, sticky="w", pady=(10, 0))
        ttk.Button(controls, text="Run Autopilot", command=self._run_bug_bounty_autopilot).grid(row=0, column=0)
        ttk.Button(controls, text="Burp Status", command=self._run_burp_status).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(controls, text="Launch Burp", command=self._launch_burp).grid(row=0, column=2, padx=(8, 0))
        ttk.Button(controls, text="Burp Proxy Probe", command=self._run_burp_probe).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(controls, text="Online OSINT", command=self._run_online_osint).grid(row=0, column=4, padx=(8, 0))
        ttk.Button(controls, text="Wordlists", command=self._run_wordlist_catalog).grid(row=0, column=5, padx=(8, 0))
        ttk.Button(controls, text="All Tools", command=self._run_full_tool_inventory).grid(row=0, column=6, padx=(8, 0))
        ttk.Button(controls, text="Current Vectors", command=self._run_current_vectors).grid(row=0, column=7, padx=(8, 0))
        ttk.Button(controls, text="Checklist", command=self._show_bounty_checklist).grid(row=0, column=8, padx=(8, 0))
        ttk.Button(controls, text="Money Report", command=self._show_money_report).grid(row=0, column=9, padx=(8, 0))
        ttk.Button(controls, text="Export Report", command=self._export_bug_bounty_report).grid(row=0, column=10, padx=(8, 0))

        h1_controls = ttk.Frame(self.bounty_tab)
        h1_controls.grid(row=3, column=0, sticky="w", pady=(10, 0))
        ttk.Button(h1_controls, text="Fetch H1 Rules/Scope", command=self._fetch_hackerone_scope).grid(row=0, column=0)
        ttk.Button(h1_controls, text="Import Scope File", command=self._import_scope_file).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(h1_controls, text="Add Eligible Scope", command=self._add_hackerone_scope_to_allowlist).grid(row=0, column=2, padx=(8, 0))
        ttk.Button(h1_controls, text="Run H1 Automation", command=self._run_hackerone_automation).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(h1_controls, text="Run Imported Scope", command=self._run_imported_scope_automation).grid(row=0, column=4, padx=(8, 0))
        ttk.Button(h1_controls, text="Create Report Intent", command=self._create_hackerone_intent).grid(row=0, column=5, padx=(8, 0))
        ttk.Button(h1_controls, text="Check Intent", command=self._check_hackerone_intent).grid(row=0, column=6, padx=(8, 0))
        ttk.Button(h1_controls, text="Submit Ready Intent", command=self._submit_hackerone_intent).grid(row=0, column=7, padx=(8, 0))
        ttk.Button(h1_controls, text="Open H1", command=self._open_hackerone_login).grid(row=0, column=8, padx=(8, 0))
        ttk.Button(h1_controls, text="API Token", command=self._open_hackerone_api_token).grid(row=0, column=9, padx=(8, 0))
        ttk.Label(h1_controls, text="Scope limit").grid(row=0, column=10, padx=(16, 4))
        ttk.Spinbox(h1_controls, from_=1, to=25, textvariable=self.h1_scope_limit, width=5).grid(row=0, column=11)
        ttk.Label(h1_controls, text="Auto intents", style="PanelSubtle.TLabel").grid(row=0, column=12, padx=(12, 6))
        ToggleSwitch(h1_controls, self.h1_auto_create_intents, enabled=True).grid(row=0, column=13)

        note = (
            "Bug bounty mode gathers scoped OSINT, HackerOne rules/scope, Burp proxy status, Kali inventory, wordlist catalogs, safe validation evidence, and report-intent drafts. "
            "Submission requires a ready report intent and explicit action."
        )
        ttk.Label(self.bounty_tab, text=note, wraplength=1050).grid(row=4, column=0, sticky="w", pady=(10, 0))
        self.bounty_output = tk.Text(self.bounty_tab, wrap="word", height=28)
        self.bounty_output.grid(row=5, column=0, sticky="nsew", pady=(10, 0))
        self.bounty_tab.rowconfigure(5, weight=1)

    def _vectors_ui(self):
        self.vectors_tab.columnconfigure(0, weight=1)
        top = ttk.Frame(self.vectors_tab)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Intel topic").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.current_vector_query).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(top, text="Refresh Live Vectors", command=self._run_current_vectors).grid(row=0, column=2)
        ttk.Button(top, text="Scope Burst", command=self._run_scope_vector_burst).grid(row=0, column=3, padx=(8, 0))
        ttk.Checkbutton(top, text="Feed Groq every chat", variable=self.auto_web_intel).grid(row=0, column=4, padx=(12, 0))

        board = ttk.Frame(self.vectors_tab)
        board.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        for col in range(4):
            board.columnconfigure(col, weight=1)
        cards = [
            ("CISA KEV", "Known exploited vulnerabilities and remediation deadlines."),
            ("NVD CVEs", "Recently published CVEs for target technologies and bug bounty topics."),
            ("OWASP", "Web/API testing categories mapped into safe validation evidence."),
            ("HackerOne", "Policy-aware report drafting and scope confirmation."),
        ]
        for col, (title, body) in enumerate(cards):
            panel = ttk.LabelFrame(board, text=title, padding=10)
            panel.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 8, 0))
            ttk.Label(panel, text=body, wraplength=250).grid(row=0, column=0, sticky="w")

        note = (
            "This tab keeps Phoenix current by collecting public vulnerability intelligence and converting it into authorized bug bounty validation paths. "
            "It is evidence-first: scope, policy, impact, reproduction notes, and remediation."
        )
        ttk.Label(self.vectors_tab, text=note, wraplength=1050).grid(row=2, column=0, sticky="w", pady=(12, 0))
        self.vectors_output = tk.Text(self.vectors_tab, wrap="word", height=28)
        self.vectors_output.grid(row=3, column=0, sticky="nsew", pady=(10, 0))
        self.vectors_tab.rowconfigure(3, weight=1)

    def _webintel_ui(self):
        self.webintel_tab.columnconfigure(0, weight=1)
        row = ttk.Frame(self.webintel_tab)
        row.grid(row=0, column=0, sticky="ew")
        row.columnconfigure(1, weight=1)
        ttk.Label(row, text="Search").grid(row=0, column=0, sticky="w")
        ttk.Entry(row, textvariable=self.web_search_query).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(row, text="Search Web", command=self._run_web_search).grid(row=0, column=2)
        ttk.Button(row, text="Search Target", command=self._run_target_web_search).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(row, text="Current Vectors", command=self._run_current_vectors).grid(row=0, column=4, padx=(8, 0))
        note = "Public web research for scoped cybersecurity work, CVE/background research, vendor docs, and bug bounty policy discovery."
        ttk.Label(self.webintel_tab, text=note, wraplength=1050).grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.webintel_output = tk.Text(self.webintel_tab, wrap="word", height=30, bg="#0b1020", fg="#e5e7eb", insertbackground="#e5e7eb")
        self.webintel_output.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.webintel_tab.rowconfigure(2, weight=1)

    def _browser_ui(self):
        self.browser_tab.columnconfigure(0, weight=1)
        row = ttk.Frame(self.browser_tab)
        row.grid(row=0, column=0, sticky="ew")
        row.columnconfigure(1, weight=1)
        ttk.Label(row, text="URL").grid(row=0, column=0, sticky="w")
        ttk.Entry(row, textvariable=self.browser_url).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(row, text="Open Browser", command=self._open_browser_url).grid(row=0, column=2)
        ttk.Button(row, text="Fetch Context", command=self._fetch_browser_context).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(row, text="HackerOne Shopify", command=self._browser_shopify).grid(row=0, column=4, padx=(8, 0))
        note = (
            "Browser Bridge links Phoenix to web workflows without adding another crowded browser chrome. "
            "Open HackerOne, fetch public page context, and feed scoped URLs into Current Vectors or Groq."
        )
        ttk.Label(self.browser_tab, text=note, wraplength=1050).grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.browser_output = tk.Text(self.browser_tab, wrap="word", height=30)
        self.browser_output.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.browser_tab.rowconfigure(2, weight=1)

    def _terminal_ui(self):
        self.terminal_tab.columnconfigure(0, weight=1)
        row = ttk.Frame(self.terminal_tab)
        row.grid(row=0, column=0, sticky="ew")
        row.columnconfigure(3, weight=1)
        ttk.Label(row, text="WSL2").grid(row=0, column=0, sticky="w")
        ttk.Combobox(row, textvariable=self.wsl_distro, values=("kali-linux", "Ubuntu", "Debian"), width=14).grid(row=0, column=1, padx=(8, 8))
        ttk.Label(row, text="Command").grid(row=0, column=2, sticky="w")
        ttk.Entry(row, textvariable=self.wsl_command_text).grid(row=0, column=3, sticky="ew", padx=(8, 8))
        ttk.Button(row, text="Run", command=self._run_wsl_terminal_command).grid(row=0, column=4)
        ttk.Button(row, text="Open Shell", command=self._open_interactive_wsl).grid(row=0, column=5, padx=(8, 0))
        ttk.Button(row, text="Admin Shell", command=self._launch_admin_kali).grid(row=0, column=6, padx=(8, 0))
        note = "WSL2 Kali command console for professional defensive and authorized testing workflows. Unsafe credential theft, piracy, rogue AP, and exploit-delivery commands are blocked."
        ttk.Label(self.terminal_tab, text=note, wraplength=1050).grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.terminal_output = tk.Text(self.terminal_tab, wrap="word", height=30, bg="#050816", fg="#d1e7ff", insertbackground="#d1e7ff", font=("Consolas", 10))
        self.terminal_output.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.terminal_tab.rowconfigure(2, weight=1)

    def _code_lab_ui(self):
        self.code_tab.columnconfigure(0, weight=1)
        row = ttk.Frame(self.code_tab)
        row.grid(row=0, column=0, sticky="ew")
        row.columnconfigure(1, weight=1)
        ttk.Label(row, text="Focus").grid(row=0, column=0, sticky="w")
        ttk.Entry(row, textvariable=self.code_lab_query).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(row, text="Inventory Languages", command=self._run_code_inventory).grid(row=0, column=2)
        ttk.Button(row, text="Secure Script Notes", command=self._secure_script_notes).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(row, text="LLM App Checklist", command=self._llm_app_checklist).grid(row=0, column=4, padx=(8, 0))
        note = (
            "Code Lab inventories local language runtimes and security libraries for audit automation: Python, Node, Go, Rust, Java, .NET, Ruby, PHP, PowerShell, SBOM, IaC, container, and LLM app security tools."
        )
        ttk.Label(self.code_tab, text=note, wraplength=1050).grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.code_output = tk.Text(self.code_tab, wrap="word", height=30)
        self.code_output.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.code_tab.rowconfigure(2, weight=1)

    def _projects_ui(self):
        self.projects_tab.columnconfigure(0, weight=1)
        top = ttk.Frame(self.projects_tab)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Project").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.project_name).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Label(top, text="Notes").grid(row=0, column=2, sticky="w")
        ttk.Entry(top, textvariable=self.project_notes, width=34).grid(row=0, column=3, padx=(8, 8))
        ttk.Button(top, text="New Project", command=self._new_project).grid(row=0, column=4)
        ttk.Button(top, text="Load Selected", command=self._load_selected_project).grid(row=0, column=5, padx=(8, 0))

        body = ttk.Frame(self.projects_tab)
        body.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        self.projects_table = ttk.Treeview(body, columns=("name", "target", "scope", "notes", "created"), show="headings", height=16)
        for column, width in {"name": 180, "target": 220, "scope": 90, "notes": 360, "created": 150}.items():
            self.projects_table.heading(column, text=column.title())
            self.projects_table.column(column, width=width, anchor="w")
        self.projects_table.grid(row=0, column=0, sticky="nsew")
        self.projects_tab.rowconfigure(1, weight=1)

        self.projects_output = tk.Text(self.projects_tab, wrap="word", height=8)
        self.projects_output.grid(row=2, column=0, sticky="ew", pady=(10, 0))

    def _plugins_ui(self):
        self.plugins_tab.columnconfigure(0, weight=1)
        ttk.Label(self.plugins_tab, text="Phoenix plugin-style tool registry", style="SectionTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            self.plugins_tab,
            text="Enable local tool families for authorized workflows. Locked enterprise controls remain enforced for public, enterprise, and government readiness.",
            wraplength=1050,
        ).grid(row=1, column=0, sticky="w", pady=(6, 12))
        registry = ttk.Frame(self.plugins_tab)
        registry.grid(row=2, column=0, sticky="ew")
        registry.columnconfigure(0, weight=1)
        plugins = [
            ("groq_command", "Groq Command", "LLM chat, report drafting, safe action routing, and current web context."),
            ("hackerone", "HackerOne", "Program scope/rules fetch, report intents, and browser bridge links."),
            ("kali_wsl", "WSL2 Kali", "Kali terminal, drones, language inventory, and local audit tooling."),
            ("burp", "Burp Suite", "Proxy status, launch helper, and header-only proxy probe."),
            ("vectors", "Current Vectors", "CISA KEV, NVD CVE API, OWASP, HackerOne references, and bug bounty playbooks."),
            ("code_lab", "Code Lab", "Python, Node, Go, Rust, Java, .NET, PowerShell, SBOM, IaC, container, and LLM app security checks."),
            ("fraud_lab", "Card Fraud Lab", "CSV forensic triage, fraud trails, and evidence handoff reports."),
        ]
        self.plugin_vars = {}
        for row, (key, name, detail) in enumerate(plugins):
            var = tk.BooleanVar(value=True)
            self.plugin_vars[key] = var
            item = ttk.Frame(registry, style="Card.TFrame", padding=(12, 9))
            item.grid(row=row, column=0, sticky="ew", pady=4)
            item.columnconfigure(1, weight=1)
            ToggleSwitch(item, var, enabled=True, command=lambda value, plugin_key=key: self._plugin_changed(plugin_key, value)).grid(row=0, column=0, rowspan=2, padx=(0, 12))
            ttk.Label(item, text=name, style="CardTitle.TLabel").grid(row=0, column=1, sticky="w")
            ttk.Label(item, text="LOCAL", style="Badge.TLabel").grid(row=0, column=2, sticky="e")
            ttk.Label(item, text=detail, style="CardSubtle.TLabel", wraplength=880).grid(row=1, column=1, columnspan=2, sticky="w", pady=(4, 0))
        self.plugins_output = tk.Text(self.plugins_tab, wrap="word", height=8)
        self.plugins_output.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        self.plugins_output.insert(tk.END, "Plugin registry ready. All plugin-style integrations run locally or through configured APIs.\n")

    def _chat_ui(self):
        self.chat_tab.columnconfigure(1, weight=1)
        memory = ttk.LabelFrame(self.chat_tab, text="Memory", padding=8)
        memory.grid(row=0, column=0, rowspan=3, sticky="nsew", padx=(0, 10))
        memory.rowconfigure(1, weight=1)
        ttk.Label(memory, text="Chat history", style="PanelSubtle.TLabel").grid(row=0, column=0, sticky="w")
        self.chat_memory_list = tk.Listbox(memory, width=32, height=24)
        self.chat_memory_list.grid(row=1, column=0, sticky="nsew", pady=(8, 8))
        self.chat_memory_list.bind("<<ListboxSelect>>", self._load_selected_chat_memory)
        ttk.Button(memory, text="Clear Memory", command=self._clear_chat_memory).grid(row=2, column=0, sticky="ew")
        self._refresh_chat_memory_list()

        top = ttk.Frame(self.chat_tab)
        top.grid(row=0, column=1, sticky="ew")
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Groq API key").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.groq_api_key, show="*", width=36).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Label(top, text="Model").grid(row=0, column=2, sticky="w")
        ttk.Combobox(
            top,
            textvariable=self.groq_model,
            values=(GROQ_DEFAULT_MODEL, "llama-3.1-8b-instant", "openai/gpt-oss-20b", "openai/gpt-oss-120b"),
            width=26,
        ).grid(row=0, column=3, padx=(8, 0))
        ttk.Checkbutton(top, text="Pre-approve safe action", variable=self.chat_preapprove).grid(row=0, column=4, padx=(12, 0))
        ttk.Checkbutton(top, text="Auto web context", variable=self.auto_web_intel).grid(row=0, column=5, padx=(12, 0))
        ttk.Button(top, text="Test Groq", command=self._test_groq).grid(row=0, column=6, padx=(8, 0))
        ttk.Button(top, text="New Chat", command=self._new_chat).grid(row=0, column=7, padx=(8, 0))
        ttk.Button(top, text="Save Key", command=self._save_groq_key).grid(row=0, column=8, padx=(8, 0))
        ttk.Button(top, text="Load Key", command=self._load_groq_key).grid(row=0, column=9, padx=(8, 0))
        self.chat_output = tk.Text(self.chat_tab, wrap="word", height=24, bg=THEME["field"], fg="#e5e7eb", insertbackground="#e5e7eb")
        self.chat_output.grid(row=1, column=1, sticky="nsew", pady=(10, 0))
        self.chat_tab.rowconfigure(1, weight=1)
        bottom = ttk.Frame(self.chat_tab)
        bottom.grid(row=2, column=1, sticky="ew", pady=(10, 0))
        bottom.columnconfigure(0, weight=1)
        self.chat_input = tk.Text(bottom, wrap="word", height=4, bg=THEME["field"], fg=THEME["text"], insertbackground=THEME["text"])
        self.chat_input.grid(row=0, column=0, sticky="ew")
        buttons = ttk.Frame(bottom)
        buttons.grid(row=0, column=1, sticky="ns", padx=(8, 0))
        ttk.Button(buttons, text="Ask Groq", command=self._ask_chatgpt).grid(row=0, column=0, sticky="ew")
        ttk.Button(buttons, text="Run Approved", command=self._run_pending_chat_action).grid(row=1, column=0, sticky="ew", pady=(8, 0))

    def _voice_ui(self):
        self.voice_tab.columnconfigure(0, weight=1)
        controls = ttk.Frame(self.voice_tab)
        controls.grid(row=0, column=0, sticky="ew")
        ttk.Button(controls, text="Start Listening", style="Primary.TButton", command=self._listen_for_voice_command).grid(row=0, column=0, sticky="w")
        ttk.Button(controls, text="Type Command", command=self._prompt_voice_command).grid(row=0, column=1, sticky="w", padx=(8, 0))
        ttk.Button(controls, text="Run Diagnostics", command=self._run_voice_diagnostics).grid(row=0, column=2, sticky="w", padx=(8, 0))
        ttk.Button(controls, text="Voice Help", command=self._show_voice_help).grid(row=0, column=3, sticky="w", padx=(8, 0))

        note = (
            "Voice commands use Python SpeechRecognition when available, then Windows System.Speech, then a typed-command prompt. "
            "Use diagnostics when speech is not recognized so Phoenix can show which backend is available."
        )
        ttk.Label(self.voice_tab, text=note, wraplength=1050).grid(row=1, column=0, sticky="w", pady=(10, 0))

        self.voice_output = tk.Text(self.voice_tab, wrap="word", height=30)
        self.voice_output.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.voice_tab.rowconfigure(2, weight=1)
        self.voice_output.insert(tk.END, self._voice_help_text())

    def _dashboard_ui(self):
        self.dashboard_tab.columnconfigure(0, weight=1)
        self.dashboard_tab.rowconfigure(2, weight=1)
        controls = ttk.Frame(self.dashboard_tab)
        controls.grid(row=0, column=0, sticky="ew")
        ttk.Button(controls, text="Refresh Cockpit", style="Primary.TButton", command=self._refresh_dashboard).grid(row=0, column=0, sticky="w")
        ttk.Label(controls, text="Phoenix HUD: scoped security posture, evidence quality, and mission readiness", style="PanelSubtle.TLabel").grid(row=0, column=1, sticky="w", padx=(12, 0))

        stats = ttk.Frame(self.dashboard_tab)
        stats.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        for col in range(4):
            stats.columnconfigure(col, weight=1)
        self.dashboard_stats = {}
        for col, (key, label, value) in enumerate((
            ("scope", "Scope Assets", "0"),
            ("findings", "Findings", "0"),
            ("critical", "High Risk", "0"),
            ("automation", "Automation", "IDLE"),
        )):
            card = ttk.Frame(stats, style="StatCard.TFrame", padding=(14, 10))
            card.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 8, 0))
            ttk.Label(card, text=label.upper(), style="StatName.TLabel").grid(row=0, column=0, sticky="w")
            value_label = ttk.Label(card, text=value, style="StatValue.TLabel")
            value_label.grid(row=1, column=0, sticky="w", pady=(4, 0))
            self.dashboard_stats[key] = value_label

        self.dashboard_canvas = tk.Canvas(self.dashboard_tab, bg=THEME["field"], highlightthickness=0, height=560)
        self.dashboard_canvas.grid(row=2, column=0, sticky="nsew", pady=(12, 0))

    def _drones_ui(self):
        self.drones_tab.columnconfigure(0, weight=1)
        top = ttk.Frame(self.drones_tab)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Target").grid(row=0, column=0, sticky="w")
        self.drone_target_entry = ttk.Entry(top)
        self.drone_target_entry.grid(row=0, column=1, sticky="ew", padx=8)
        self.drone_task = tk.StringVar(value="Recon Drone")
        ttk.Combobox(
            top,
            textvariable=self.drone_task,
            values=KALI_DRONE_TASKS,
            state="readonly",
            width=24,
        ).grid(row=0, column=2)
        ttk.Button(top, text="Run Drone", command=self._run_kali_drone).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(top, text="Inventory Tools", command=self._run_kali_inventory).grid(row=0, column=4, padx=(8, 0))
        ttk.Button(top, text="Admin WSL", command=self._launch_admin_kali).grid(row=0, column=5, padx=(8, 0))
        quick = ttk.Frame(self.drones_tab)
        quick.grid(row=1, column=0, sticky="w", pady=(10, 0))
        ttk.Button(quick, text="Cybersecurity Drone", command=self._run_cybersecurity_drone).grid(row=0, column=0, sticky="w")
        ttk.Button(quick, text="Defensive Response Drone", command=self._run_defensive_drone).grid(row=0, column=1, sticky="w", padx=(8, 0))
        note = (
            "Kali WSL drones discover installed tools and run low-rate posture tasks only against allowlisted targets. "
            "Cybersecurity Drone explores attack paths with safe probes; Defensive Response Drone focuses on fraud trails, Wi-Fi/WPS posture, and device-invasion indicators. "
            "Admin WSL asks Windows to open an elevated PowerShell running Kali; approve the UAC prompt only when you intend to."
        )
        ttk.Label(self.drones_tab, text=note, wraplength=950).grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.drone_output = tk.Text(self.drones_tab, wrap="word", height=28)
        self.drone_output.grid(row=3, column=0, sticky="nsew", pady=(10, 0))
        self.drones_tab.rowconfigure(3, weight=1)

    def _ghidra_ui(self):
        self.ghidra_tab.columnconfigure(0, weight=1)
        controls = ttk.Frame(self.ghidra_tab)
        controls.grid(row=0, column=0, sticky="ew")
        ttk.Button(controls, text="Inventory Ghidra", command=self._run_ghidra_inventory).grid(row=0, column=0)
        ttk.Button(controls, text="Hash Sample", command=self._hash_sample).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(controls, text="Create RE Case Notes", command=self._ghidra_case_notes).grid(row=0, column=2, padx=(8, 0))
        note = (
            "Defensive reverse-engineering support for suspicious binaries: inventory Ghidra, hash samples, and write case notes. "
            "This does not track Tor users, deanonymize traffic, or bypass privacy protections."
        )
        ttk.Label(self.ghidra_tab, text=note, wraplength=950).grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.ghidra_output = tk.Text(self.ghidra_tab, wrap="word", height=28)
        self.ghidra_output.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.ghidra_tab.rowconfigure(2, weight=1)

    def _autonomous_ui(self):
        self.autonomous_tab.columnconfigure(0, weight=1)
        controls = ttk.Frame(self.autonomous_tab)
        controls.grid(row=0, column=0, sticky="ew")
        ttk.Label(controls, text="Autonomous", style="PanelSubtle.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 6))
        ToggleSwitch(controls, self.autonomous_enabled, enabled=True).grid(row=0, column=1, sticky="w")
        ttk.Label(controls, text="All tools", style="PanelSubtle.TLabel").grid(row=0, column=2, padx=(16, 6))
        ToggleSwitch(controls, self.autonomous_all_tabs, enabled=True).grid(row=0, column=3)
        ttk.Label(controls, text="Bug bounty", style="PanelSubtle.TLabel").grid(row=0, column=4, padx=(16, 6))
        ToggleSwitch(controls, self.autonomous_bug_bounty, enabled=True).grid(row=0, column=5)
        ttk.Label(controls, text="Full access", style="PanelSubtle.TLabel").grid(row=0, column=6, padx=(16, 6))
        ToggleSwitch(controls, self.local_full_access, enabled=True, command=self._toggle_full_access).grid(row=0, column=7)
        ttk.Label(controls, text="Interval").grid(row=0, column=8, padx=(18, 6))
        ttk.Spinbox(controls, from_=5, to=240, textvariable=self.autonomous_interval, width=6).grid(row=0, column=9)
        ttk.Button(controls, text="Run All Tools Now", command=self._run_autonomous_cycle).grid(row=0, column=10, padx=(10, 0))
        note = (
            "Autonomous mode runs allowlisted, low-impact checks across the app: web headers, harmless validation, Wi-Fi defense/monitoring, "
            "card fraud trails for a selected CSV, cybersecurity and defensive drones, local device-invasion posture, threat forecasting, and Ghidra readiness. "
            "It will not run deauth, WPS brute force, credential attacks, exploit delivery, stealth, Tor tracking, or log wiping."
        )
        ttk.Label(self.autonomous_tab, text=note, wraplength=950).grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.autonomous_output = tk.Text(self.autonomous_tab, wrap="word", height=28)
        self.autonomous_output.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.autonomous_tab.rowconfigure(2, weight=1)

    def _privacy_ui(self):
        self.privacy_tab.columnconfigure(0, weight=1)
        self.privacy_tab.rowconfigure(0, weight=1)
        canvas = tk.Canvas(self.privacy_tab, bg=THEME["panel"], highlightthickness=0)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(self.privacy_tab, orient="vertical", command=canvas.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        content = ttk.Frame(canvas, padding=(0, 0, 10, 0))
        window_id = canvas.create_window((0, 0), window=content, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        def _sync_scrollregion(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfigure(window_id, width=canvas.winfo_width())

        def _mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _wheel_up(event):
            canvas.yview_scroll(-3, "units")

        def _wheel_down(event):
            canvas.yview_scroll(3, "units")

        content.bind("<Configure>", _sync_scrollregion)
        canvas.bind("<Configure>", _sync_scrollregion)
        canvas.bind("<Enter>", lambda event: (canvas.bind_all("<MouseWheel>", _mousewheel), canvas.bind_all("<Button-4>", _wheel_up), canvas.bind_all("<Button-5>", _wheel_down)))
        canvas.bind("<Leave>", lambda event: (canvas.unbind_all("<MouseWheel>"), canvas.unbind_all("<Button-4>"), canvas.unbind_all("<Button-5>")))

        content.columnconfigure(0, weight=1)
        ttk.Label(content, text="Settings", font=("Segoe UI", 13, "bold")).grid(row=0, column=0, sticky="w")
        text = (
            "Codex-style controls for Groq API access, automatic web intelligence, automation posture, visible guardrails, tool policy, and local privacy. "
            "Hard safety locks are shown here for auditability and remain enforced."
        )
        ttk.Label(content, text=text, wraplength=920).grid(row=1, column=0, sticky="w", pady=(8, 14))

        api = ttk.Frame(content)
        api.grid(row=2, column=0, sticky="ew")
        api.columnconfigure(1, weight=1)
        ttk.Label(api, text="Groq API key").grid(row=0, column=0, sticky="w")
        ttk.Entry(api, textvariable=self.groq_api_key, show="*").grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Label(api, text="Model").grid(row=0, column=2, sticky="w")
        ttk.Entry(api, textvariable=self.groq_model, width=28).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(api, text="Save Key", command=self._save_groq_key).grid(row=0, column=4, padx=(8, 0))
        ttk.Button(api, text="Load Key", command=self._load_groq_key).grid(row=0, column=5, padx=(8, 0))
        ttk.Label(api, text="Theme").grid(row=1, column=0, sticky="w", pady=(10, 0))
        ttk.Combobox(api, textvariable=self.theme_name, values=tuple(THEME_PRESETS), state="readonly", width=18).grid(row=1, column=1, sticky="w", padx=(8, 8), pady=(10, 0))
        ttk.Button(api, text="Apply Theme", command=self._apply_theme).grid(row=1, column=2, sticky="w", pady=(10, 0))
        ttk.Label(api, text="Auto web", style="PanelSubtle.TLabel").grid(row=1, column=3, padx=(12, 6), pady=(10, 0))
        ToggleSwitch(api, self.auto_web_intel, enabled=True).grid(row=1, column=4, padx=(0, 12), pady=(10, 0))
        ttk.Label(api, text="Full access", style="PanelSubtle.TLabel").grid(row=1, column=5, padx=(4, 6), pady=(10, 0))
        ToggleSwitch(api, self.local_full_access, enabled=True, command=self._toggle_full_access).grid(row=1, column=6, pady=(10, 0))

        guard = ttk.LabelFrame(content, text="Guardrails and professional controls", padding=10)
        guard.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        guard.columnconfigure(0, weight=1)
        for row, (key, label, default, editable, detail) in enumerate(GUARDRAIL_ITEMS):
            item = ttk.Frame(guard, style="Card.TFrame", padding=(12, 9))
            item.grid(row=row, column=0, sticky="ew", pady=4)
            item.columnconfigure(1, weight=1)
            ToggleSwitch(
                item,
                self.guardrail_vars[key],
                enabled=editable,
                command=lambda value, guard_key=key: self._guardrail_changed(guard_key, value),
            ).grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, 12))
            ttk.Label(item, text=label, style="CardTitle.TLabel").grid(row=0, column=1, sticky="w")
            badge_style = "Badge.TLabel" if editable else "LockedBadge.TLabel"
            badge_text = "CONFIGURABLE" if editable else "LOCKED"
            ttk.Label(item, text=badge_text, style=badge_style).grid(row=0, column=2, sticky="e", padx=(12, 0))
            ttk.Label(item, text=detail, wraplength=860, style="CardSubtle.TLabel").grid(row=1, column=1, columnspan=2, sticky="w", pady=(4, 0))

        policy = ttk.LabelFrame(content, text="Tool policy catalog", padding=10)
        policy.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        self.tool_policy_table = ttk.Treeview(policy, columns=("tool", "use", "status"), show="headings", height=8)
        for column, width in {"tool": 240, "use": 520, "status": 220}.items():
            self.tool_policy_table.heading(column, text=column.title())
            self.tool_policy_table.column(column, width=width, anchor="w")
        self.tool_policy_table.grid(row=0, column=0, sticky="ew")
        for item in TOOL_POLICY_CATALOG:
            self.tool_policy_table.insert("", tk.END, values=item)

        controls = ttk.Frame(content)
        controls.grid(row=5, column=0, sticky="w", pady=(12, 0))
        ttk.Button(controls, text="Clear Current Findings", command=self._clear_findings).grid(row=0, column=0)
        ttk.Button(controls, text="Clear Scope File", command=self._clear_scope_file).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(controls, text="Redacted Export", command=self._export_redacted_csv).grid(row=0, column=2, padx=(8, 0))

        self.privacy_output = tk.Text(content, wrap="word", height=8, bg="#0b1020", fg="#e5e7eb", insertbackground="#e5e7eb")
        self.privacy_output.grid(row=6, column=0, sticky="nsew", pady=(12, 0))
        self.privacy_output.insert(tk.END, "Settings log is local to this app session.\n")
        content.rowconfigure(6, weight=1)

    def _add_scope(self):
        added = self.scope.add(self.scope_entry.get())
        if added:
            self.scope_entry.delete(0, tk.END)
            self._refresh_scope()

    def _remove_scope(self):
        selected = list(self.scope_list.curselection())
        for index in reversed(selected):
            self.scope.remove(self.scope_list.get(index))
        self._refresh_scope()

    def _refresh_scope(self):
        self.scope_list.delete(0, tk.END)
        for item in self.scope.scope:
            self.scope_list.insert(tk.END, item)

    def _run_web_audit(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showinfo(APP_NAME, "Enter a target URL or domain.")
            return
        if not self.scope.is_allowed(target):
            messagebox.showwarning(APP_NAME, "Target is not in your authorized scope allowlist.")
            return
        self.web_output.delete("1.0", tk.END)
        self.web_output.insert(tk.END, f"Running safe audit for {target}...\n")
        self.status_text.set(f"Running web audit for {target}")
        threading.Thread(target=self._web_worker, args=(target,), daemon=True).start()

    def _web_worker(self, target):
        findings, evidence = web_audit(target)
        self.work_queue.put(("web", target, findings, evidence))

    def _run_wifi_audit(self):
        self.wifi_output.delete("1.0", tk.END)
        self.wifi_output.insert(tk.END, "Reviewing local Wi-Fi posture...\n")
        self.status_text.set("Reviewing local Wi-Fi posture")
        threading.Thread(target=self._wifi_worker, daemon=True).start()

    def _run_wifi_monitor(self):
        self.monitor_output.delete("1.0", tk.END)
        self.monitor_output.insert(tk.END, "Capturing passive Wi-Fi monitor snapshot...\n")
        self.status_text.set("Capturing Wi-Fi monitor snapshot")
        threading.Thread(target=self._wifi_monitor_worker, daemon=True).start()

    def _wifi_monitor_worker(self):
        findings, evidence = wifi_monitor_snapshot()
        self.work_queue.put(("monitor", "Nearby Wi-Fi", findings, evidence))

    def _incident_draft(self):
        draft = (
            "Incident report draft\n\n"
            f"Time: {dt.datetime.now().isoformat(timespec='seconds')}\n"
            "Reporter: Phoenix Guardian operator\n"
            "Summary: Suspicious or weak wireless posture was observed during authorized monitoring.\n"
            "Evidence: Attach exported findings and Wi-Fi monitor output.\n"
            "Recommended action: Preserve evidence, avoid disruptive countermeasures, rotate affected credentials, review router logs, and contact the network owner, ISP, platform, or appropriate authority if unauthorized activity is suspected.\n"
        )
        self.monitor_output.insert(tk.END, "\n\n" + draft)

    def _choose_fraud_csv(self):
        path = filedialog.askopenfilename(
            title="Select card transaction CSV",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
        )
        if path:
            self.fraud_dataset_path.set(path)
            self.fraud_output.delete("1.0", tk.END)
            self.fraud_output.insert(tk.END, f"Selected dataset:\n{path}\n\nRun forensic analysis to generate leads and a report.\n")

    def _run_fraud_analysis(self):
        path = self.fraud_dataset_path.get().strip()
        if not path:
            messagebox.showinfo(APP_NAME, "Choose a transaction CSV first.")
            return
        if not os.path.exists(path):
            messagebox.showwarning(APP_NAME, "The selected CSV file was not found.")
            return
        self.fraud_output.delete("1.0", tk.END)
        self.fraud_output.insert(tk.END, f"Analyzing card transaction evidence:\n{path}\n")
        self.status_text.set("Running card fraud forensic analysis")
        threading.Thread(target=self._fraud_worker, args=(path,), daemon=True).start()

    def _fraud_worker(self, path):
        try:
            findings, evidence, report = fraud_forensic_analysis(path)
            self.work_queue.put(("fraud", path, findings, evidence + [report]))
        except Exception as exc:
            finding = Finding(
                target=path,
                category="Card Fraud Forensics",
                severity="Info",
                title="Fraud analysis failed",
                detail=str(exc),
                remediation="Confirm the CSV is readable and includes columns such as timestamp, card token, amount, status, merchant, terminal, IP, or device.",
            )
            self.work_queue.put(("fraud", path, [finding], [str(exc), ""]))

    def _export_fraud_report(self):
        if not self.last_fraud_report:
            messagebox.showinfo(APP_NAME, "Run card fraud forensic analysis before exporting a detailed report.")
            return
        path = filedialog.asksaveasfilename(
            title="Export detailed fraud report",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("Markdown", "*.md"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.last_fraud_report)
        messagebox.showinfo(APP_NAME, f"Detailed report exported:\n{path}")

    def _bounty_target(self, require_scope=True):
        target = self.bounty_target_entry.get().strip() or self.drone_target_entry.get().strip() or self.target_entry.get().strip()
        if not target:
            messagebox.showinfo(APP_NAME, "Enter a bug bounty target URL or domain.")
            return ""
        if require_scope and not self.scope.is_allowed(target):
            messagebox.showwarning(APP_NAME, "Target is not in your authorized scope allowlist.")
            return ""
        return target

    def _run_bug_bounty_autopilot(self):
        target = self._bounty_target(require_scope=True)
        if not target:
            return
        self.bounty_output.delete("1.0", tk.END)
        self.bounty_output.insert(tk.END, f"Running bug bounty autopilot for {target}...\n")
        self.status_text.set(f"Running bug bounty autopilot for {target}")
        threading.Thread(target=self._bug_bounty_worker, args=(target,), daemon=True).start()

    def _bug_bounty_worker(self, target):
        try:
            findings, evidence = bug_bounty_autopilot(target)
            self.work_queue.put(("bounty", target, findings, evidence))
        except Exception as exc:
            finding = Finding(
                target=target,
                category="Bug Bounty",
                severity="Info",
                title="Bug bounty autopilot failed",
                detail=str(exc),
                remediation="Confirm network access, target scope, and Kali WSL availability, then rerun.",
            )
            self.work_queue.put(("bounty", target, [finding], [str(exc)]))

    def _run_burp_status(self):
        self.bounty_output.delete("1.0", tk.END)
        self.bounty_output.insert(tk.END, "Checking Burp Suite status...\n")
        self.status_text.set("Checking Burp Suite status")
        threading.Thread(target=self._burp_status_worker, daemon=True).start()

    def _burp_status_worker(self):
        findings, evidence = burp_suite_status()
        self.work_queue.put(("bounty", "Burp Suite", findings, evidence))

    def _launch_burp(self):
        self.bounty_output.insert(tk.END, "\nRequesting Burp Suite launch in Kali WSL...\n")
        self.status_text.set("Launching Burp Suite")
        threading.Thread(target=self._launch_burp_worker, daemon=True).start()

    def _launch_burp_worker(self):
        output = launch_burp_suite()
        finding = Finding(
            target="Burp Suite",
            category="Burp Suite",
            severity="Info",
            title="Burp launch requested",
            detail="Phoenix Guardian asked Kali WSL to start Burp Suite.",
            remediation="Confirm Burp opened and that proxy listener settings match the app's Burp proxy configuration.",
        )
        self.work_queue.put(("bounty", "Burp Suite", [finding], [output]))

    def _run_burp_probe(self):
        target = self._bounty_target(require_scope=True)
        if not target:
            return
        self.bounty_output.delete("1.0", tk.END)
        self.bounty_output.insert(tk.END, f"Sending header-only probe through Burp for {target}...\n")
        self.status_text.set(f"Running Burp proxy probe for {target}")
        threading.Thread(target=self._burp_probe_worker, args=(target,), daemon=True).start()

    def _burp_probe_worker(self, target):
        findings, evidence = burp_proxy_probe(target)
        self.work_queue.put(("bounty", target, findings, evidence))

    def _run_online_osint(self):
        target = self._bounty_target(require_scope=True)
        if not target:
            return
        self.bounty_output.delete("1.0", tk.END)
        self.bounty_output.insert(tk.END, f"Collecting online OSINT for {target}...\n")
        self.status_text.set(f"Collecting online OSINT for {target}")
        threading.Thread(target=self._online_osint_worker, args=(target,), daemon=True).start()

    def _online_osint_worker(self, target):
        findings, evidence = online_osint(target)
        self.work_queue.put(("bounty", target, findings, evidence))

    def _run_wordlist_catalog(self):
        self.bounty_output.delete("1.0", tk.END)
        self.bounty_output.insert(tk.END, "Cataloging Kali wordlists and password lists for offline/lab use...\n")
        self.status_text.set("Cataloging wordlists")
        threading.Thread(target=self._wordlist_worker, daemon=True).start()

    def _wordlist_worker(self):
        output = wordlist_catalog()
        finding = Finding(
            target="Kali wordlists",
            category="Bug Bounty",
            severity="Info",
            title="Wordlist catalog completed",
            detail="Local wordlists and password-list paths were cataloged for offline auditing, content discovery planning, and lab use.",
            remediation="Do not use password lists for live credential attacks. Use content wordlists only where the program policy permits low-rate discovery.",
        )
        self.work_queue.put(("bounty", "Kali wordlists", [finding], [output]))

    def _run_full_tool_inventory(self):
        self.bounty_output.delete("1.0", tk.END)
        self.bounty_output.insert(tk.END, "Building broad cybersecurity tool inventory from Kali PATH...\n")
        self.status_text.set("Building broad cybersecurity inventory")
        threading.Thread(target=self._full_tool_inventory_worker, daemon=True).start()

    def _full_tool_inventory_worker(self):
        output = kali_full_tool_inventory()
        finding = Finding(
            target="Kali tools",
            category="Bug Bounty",
            severity="Info",
            title="Broad cybersecurity tool inventory completed",
            detail="Phoenix Guardian listed security-relevant commands available in Kali PATH.",
            remediation="Use tools only for authorized, policy-compliant testing and defensive validation.",
        )
        self.work_queue.put(("bounty", "Kali tools", [finding], [output]))

    def _show_bounty_checklist(self):
        self.bounty_output.delete("1.0", tk.END)
        self.bounty_output.insert(tk.END, vulnerability_checklist_text())

    def _show_money_report(self):
        money = monetary_estimate(self.findings)
        lines = [
            "Phoenix Guardian Monetary Readiness",
            f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}",
            "",
            f"Estimated bounty band: {money['bounty_band']}",
            f"Estimated remediation cost: {money['remediation_cost']}",
            f"Exposure note: {money['exposure_note']}",
            "",
            "Highest-value bug bounty classes to validate carefully:",
        ]
        lines.extend(f"- {name}" for name in VULNERABILITY_TAXONOMY[:20])
        lines.append("\nThese estimates help prioritize work. Actual payout depends on program policy, duplicate status, exploitability, and evidence quality.")
        self.bounty_output.delete("1.0", tk.END)
        self.bounty_output.insert(tk.END, "\n".join(lines))

    def _open_hackerone_login(self):
        webbrowser.open("https://hackerone.com/users/sign_in")
        self.status_text.set("Opened HackerOne login")

    def _open_hackerone_api_token(self):
        webbrowser.open("https://hackerone.com/settings/api_token/edit")
        self.status_text.set("Opened HackerOne API token settings")

    def _h1_credentials(self):
        return self.h1_username.get().strip(), self.h1_token.get().strip(), self.h1_program_handle.get().strip()

    def _fetch_hackerone_scope(self):
        username, token, handle = self._h1_credentials()
        if not handle:
            messagebox.showinfo(APP_NAME, "Enter a HackerOne program handle.")
            return
        self.bounty_output.delete("1.0", tk.END)
        self.bounty_output.insert(tk.END, f"Fetching HackerOne rules and structured scope for {handle}...\n")
        threading.Thread(target=self._hackerone_scope_worker, args=(username, token, handle), daemon=True).start()

    def _hackerone_scope_worker(self, username, token, handle):
        program_status, program = hackerone_program(username, token, handle)
        scope_status, scopes = hackerone_structured_scopes(username, token, handle)
        evidence = [
            f"Program HTTP status: {program_status}",
            f"Scope HTTP status: {scope_status}",
            hackerone_policy_summary(program if isinstance(program, dict) else {}, scopes if isinstance(scopes, dict) else {}),
        ]
        finding = Finding(
            target=f"HackerOne:{handle}",
            category="HackerOne",
            severity="Info",
            title="HackerOne rules and scope fetched",
            detail=f"Fetched program policy and {len((scopes or {}).get('data', [])) if isinstance(scopes, dict) else 0} structured scope entries.",
            remediation="Review policy and test only eligible in-scope assets.",
        )
        self._last_h1_program = program
        self._last_h1_scopes = scopes
        self.work_queue.put(("bounty", f"HackerOne:{handle}", [finding], evidence))

    def _import_scope_file(self):
        default_path = "/mnt/c/Users/f/.codex/attachments/ffd40446-3d7f-4bf2-ab00-7639503531d1/pasted-text.txt"
        path = default_path if os.path.exists(default_path) else filedialog.askopenfilename(
            title="Import HackerOne scope text",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                text = handle.read()
            self.imported_scope_entries = parse_scope_text(text)
            if "shopify" in text.lower():
                self.h1_program_handle.set("shopify")
            self.h1_researcher_tag.set("james1956")
            summary = imported_scope_summary(self.imported_scope_entries)
            self.bounty_output.delete("1.0", tk.END)
            self.bounty_output.insert(tk.END, f"Imported scope file:\n{path}\n\n{summary}")
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))

    def _add_hackerone_scope_to_allowlist(self):
        scopes = getattr(self, "_last_h1_scopes", None)
        imported = getattr(self, "imported_scope_entries", [])
        if not scopes and not imported:
            messagebox.showinfo(APP_NAME, "Fetch HackerOne scope first.")
            return
        added = []
        if scopes:
            for item in scopes.get("data", []):
                attrs = item.get("attributes", {})
                if not attrs.get("eligible_for_submission"):
                    continue
                target = scope_asset_to_target(item)
                if target:
                    normalized = self.scope.add(target)
                    if normalized:
                        added.append(normalized)
        for item in imported:
            if not item.get("eligible"):
                continue
            asset = item.get("asset_identifier", "")
            if item.get("asset_type") not in {"Domain", "Wildcard"}:
                continue
            target = host_for_target(asset.replace("*.", ""))
            if target:
                normalized = self.scope.add(target)
                if normalized:
                    added.append(normalized)
        self._refresh_scope()
        self.bounty_output.insert(tk.END, f"\nAdded/confirmed {len(added)} HackerOne scope assets in Phoenix Guardian allowlist.\n")

    def _run_hackerone_automation(self):
        username, token, handle = self._h1_credentials()
        if not handle:
            messagebox.showinfo(APP_NAME, "Enter a HackerOne program handle.")
            return
        self.bounty_output.delete("1.0", tk.END)
        self.bounty_output.insert(tk.END, f"Running HackerOne-aware bug bounty automation for {handle}...\n")
        self.status_text.set(f"Running HackerOne automation for {handle}")
        threading.Thread(target=self._hackerone_automation_worker, args=(username, token, handle), daemon=True).start()

    def _hackerone_automation_worker(self, username, token, handle):
        program_status, program = hackerone_program(username, token, handle)
        scope_status, scopes = hackerone_structured_scopes(username, token, handle)
        findings = []
        evidence = [f"Program HTTP status: {program_status}", f"Scope HTTP status: {scope_status}"]
        evidence.append(hackerone_policy_summary(program if isinstance(program, dict) else {}, scopes if isinstance(scopes, dict) else {}))
        scope_items = []
        if isinstance(scopes, dict):
            for item in scopes.get("data", []):
                attrs = item.get("attributes", {})
                if attrs.get("eligible_for_submission"):
                    target = scope_asset_to_target(item)
                    if target:
                        scope_items.append((target, attrs))
        limit = max(1, int(self.h1_scope_limit.get() or 3))
        researcher_tag = self.h1_researcher_tag.get().strip()
        created_intents = []
        for target, attrs in scope_items[:limit]:
            self.scope.add(target)
            bounty_findings, bounty_evidence = bug_bounty_autopilot(target)
            findings.extend(bounty_findings)
            evidence.append(f"=== Automation target: {target} ===\nScope instruction: {attrs.get('instruction', '')}\n" + "\n\n".join(bounty_evidence))
            if self.h1_auto_create_intents.get():
                report = bug_bounty_report(target, bounty_findings, bounty_evidence)
                description = (
                    f"{report}\n\n"
                    f"HackerOne researcher tag/handle: {researcher_tag or 'not provided'}\n"
                    f"Program handle: {handle}\n"
                    "Generated by Phoenix Guardian after reading structured scope and policy."
                )
                status, payload = hackerone_create_report_intent(username, token, handle, description[:30000])
                evidence.append(f"=== HackerOne report intent for {target}: HTTP {status} ===\n{json.dumps(payload, indent=2)[:5000]}")
                if isinstance(payload, dict) and payload.get("data", {}).get("id"):
                    intent_id = str(payload["data"]["id"])
                    created_intents.append(intent_id)
                    self.h1_last_intent_id.set(intent_id)
        self._refresh_scope()
        findings.append(Finding(
            target=f"HackerOne:{handle}",
            category="HackerOne",
            severity="Info",
            title="HackerOne automation cycle completed",
            detail=f"Processed {min(limit, len(scope_items))} eligible scope assets and created {len(created_intents)} report intents.",
            remediation="Review created report intents, confirm HackerOne readiness, and submit only validated reports.",
        ))
        self.work_queue.put(("bounty", f"HackerOne:{handle}", findings, evidence))

    def _run_imported_scope_automation(self):
        if not self.imported_scope_entries:
            self._import_scope_file()
        if not self.imported_scope_entries:
            return
        handle = self.h1_program_handle.get().strip() or "shopify"
        self.bounty_output.delete("1.0", tk.END)
        self.bounty_output.insert(tk.END, f"Running imported-scope bug bounty automation for {handle}...\n")
        self.status_text.set(f"Running imported-scope automation for {handle}")
        threading.Thread(target=self._imported_scope_automation_worker, args=(handle,), daemon=True).start()

    def _imported_scope_automation_worker(self, handle):
        username, token, _ = self._h1_credentials()
        limit = max(1, int(self.h1_scope_limit.get() or 3))
        researcher_tag = self.h1_researcher_tag.get().strip() or "james1956"
        eligible = []
        for item in self.imported_scope_entries:
            if not item.get("eligible"):
                continue
            if item.get("asset_type") not in {"Domain", "Wildcard"}:
                continue
            asset = item.get("asset_identifier", "")
            if not asset or "your-store.myshopify.com" in asset:
                continue
            target = host_for_target(asset.replace("*.", ""))
            if target:
                eligible.append((target, item))

        findings = []
        evidence = [
            imported_scope_summary(self.imported_scope_entries),
            f"Researcher tag/handle: {researcher_tag}",
            f"Program handle: {handle}",
            f"Automation target limit: {limit}",
        ]
        created_intents = []
        for target, item in eligible[:limit]:
            self.scope.add(target)
            bounty_findings, bounty_evidence = bug_bounty_autopilot(target)
            findings.extend(bounty_findings)
            report = bug_bounty_report(target, bounty_findings, bounty_evidence)
            evidence.append(
                f"=== Imported scope target: {target} ===\n"
                f"Severity: {item.get('max_severity', 'unknown')}\n"
                f"Environment: {item.get('environment', 'unknown')}\n"
                f"Notes: {' '.join(item.get('notes', []))[:500]}\n\n"
                + "\n\n".join(bounty_evidence)
            )
            if self.h1_auto_create_intents.get() and username and token:
                description = (
                    f"{report}\n\n"
                    f"HackerOne researcher tag/handle: {researcher_tag}\n"
                    f"Program handle: {handle}\n"
                    "Scope source: imported HackerOne scope file."
                )
                status, payload = hackerone_create_report_intent(username, token, handle, description[:30000])
                evidence.append(f"=== HackerOne report intent for {target}: HTTP {status} ===\n{json.dumps(payload, indent=2)[:5000]}")
                if isinstance(payload, dict) and payload.get("data", {}).get("id"):
                    intent_id = str(payload["data"]["id"])
                    created_intents.append(intent_id)
                    self.h1_last_intent_id.set(intent_id)
            elif self.h1_auto_create_intents.get():
                evidence.append("=== HackerOne report intent skipped ===\nMissing HackerOne username/token in the app or environment.")

        self._refresh_scope()
        findings.append(Finding(
            target=f"HackerOne:{handle}",
            category="HackerOne",
            severity="Info",
            title="Imported HackerOne scope automation completed",
            detail=f"Processed {min(limit, len(eligible))} eligible imported scope assets and created {len(created_intents)} report intents.",
            remediation="Review report intent drafts and submit only validated reports that satisfy Shopify/HackerOne rules.",
        ))
        self.work_queue.put(("bounty", f"HackerOne:{handle}", findings, evidence))

    def _create_hackerone_intent(self):
        username, token, handle = self._h1_credentials()
        if not handle:
            messagebox.showinfo(APP_NAME, "Enter a HackerOne program handle.")
            return
        target = self.bounty_target_entry.get().strip() or "Current findings"
        report = self.last_bug_bounty_report or bug_bounty_report(target, self.findings, ["Manual report generated from current findings."])
        researcher_tag = self.h1_researcher_tag.get().strip()
        description = f"{report}\n\nHackerOne researcher tag/handle: {researcher_tag or 'not provided'}\nProgram handle: {handle}"
        self.bounty_output.insert(tk.END, f"\nCreating HackerOne report intent for {handle}...\n")
        threading.Thread(target=self._create_hackerone_intent_worker, args=(username, token, handle, description), daemon=True).start()

    def _create_hackerone_intent_worker(self, username, token, handle, description):
        status, payload = hackerone_create_report_intent(username, token, handle, description[:30000])
        if isinstance(payload, dict) and payload.get("data", {}).get("id"):
            self.h1_last_intent_id.set(str(payload["data"]["id"]))
        finding = Finding(
            target=f"HackerOne:{handle}",
            category="HackerOne",
            severity="Info",
            title="HackerOne report intent created",
            detail=f"HackerOne returned HTTP {status}. Last intent id: {self.h1_last_intent_id.get() or 'not returned'}.",
            remediation="Check the report intent, complete any required fields, then submit only when ready.",
        )
        self.work_queue.put(("bounty", f"HackerOne:{handle}", [finding], [json.dumps(payload, indent=2)[:10000]]))

    def _check_hackerone_intent(self):
        username, token, handle = self._h1_credentials()
        intent_id = self.h1_last_intent_id.get().strip()
        if not intent_id:
            messagebox.showinfo(APP_NAME, "No HackerOne report intent id is set.")
            return
        threading.Thread(target=self._check_hackerone_intent_worker, args=(username, token, intent_id), daemon=True).start()

    def _check_hackerone_intent_worker(self, username, token, intent_id):
        status, payload = hackerone_get_report_intent(username, token, intent_id)
        finding = Finding(
            target=f"HackerOne intent {intent_id}",
            category="HackerOne",
            severity="Info",
            title="HackerOne report intent checked",
            detail=f"HackerOne returned HTTP {status}.",
            remediation="Submit only when the intent is ready and the report is accurate.",
        )
        self.work_queue.put(("bounty", f"HackerOne intent {intent_id}", [finding], [json.dumps(payload, indent=2)[:10000]]))

    def _submit_hackerone_intent(self):
        username, token, handle = self._h1_credentials()
        intent_id = self.h1_last_intent_id.get().strip()
        if not intent_id:
            messagebox.showinfo(APP_NAME, "No HackerOne report intent id is set.")
            return
        if not messagebox.askyesno(APP_NAME, f"Submit HackerOne report intent {intent_id}? Confirm you reviewed scope, policy, evidence, and report quality."):
            return
        threading.Thread(target=self._submit_hackerone_intent_worker, args=(username, token, intent_id), daemon=True).start()

    def _submit_hackerone_intent_worker(self, username, token, intent_id):
        status, payload = hackerone_submit_report_intent(username, token, intent_id)
        finding = Finding(
            target=f"HackerOne intent {intent_id}",
            category="HackerOne",
            severity="Info",
            title="HackerOne report intent submit requested",
            detail=f"HackerOne returned HTTP {status}.",
            remediation="Monitor HackerOne for triage response and promptly answer follow-up questions.",
        )
        self.work_queue.put(("bounty", f"HackerOne intent {intent_id}", [finding], [json.dumps(payload, indent=2)[:10000]]))

    def _export_bug_bounty_report(self):
        if not self.last_bug_bounty_report:
            target = self.bounty_target_entry.get().strip() or "Current findings"
            self.last_bug_bounty_report = bug_bounty_report(target, self.findings, ["Manual report generated from current findings."])
        path = filedialog.asksaveasfilename(
            title="Export bug bounty report",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("Markdown", "*.md"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.last_bug_bounty_report)
        messagebox.showinfo(APP_NAME, f"Bug bounty report exported:\n{path}")

    def _run_kali_inventory(self):
        self.drone_output.delete("1.0", tk.END)
        self.drone_output.insert(tk.END, "Checking Kali WSL tool inventory...\n")
        self.status_text.set("Checking Kali WSL tool inventory")
        threading.Thread(target=self._kali_inventory_worker, daemon=True).start()

    def _kali_inventory_worker(self):
        output = kali_tool_inventory(distro=self.wsl_distro.get().strip() or "kali-linux")
        self.work_queue.put(("drone_text", "Kali inventory", [], [output]))

    def _launch_admin_kali(self):
        self.drone_output.insert(tk.END, "\nRequesting elevated PowerShell for Kali WSL. Approve the Windows UAC prompt if it appears.\n")
        self.status_text.set("Requesting elevated Kali WSL PowerShell")
        threading.Thread(target=self._admin_kali_worker, daemon=True).start()

    def _admin_kali_worker(self):
        distro = self.wsl_distro.get().strip() or "kali-linux"
        output = launch_admin_kali_powershell(distro)
        note = output or f"Windows was asked to open an elevated PowerShell session running: wsl.exe -d {distro}"
        self.work_queue.put(("drone_text", "Admin WSL requested", [], [note]))

    def _run_cybersecurity_drone(self):
        self.drone_task.set("Cybersecurity Drone")
        self._run_kali_drone()

    def _run_defensive_drone(self):
        self.drone_task.set("Defensive Response Drone")
        self._run_kali_drone()

    def _run_kali_drone(self):
        target = self.drone_target_entry.get().strip()
        task = self.drone_task.get()
        if not target and task != "Defensive Response Drone":
            messagebox.showinfo(APP_NAME, "Enter a target URL or domain.")
            return
        if target and not self.scope.is_allowed(target):
            messagebox.showwarning(APP_NAME, "Target is not in your authorized scope allowlist.")
            return
        self.drone_output.delete("1.0", tk.END)
        label = target or "local defensive posture"
        self.drone_output.insert(tk.END, f"Launching {task} for {label}...\n")
        self.status_text.set(f"Launching {task} for {label}")
        threading.Thread(target=self._kali_drone_worker, args=(task, target), daemon=True).start()

    def _kali_drone_worker(self, task, target):
        distro = self.wsl_distro.get().strip() or "kali-linux"
        if task == "Cybersecurity Drone":
            findings, evidence = cybersecurity_drone(target, distro=distro)
        elif task == "Defensive Response Drone":
            findings, evidence = defensive_response_drone(target=target, fraud_path=self.fraud_dataset_path.get().strip())
        else:
            output = kali_drone_task(task, target, distro=distro)
            findings = [Finding(
                target=target,
                category="Kali Drone",
                severity="Info",
                title=f"{task} completed",
                detail=f"A scoped Kali WSL posture task completed using the {task} profile. Review evidence output for details.",
                remediation="Use the output to prioritize manual validation and defensive fixes.",
            )]
            evidence = [output]
        self.work_queue.put(("drone", target or "Local defensive posture", findings, evidence))

    def _run_ghidra_inventory(self):
        self.ghidra_output.delete("1.0", tk.END)
        self.ghidra_output.insert(tk.END, "Checking for Ghidra in Kali WSL and Windows PATH...\n")
        threading.Thread(target=self._ghidra_inventory_worker, daemon=True).start()

    def _ghidra_inventory_worker(self):
        output = run_wsl_command(
            "command -v ghidraRun || command -v analyzeHeadless || echo 'Ghidra not found in WSL PATH.'",
            distro=self.wsl_distro.get().strip() or "kali-linux",
            timeout=20,
        )
        local = run_command(["where", "ghidraRun"]) if os.name == "nt" else "Windows PATH check skipped."
        self.work_queue.put(("ghidra_text", "Ghidra inventory", [], [f"Kali WSL:\n{output}\n\nWindows PATH:\n{local}"]))

    def _hash_sample(self):
        path = filedialog.askopenfilename(title="Select suspicious sample to hash")
        if not path:
            return
        try:
            digest = hashlib.sha256()
            size = 0
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    size += len(chunk)
                    digest.update(chunk)
            self.ghidra_output.insert(tk.END, f"\nSample: {path}\nSize: {size} bytes\nSHA256: {digest.hexdigest()}\n")
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))

    def _ghidra_case_notes(self):
        notes = (
            "Defensive reverse-engineering case notes\n\n"
            f"Opened: {dt.datetime.now().isoformat(timespec='seconds')}\n"
            "Purpose: Analyze a suspicious binary or artifact from an owned system or authorized investigation.\n"
            "Handling: Preserve original sample, work from a copy, record SHA256, avoid executing unknown code, and document indicators.\n"
            "Network note: Do not attempt Tor deanonymization or unauthorized tracking. Use lawful logs, consent-based telemetry, and provider/authority reporting channels.\n"
        )
        self.ghidra_output.insert(tk.END, "\n" + notes)

    def _run_web_search(self):
        query = self.web_search_query.get().strip()
        if not query:
            messagebox.showinfo(APP_NAME, "Enter a web search query.")
            return
        self.webintel_output.delete("1.0", tk.END)
        self.webintel_output.insert(tk.END, f"Searching web for: {query}\n")
        self.status_text.set("Running web search")
        threading.Thread(target=self._web_search_worker, args=(query,), daemon=True).start()

    def _run_target_web_search(self):
        target = self.bounty_target_entry.get().strip() or self.target_entry.get().strip()
        if not target:
            messagebox.showinfo(APP_NAME, "Enter a target first.")
            return
        query = f"{host_for_target(target)} security.txt bug bounty vulnerability disclosure CVE"
        self.web_search_query.set(query)
        self._run_web_search()

    def _web_search_worker(self, query):
        report = web_search_report(query)
        self.work_queue.put(("webintel", query, [], [report]))

    def _open_browser_url(self):
        url = self.browser_url.get().strip()
        if not url:
            messagebox.showinfo(APP_NAME, "Enter a browser URL.")
            return
        webbrowser.open(ensure_url(url))
        self.status_text.set(f"Opened browser URL: {host_for_target(url)}")

    def _browser_shopify(self):
        self.browser_url.set("https://hackerone.com/shopify?type=team")
        self._open_browser_url()

    def _fetch_browser_context(self):
        url = self.browser_url.get().strip()
        if not url:
            messagebox.showinfo(APP_NAME, "Enter a browser URL.")
            return
        self.browser_output.delete("1.0", tk.END)
        self.browser_output.insert(tk.END, f"Fetching public page context for {url}...\n")
        self.status_text.set("Fetching browser context")
        threading.Thread(target=self._browser_context_worker, args=(url,), daemon=True).start()

    def _browser_context_worker(self, url):
        try:
            status, content_type, body = fetch_url_text(ensure_url(url), timeout=18, limit=220000)
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            title = html.unescape(re.sub(r"\s+", " ", title_match.group(1)).strip()) if title_match else "No title parsed"
            text = re.sub(r"<(script|style).*?</\1>", " ", body, flags=re.I | re.S)
            text = html.unescape(re.sub(r"<[^>]+>", " ", text))
            text = re.sub(r"\s+", " ", text).strip()
            report = (
                f"Browser Bridge Context\nURL: {ensure_url(url)}\nHTTP: {status}\nContent-Type: {content_type}\nTitle: {title}\n\n"
                f"Extracted text preview:\n{text[:6000]}"
            )
        except Exception as exc:
            report = f"Browser context fetch failed for {url}: {exc}"
        self.work_queue.put(("browser", url, [], [report]))

    def _run_current_vectors(self):
        query = self.current_vector_query.get().strip()
        target = self.command_target.get().strip() or self.bounty_target_entry.get().strip() or self.target_entry.get().strip()
        self.vectors_output.delete("1.0", tk.END)
        self.vectors_output.insert(tk.END, f"Refreshing live cyber vectors for {query or target or 'general bug bounty'}...\n")
        self.status_text.set("Refreshing current cyber vectors")
        threading.Thread(target=self._current_vectors_worker, args=(query, target), daemon=True).start()

    def _current_vectors_worker(self, query, target):
        report = current_vectors_report(query=query, target=target, days=14)
        finding = Finding(
            target=target or query or "Current vectors",
            category="Current Vectors",
            severity="Info",
            title="Current vector intelligence refreshed",
            detail="Pulled public vulnerability intelligence and mapped it into safe bug bounty validation playbooks.",
            remediation="Use this intelligence to prioritize in-scope evidence collection and remediation guidance.",
        )
        self.work_queue.put(("vectors", target or query or "Current vectors", [finding], [report]))

    def _run_scope_vector_burst(self):
        targets = list(self.scope.scope)[:5]
        if not targets:
            messagebox.showinfo(APP_NAME, "Add authorized scope first.")
            return
        self.vectors_output.delete("1.0", tk.END)
        self.vectors_output.insert(tk.END, f"Running current-vector burst for {len(targets)} scoped targets...\n")
        self.status_text.set("Running scoped vector burst")
        threading.Thread(target=self._scope_vector_burst_worker, args=(targets,), daemon=True).start()

    def _scope_vector_burst_worker(self, targets):
        findings = []
        evidence = []
        for target in targets:
            report = current_vectors_report(query=f"{target} bug bounty security", target=target, days=14)
            evidence.append(f"=== {target} ===\n{report}")
            findings.append(Finding(
                target=target,
                category="Current Vectors",
                severity="Info",
                title="Scoped current-vector burst completed",
                detail="Collected current public vulnerability context for this in-scope target.",
                remediation="Prioritize safe validation against program rules and attach only relevant evidence.",
            ))
        self.work_queue.put(("vectors", "Scoped vector burst", findings, evidence))

    def _run_code_inventory(self):
        self.code_output.delete("1.0", tk.END)
        self.code_output.insert(tk.END, "Inventorying local language runtimes, package managers, and security audit tools...\n")
        self.status_text.set("Running Code Lab inventory")
        threading.Thread(target=self._code_inventory_worker, daemon=True).start()

    def _code_inventory_worker(self):
        distro = self.wsl_distro.get().strip() or "kali-linux"
        commands = [
            "python3 --version", "pip3 --version", "node --version", "npm --version",
            "go version", "rustc --version", "cargo --version", "java -version",
            "javac -version", "dotnet --info", "php -v", "ruby -v", "perl -v",
            "pwsh -v", "semgrep --version", "trivy --version", "syft version",
            "osv-scanner --version", "checkov --version", "tfsec --version",
            "prowler --version", "trufflehog --version", "cosign version",
        ]
        script_lines = [
            "echo '[WSL2 distro]'; cat /etc/os-release 2>/dev/null | head -8 || true",
            "echo; echo '[Language and security tooling]';",
        ]
        for command in commands:
            quoted = shlex.quote(command)
            script_lines.append(f"echo '$ {command}'; bash -lc {quoted} 2>&1 | head -20 || true; echo")
        wsl_report = run_wsl_command("; ".join(script_lines), distro=distro, timeout=90)
        windows_commands = [
            ["python", "--version"], ["node", "--version"], ["git", "--version"],
            ["powershell.exe", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"],
        ]
        windows_lines = ["[Windows runtime check]"]
        for command in windows_commands:
            windows_lines.append("$ " + " ".join(command))
            windows_lines.append(run_command(command))
        report = (
            "Phoenix Guardian Code Lab Inventory\n"
            f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}\n"
            f"Focus: {self.code_lab_query.get().strip()}\n"
            f"WSL2 distro: {distro}\n\n"
            f"{wsl_report}\n\n" + "\n".join(windows_lines)
        )
        finding = Finding(
            target="Code Lab",
            category="Code Lab",
            severity="Info",
            title="Language and audit-tool inventory completed",
            detail="Inventoried local runtimes, package managers, SBOM, IaC, container, secrets, and LLM-adjacent security tooling.",
            remediation="Install missing tools only as needed for authorized local audit workflows.",
        )
        self.work_queue.put(("code", "Code Lab", [finding], [report]))

    def _secure_script_notes(self):
        notes = [
            "Secure Audit Script Notes",
            f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}",
            "",
            "Supported local automation languages",
            "- Python: CSV/JSON parsing, report generation, API clients, forensic triage, pytest-based checks.",
            "- JavaScript/Node: browser automation, API test harnesses, dependency review, Playwright validation.",
            "- Go/Rust: fast local parsers, log tooling, SBOM helpers, signed release utilities.",
            "- Java/.NET/PHP/Ruby: dependency and framework-specific review when the target stack requires it.",
            "- PowerShell/Bash: WSL2, Windows posture, evidence collection, and reproducible command wrappers.",
            "",
            "Enterprise coding posture",
            "- Store secrets in environment variables or OS vaults, never in source or exported reports.",
            "- Prefer structured parsers over regex when handling CSV, JSON, XML, JWT, HTTP, or logs.",
            "- Redact tokens, cookies, customer data, and card data before sending context to Groq or HackerOne.",
            "- Keep destructive actions behind explicit local confirmation and scope checks.",
        ]
        self.code_output.delete("1.0", tk.END)
        self.code_output.insert(tk.END, "\n".join(notes))

    def _llm_app_checklist(self):
        checklist = [
            "LLM / Agentic App Security Checklist",
            f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}",
            "",
            "- Prompt injection: test benign instruction conflicts and verify system/tool policy wins.",
            "- Tool authorization: confirm every action has scoped permissions, logging, and user intent.",
            "- RAG leakage: verify private documents cannot be retrieved across tenants or roles.",
            "- Secret handling: scan traces, prompts, tool outputs, and reports for API keys and tokens.",
            "- Output trust: treat model output as untrusted until validated by code or human review.",
            "- Audit trail: preserve prompts, tool calls, timestamps, source URLs, and redaction evidence.",
            "- Model fallback: make provider/model errors visible and actionable without exposing keys.",
        ]
        self.code_output.delete("1.0", tk.END)
        self.code_output.insert(tk.END, "\n".join(checklist))

    def _run_wsl_terminal_command(self):
        command = self.wsl_command_text.get().strip()
        if not command:
            messagebox.showinfo(APP_NAME, "Enter a Kali command.")
            return
        if contains_blocked_intent(command):
            messagebox.showwarning(APP_NAME, "This command matches a hard-blocked unsafe category.")
            return
        self.terminal_output.insert(tk.END, f"\n$ {command}\nRunning...\n")
        self.status_text.set("Running Kali command")
        threading.Thread(target=self._wsl_terminal_worker, args=(command, self.wsl_distro.get().strip() or "kali-linux"), daemon=True).start()

    def _wsl_terminal_worker(self, command, distro):
        output = run_wsl_command(command, distro=distro, timeout=120)
        self.work_queue.put(("terminal", command, [], [output]))

    def _open_interactive_wsl(self):
        output = open_interactive_kali_terminal(self.wsl_distro.get().strip() or "kali-linux")
        self.terminal_output.insert(tk.END, "\nRequested external interactive Kali WSL shell.\n" + (output or "") + "\n")

    def _ask_chatgpt(self):
        text = self.chat_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo(APP_NAME, "Type a message for Groq Command.")
            return
        self.chat_output.insert(tk.END, f"\nYou:\n{text}\n")
        self.chat_input.delete("1.0", tk.END)
        context = (
            f"Scope: {', '.join(self.scope.scope)}\n"
            f"Findings: {len(self.findings)}\n"
            f"Top summary:\n{ai_summary(self.findings)[:1500]}"
        )
        api_key = self.groq_api_key.get().strip()
        model = self.groq_model.get().strip()
        auto_web = self.auto_web_intel.get()
        scope_snapshot = list(self.scope.scope)
        self.status_text.set("Asking Groq Command")
        threading.Thread(target=self._chatgpt_worker, args=(text, context, api_key, model, auto_web, scope_snapshot), daemon=True).start()

    def _test_groq(self):
        api_key = self.groq_api_key.get().strip()
        model = self.groq_model.get().strip()
        self.chat_output.insert(tk.END, "\nPhoenix Guardian:\nTesting Groq API connectivity...\n")
        self.status_text.set("Testing Groq API")
        threading.Thread(
            target=self._chatgpt_worker,
            args=("Reply with: Phoenix Guardian Groq check OK.", "API connectivity test.", api_key, model, False, []),
            daemon=True,
        ).start()

    def _chatgpt_worker(self, text, context, api_key, model, auto_web, scope_snapshot):
        web_context = automatic_web_context(text, scope_snapshot) if auto_web else ""
        response = groq_chat_response(api_key, model, text, context=context, web_context=web_context)
        action = self._extract_chat_action(response)
        self.pending_chat_action = action
        if action and action != "none":
            response += f"\n\nPending safe action: {action}"
            if self.chat_preapprove.get():
                response += "\nPre-approval is on; running action now."
                self.work_queue.put(("chat", text, [], [response]))
                self._execute_chat_action(action)
                return
        self.work_queue.put(("chat", text, [], [response]))

    def _extract_chat_action(self, response):
        for line in reversed((response or "").splitlines()):
            if line.strip().lower().startswith("action:"):
                return line.split(":", 1)[1].strip()
        return None

    def _run_pending_chat_action(self):
        if not self.pending_chat_action or self.pending_chat_action == "none":
            messagebox.showinfo(APP_NAME, "No pending safe chat action.")
            return
        self._execute_chat_action(self.pending_chat_action)

    def _execute_chat_action(self, action):
        if contains_blocked_intent(action):
            self.work_queue.put(("chat", "Groq", [], ["Blocked pending action because it matched a hard safety category."]))
            return
        if action.startswith("web_search:"):
            query = action.split(":", 1)[1].strip()
            self.web_search_query.set(query)
            self._run_web_search()
        elif action == "current_vectors":
            self._run_current_vectors()
        elif action == "kali_inventory":
            self._run_kali_inventory()
        elif action == "wordlists":
            self._run_wordlist_catalog()
        elif action == "burp_status":
            self._run_burp_status()
        elif action == "bug_bounty_autopilot":
            self._run_bug_bounty_autopilot()
        else:
            self.work_queue.put(("chat", "Groq", [], [f"No executable safe action matched: {action}"]))

    def _run_autonomous_cycle(self):
        self.autonomous_output.insert(tk.END, f"\n{dt.datetime.now().isoformat(timespec='seconds')} autonomous cycle started.\n")
        self.status_text.set("Autonomous cycle started")
        threading.Thread(target=self._autonomous_worker, daemon=True).start()

    def _autonomous_worker(self):
        all_findings = []
        evidence = []
        all_tabs = self.autonomous_all_tabs.get()
        distro = self.wsl_distro.get().strip() or "kali-linux"
        evidence.append(f"[Autonomous mode]\nAll tabs: {all_tabs}")
        if self.auto_web_intel.get():
            vector_topic = self.current_vector_query.get().strip() or "bug bounty web application API"
            evidence.append("[Current vectors]\n" + current_vectors_report(query=vector_topic, days=14))
        inventory = kali_tool_inventory(distro=distro)
        evidence.append("[Kali inventory]\n" + inventory)
        wifi_defense_findings, wifi_defense_evidence = wifi_audit()
        all_findings.extend(wifi_defense_findings)
        evidence.append("[Wi-Fi defense]\n" + "\n".join(wifi_defense_evidence))
        wifi_findings, wifi_evidence = wifi_monitor_snapshot()
        all_findings.extend(wifi_findings)
        evidence.append("[Wi-Fi monitor]\n" + "\n".join(wifi_evidence))
        wps_findings, wps_evidence = wps_defense_review()
        all_findings.extend(wps_findings)
        evidence.append("[Wi-Fi/WPS defense]\n" + "\n".join(wps_evidence))
        device_findings, device_evidence = device_defensive_posture()
        all_findings.extend(device_findings)
        evidence.append("[Device invasion posture]\n" + "\n\n".join(device_evidence))
        ghidra_status = run_wsl_command("command -v ghidraRun || command -v analyzeHeadless || true", distro=distro, timeout=20)
        evidence.append("[Ghidra readiness]\n" + (ghidra_status or "Ghidra not found in Kali PATH."))
        fraud_path = self.fraud_dataset_path.get().strip()
        if fraud_path and os.path.exists(fraud_path):
            fraud_findings, fraud_evidence, fraud_report = fraud_forensic_analysis(fraud_path)
            all_findings.extend(fraud_findings)
            evidence.append(f"[Card fraud analysis: {fraud_path}]\n" + "\n".join(fraud_evidence))
            evidence.append("[Card fraud report]\n" + fraud_report)
        for target in list(self.scope.scope):
            web_findings, web_evidence = web_audit(target)
            val_findings, val_evidence = offensive_validation(target)
            all_findings.extend(web_findings)
            all_findings.extend(val_findings)
            evidence.append(f"[Web audit: {target}]\n" + "\n".join(web_evidence))
            evidence.append(f"[Validation: {target}]\n" + "\n".join(val_evidence))
            if self.autonomous_bug_bounty.get():
                bounty_findings, bounty_evidence = bug_bounty_autopilot(target, distro=distro)
                all_findings.extend(bounty_findings)
                evidence.append(f"[Bug Bounty Autopilot: {target}]\n" + "\n\n".join(bounty_evidence))
            tasks = AUTONOMOUS_DRONE_TASKS if all_tabs else ["Recon Drone"]
            for task in tasks:
                if task == "Cybersecurity Drone":
                    cyber_findings, cyber_evidence = cybersecurity_drone(target, distro=distro)
                    all_findings.extend(cyber_findings)
                    evidence.append(f"[Cybersecurity Drone: {target}]\n" + "\n\n".join(cyber_evidence))
                elif task == "Defensive Response Drone":
                    defensive_findings, defensive_evidence = defensive_response_drone(target=target, fraud_path=fraud_path)
                    all_findings.extend(defensive_findings)
                    evidence.append(f"[Defensive Response Drone: {target}]\n" + "\n\n".join(defensive_evidence))
                else:
                    evidence.append(f"[{task}: {target}]\n{kali_drone_task(task, target, distro=distro)}")
        self.work_queue.put(("autonomous", "Saved scope", all_findings, evidence))

    def _autonomous_tick(self):
        if self.autonomous_enabled.get():
            now = dt.datetime.now()
            interval = max(5, int(self.autonomous_interval.get() or 15))
            last = getattr(self, "_last_autonomous_run", None)
            if last is None or (now - last).total_seconds() >= interval * 60:
                self._last_autonomous_run = now
                self._run_autonomous_cycle()
        self.after(30000, self._autonomous_tick)

    def _run_offense_validation(self):
        target = self.offense_target_entry.get().strip()
        if not target:
            messagebox.showinfo(APP_NAME, "Enter a target URL or domain.")
            return
        if not self.scope.is_allowed(target):
            messagebox.showwarning(APP_NAME, "Target is not in your authorized scope allowlist.")
            return
        self.offense_output.delete("1.0", tk.END)
        self.offense_output.insert(tk.END, f"Running authorized validation for {target}...\n")
        self.status_text.set(f"Running authorized validation for {target}")
        threading.Thread(target=self._offense_worker, args=(target,), daemon=True).start()

    def _offense_worker(self, target):
        findings, evidence = offensive_validation(target)
        self.work_queue.put(("offense", target, findings, evidence))

    def _wifi_worker(self):
        findings, evidence = wifi_audit()
        self.work_queue.put(("wifi", "Local Wi-Fi", findings, evidence))

    def _drain_queue(self):
        try:
            while True:
                kind, target, findings, evidence = self.work_queue.get_nowait()
                self.findings.extend(findings)
                if kind == "web":
                    self._write_result(self.web_output, target, findings, evidence)
                elif kind == "offense":
                    self._write_result(self.offense_output, target, findings, evidence)
                elif kind == "wifi":
                    self._write_result(self.wifi_output, target, findings, evidence)
                elif kind == "monitor":
                    self._write_result(self.monitor_output, target, findings, evidence)
                elif kind == "fraud":
                    self.last_fraud_report = evidence[-1] if evidence else ""
                    self._write_result(self.fraud_output, target, findings, evidence[:-1])
                    if self.last_fraud_report:
                        self.fraud_output.insert(tk.END, "\n\nDetailed Report\n")
                        self.fraud_output.insert(tk.END, self.last_fraud_report)
                elif kind == "bounty":
                    report = next((item.split("=== Bug bounty report draft ===\n", 1)[1] for item in evidence if item.startswith("=== Bug bounty report draft ===")), "")
                    if report:
                        self.last_bug_bounty_report = report
                    self._write_result(self.bounty_output, target, findings, evidence)
                elif kind == "webintel":
                    self.webintel_output.delete("1.0", tk.END)
                    self.webintel_output.insert(tk.END, "\n\n".join(evidence))
                elif kind == "browser":
                    self.browser_output.delete("1.0", tk.END)
                    self.browser_output.insert(tk.END, "\n\n".join(evidence))
                elif kind == "vectors":
                    self.last_vector_report = "\n\n".join(evidence)
                    self.vectors_output.delete("1.0", tk.END)
                    self.vectors_output.insert(tk.END, self.last_vector_report)
                elif kind == "terminal":
                    self.terminal_output.insert(tk.END, f"\n$ {target}\n")
                    self.terminal_output.insert(tk.END, "\n".join(evidence) + "\n")
                elif kind == "chat":
                    self.chat_output.insert(tk.END, f"\nPhoenix Guardian:\n{evidence[0] if evidence else ''}\n")
                    if target not in {"Groq", "Groq test"} and evidence:
                        self._remember_chat(target, evidence[0])
                elif kind == "voice_diag":
                    self.voice_output.delete("1.0", tk.END)
                    self.voice_output.insert(tk.END, "\n\n".join(evidence))
                    self.status_text.set("Voice diagnostics complete")
                    continue
                elif kind == "code":
                    self._write_result(self.code_output, target, findings, evidence)
                elif kind == "drone":
                    self._write_result(self.drone_output, target, findings, evidence)
                elif kind == "drone_text":
                    self.drone_output.delete("1.0", tk.END)
                    self.drone_output.insert(tk.END, "\n".join(evidence))
                    self.status_text.set(target)
                    continue
                elif kind == "ghidra_text":
                    self.ghidra_output.delete("1.0", tk.END)
                    self.ghidra_output.insert(tk.END, "\n".join(evidence))
                    self.status_text.set(target)
                    continue
                elif kind == "autonomous":
                    self.autonomous_output.insert(tk.END, f"{dt.datetime.now().isoformat(timespec='seconds')} cycle complete: {len(findings)} findings.\n")
                    self.autonomous_output.insert(tk.END, "\n\n".join(evidence[-8:]) + "\n")
                elif kind == "voice":
                    self.voice_listening = False
                    if hasattr(self, "voice_output"):
                        self.voice_output.insert(tk.END, f"\n\nHeard: {target}\n")
                    self._handle_voice_command(target)
                    continue
                elif kind == "voice_error":
                    self.voice_listening = False
                    reason = evidence[0] if evidence else "Voice command failed."
                    if hasattr(self, "voice_output"):
                        self.voice_output.insert(tk.END, f"\n\nVoice recognition issue:\n{reason}\n\nOpening typed command fallback...\n")
                    messagebox.showinfo(APP_NAME, reason)
                    self._prompt_voice_command(reason)
                    self.status_text.set("Voice command unavailable")
                    continue

                self._refresh_table()
                self._refresh_summary()
                self._refresh_threat_model()
                self.status_text.set(f"Completed {kind} check for {target}: {len(findings)} findings")
        except queue.Empty:
            pass
        self.after(150, self._drain_queue)

    def _write_result(self, widget, target, findings, evidence):
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, f"Target: {target}\n")
        widget.insert(tk.END, f"Findings: {len(findings)}\n\n")
        for item in findings:
            widget.insert(tk.END, f"[{item.severity}] {item.title}\n")
            widget.insert(tk.END, f"{item.detail}\nFix: {item.remediation}\n\n")
        widget.insert(tk.END, "Evidence\n")
        widget.insert(tk.END, "\n".join(evidence))

    def _refresh_table(self):
        self.finding_table.delete(*self.finding_table.get_children())
        for item in self.findings:
            self.finding_table.insert(
                "",
                tk.END,
                values=(item.timestamp, item.severity, item.category, item.target, item.title),
            )

    def _refresh_summary(self):
        self.summary_output.delete("1.0", tk.END)
        self.summary_output.insert(tk.END, ai_summary(self.findings))

    def _refresh_threat_model(self):
        self.threat_output.delete("1.0", tk.END)
        self.threat_output.insert(tk.END, predictive_threat_model(self.findings))
        self._refresh_dashboard()

    def _refresh_dashboard(self):
        if not hasattr(self, "dashboard_canvas"):
            return
        canvas = self.dashboard_canvas
        canvas.configure(bg=THEME["field"])
        canvas.delete("all")
        width = max(canvas.winfo_width(), 1080)
        height = max(canvas.winfo_height(), 560)
        severity_counts = Counter(item.severity for item in self.findings)
        category_counts = Counter(item.category for item in self.findings)
        colors = {"High": THEME["bad"], "Medium": THEME["warn"], "Low": THEME["accent"], "Info": THEME["good"]}
        money = monetary_estimate(self.findings)

        if hasattr(self, "dashboard_stats"):
            self.dashboard_stats["scope"].configure(text=str(len(self.scope.scope)))
            self.dashboard_stats["findings"].configure(text=str(len(self.findings)))
            self.dashboard_stats["critical"].configure(text=str(severity_counts.get("High", 0)))
            self.dashboard_stats["automation"].configure(text="ACTIVE" if self.autonomous_enabled.get() else "IDLE")

        for x in range(0, width, 48):
            canvas.create_line(x, 0, x, height, fill=THEME["grid"])
        for y in range(0, height, 42):
            canvas.create_line(0, y, width, y, fill=THEME["grid"])

        canvas.create_text(26, 24, text="PHOENIX GUARDIAN / OPS COCKPIT", fill=THEME["text"], anchor="w", font=("Segoe UI", 17, "bold"))
        canvas.create_text(26, 52, text="Authorized scope telemetry, evidence readiness, and live security posture", fill=THEME["muted"], anchor="w", font=("Segoe UI", 10))
        canvas.create_text(width - 26, 26, text=dt.datetime.now().strftime("%Y-%m-%d %H:%M"), fill=THEME["accent"], anchor="e", font=("Segoe UI", 10, "bold"))

        left_w = min(330, max(280, width * 0.27))
        right_w = min(370, max(310, width * 0.30))
        mid_x0 = left_w + 32
        mid_x1 = width - right_w - 32
        panel_top = 76
        panel_bottom = height - 26

        self._draw_panel(canvas, 24, panel_top, left_w, panel_bottom, "Threat distribution", THEME["accent"])
        self._draw_panel(canvas, mid_x0, panel_top, mid_x1, panel_bottom, "Mission route", THEME["accent_3"])
        self._draw_panel(canvas, width - right_w, panel_top, width - 24, panel_bottom, "Evidence analytics", THEME["accent_2"])

        total = sum(severity_counts.values()) or 1
        start = 90
        cx, cy, radius = 164, 214, 96
        for severity in ("High", "Medium", "Low", "Info"):
            count = severity_counts.get(severity, 0)
            extent = 360 * count / total
            if count or total == 1:
                canvas.create_arc(cx - radius, cy - radius, cx + radius, cy + radius, start=start, extent=extent, style="pieslice", fill=colors[severity], outline=THEME["field"])
            start += extent
        canvas.create_oval(cx - 54, cy - 54, cx + 54, cy + 54, fill=THEME["panel"], outline=THEME["line"])
        canvas.create_text(cx, cy - 9, text=str(len(self.findings)), fill=THEME["text"], font=("Segoe UI", 24, "bold"))
        canvas.create_text(cx, cy + 18, text="findings", fill=THEME["muted"], font=("Segoe UI", 9, "bold"))
        for idx, severity in enumerate(("High", "Medium", "Low", "Info")):
            y = 346 + idx * 34
            canvas.create_rectangle(54, y - 8, 72, y + 8, fill=colors[severity], outline="")
            canvas.create_text(86, y, text=f"{severity.upper()}  {severity_counts.get(severity, 0)}", fill=THEME["text"], anchor="w", font=("Segoe UI", 10, "bold"))
            canvas.create_line(184, y, left_w - 34, y, fill=THEME["line"])

        route_mid = (mid_x0 + mid_x1) // 2
        route_points = [
            (mid_x0 + 58, panel_bottom - 82),
            (mid_x0 + 122, panel_bottom - 158),
            (route_mid - 38, panel_top + 226),
            (route_mid + 62, panel_top + 150),
            (mid_x1 - 72, panel_top + 86),
        ]
        for idx in range(len(route_points) - 1):
            canvas.create_line(*route_points[idx], *route_points[idx + 1], fill=THEME["route"], width=3)
        for idx, (x, y) in enumerate(route_points, start=1):
            fill = THEME["accent_3"] if idx == len(route_points) else THEME["accent"]
            canvas.create_oval(x - 8, y - 8, x + 8, y + 8, fill=fill, outline=THEME["text"])
            canvas.create_text(x, y - 22, text=f"0{idx}", fill=THEME["muted"], font=("Segoe UI", 8, "bold"))
        canvas.create_text(route_mid, panel_top + 54, text="AUTHORIZED ATTACK SURFACE", fill=THEME["text"], font=("Segoe UI", 15, "bold"))
        canvas.create_text(route_mid, panel_top + 80, text=f"{len(self.scope.scope)} scoped assets | {len(category_counts)} active evidence categories", fill=THEME["muted"], font=("Segoe UI", 10))
        self._draw_mini_phoenix(canvas, route_mid, panel_top + 250, scale=1.55)
        canvas.create_text(route_mid, panel_bottom - 42, text="Scope -> Intel -> Validation -> Evidence -> Report", fill=THEME["accent"], font=("Segoe UI", 10, "bold"))

        top_categories = category_counts.most_common(9)
        max_count = max([count for name, count in top_categories] or [1])
        rx0 = width - right_w + 28
        rx1 = width - 54
        canvas.create_text(rx0, panel_top + 58, text="CATEGORY SIGNALS", fill=THEME["text"], anchor="w", font=("Segoe UI", 12, "bold"))
        if not top_categories:
            canvas.create_text(rx0, panel_top + 104, text="No findings yet. Run a scoped audit to populate this panel.", fill=THEME["muted"], anchor="w", width=right_w - 56, font=("Segoe UI", 10))
        for idx, (name, count) in enumerate(top_categories):
            y = panel_top + 98 + idx * 34
            canvas.create_text(rx0, y, text=name[:28], fill=THEME["muted"], anchor="w", font=("Segoe UI", 9, "bold"))
            bar_x = rx0 + 142
            bar_w = max(8, int((rx1 - bar_x - 34) * count / max_count))
            canvas.create_rectangle(bar_x, y - 8, rx1 - 34, y + 8, fill=THEME["field"], outline=THEME["line"])
            canvas.create_rectangle(bar_x, y - 8, bar_x + bar_w, y + 8, fill=THEME["accent_2"], outline="")
            canvas.create_text(rx1 - 18, y, text=str(count), fill=THEME["text"], anchor="e", font=("Segoe UI", 9, "bold"))

        y0 = panel_bottom - 112
        canvas.create_line(rx0, y0 - 20, rx1, y0 - 20, fill=THEME["line"])
        canvas.create_text(rx0, y0, text="MONETARY READINESS", fill=THEME["accent_3"], anchor="w", font=("Segoe UI", 10, "bold"))
        canvas.create_text(rx0, y0 + 30, text=f"Bounty band: {money['bounty_band']}", fill=THEME["text"], anchor="w", width=right_w - 56, font=("Segoe UI", 10))
        canvas.create_text(rx0, y0 + 58, text=f"Remediation: {money['remediation_cost']}", fill=THEME["muted"], anchor="w", width=right_w - 56, font=("Segoe UI", 9))

    def _clear_findings(self):
        if not messagebox.askyesno(APP_NAME, "Clear current in-memory findings?"):
            return
        self.findings.clear()
        self._refresh_table()
        self._refresh_summary()
        self._refresh_threat_model()
        self.privacy_output.insert(tk.END, f"{dt.datetime.now().isoformat(timespec='seconds')} cleared current findings.\n")
        self.status_text.set("Current findings cleared")

    def _clear_scope_file(self):
        if not messagebox.askyesno(APP_NAME, "Clear the local authorized scope file?"):
            return
        self.scope.scope = []
        self.scope.save()
        self._refresh_scope()
        self.privacy_output.insert(tk.END, f"{dt.datetime.now().isoformat(timespec='seconds')} cleared scope file.\n")
        self.status_text.set("Scope file cleared")

    def _export_redacted_csv(self):
        if not self.findings:
            messagebox.showinfo(APP_NAME, "No findings to export yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Export redacted findings",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["timestamp", "severity", "category", "target", "title", "detail", "remediation"])
            for index, item in enumerate(self.findings, start=1):
                writer.writerow([
                    item.timestamp,
                    item.severity,
                    item.category,
                    f"redacted-target-{index}",
                    item.title,
                    item.detail,
                    item.remediation,
                ])
        self.privacy_output.insert(tk.END, f"{dt.datetime.now().isoformat(timespec='seconds')} exported redacted CSV.\n")
        messagebox.showinfo(APP_NAME, f"Exported {len(self.findings)} redacted findings.")

    def _voice_help_text(self):
        return "\n".join([
            "Phoenix Guardian Voice Commands",
            f"Generated: {dt.datetime.now().isoformat(timespec='seconds')}",
            "",
            "Say or type one of these:",
            "- fire theme",
            "- codex theme",
            "- settings",
            "- new chat",
            "- test groq",
            "- browser",
            "- hackerone",
            "- current vectors",
            "- code lab",
            "- full access on",
            "- full access off",
            "- bug bounty",
            "- checklist",
            "- web search",
            "- terminal",
            "- wifi",
            "- monitor",
            "- fraud",
            "- cybersecurity drone",
            "- defensive drone",
            "- autonomous",
            "- ghidra",
            "- web audit",
            "- validation",
            "",
            "If microphone recognition fails, Phoenix opens the typed-command fallback automatically.",
        ])

    def _show_voice_help(self):
        self.voice_output.delete("1.0", tk.END)
        self.voice_output.insert(tk.END, self._voice_help_text())
        self.status_text.set("Voice command help loaded")

    def _run_voice_diagnostics(self):
        if hasattr(self, "voice_output"):
            self.voice_output.delete("1.0", tk.END)
            self.voice_output.insert(tk.END, "Running voice diagnostics...\n")
        self.status_text.set("Running voice diagnostics")
        threading.Thread(target=self._voice_diagnostics_worker, daemon=True).start()

    def _voice_diagnostics_worker(self):
        report = voice_dependency_report()
        self.work_queue.put(("voice_diag", "Voice diagnostics", [], [report]))

    def _listen_for_voice_command(self):
        if self.voice_listening:
            self.status_text.set("Voice command is already listening")
            return
        self.voice_listening = True
        self.status_text.set("Listening for voice command")
        threading.Thread(target=self._voice_worker, daemon=True).start()

    def _voice_worker(self):
        errors = []
        try:
            import speech_recognition as sr
        except ImportError:
            sr = None
            errors.append("Python SpeechRecognition is not installed.")

        if sr is not None:
            try:
                recognizer = sr.Recognizer()
                recognizer.dynamic_energy_threshold = True
                recognizer.pause_threshold = 0.75
                with sr.Microphone() as source:
                    recognizer.adjust_for_ambient_noise(source, duration=0.8)
                    audio = recognizer.listen(source, timeout=8, phrase_time_limit=8)
                command = recognizer.recognize_google(audio).lower()
                self.work_queue.put(("voice", command, [], [command]))
                return
            except sr.WaitTimeoutError:
                errors.append("No voice was heard before the Python recognizer timeout.")
            except sr.UnknownValueError:
                errors.append("Python recognizer could not understand the audio.")
            except sr.RequestError as exc:
                errors.append(f"Python speech recognition service failed: {exc}")
            except OSError as exc:
                errors.append(f"Python microphone/audio device error: {exc}")
            except Exception as exc:
                errors.append(f"Python voice recognition failed: {exc}")

        command, error = windows_voice_command(timeout=8)
        if command:
            self.work_queue.put(("voice", command, [], [command]))
            return
        if error:
            errors.append(f"Windows Speech fallback: {error}")
        self.work_queue.put(("voice_error", "Voice", [], ["\n".join(errors) or "Voice command failed."]))

    def _prompt_voice_command(self, reason=""):
        prompt = "Type a Phoenix voice command"
        if reason:
            prompt += f"\n\nVoice issue: {reason}"
        command = simpledialog.askstring(APP_NAME, prompt)
        if command:
            self._handle_voice_command(command.lower().strip())

    def _handle_voice_command(self, command):
        command = (command or "").lower().strip()
        self.status_text.set(f"Voice command: {command}")
        if not command:
            return
        if "fire" in command and "theme" in command:
            self.theme_name.set("Phoenix Fire")
            self._apply_theme()
        elif "codex" in command and "theme" in command:
            self.theme_name.set("Codex Dark")
            self._apply_theme()
        elif "voice panel" in command:
            self._select_voice_panel()
        elif "voice help" in command:
            self._select_voice_panel()
            self._show_voice_help()
        elif "voice diagnostic" in command or "speech diagnostic" in command or "mic diagnostic" in command:
            self._select_voice_panel()
            self._run_voice_diagnostics()
        elif "settings" in command:
            self._select_settings()
        elif "new chat" in command or "start chat" in command:
            self._new_chat()
        elif "test groq" in command or "groq test" in command:
            self._test_groq()
        elif "save key" in command:
            self._save_groq_key()
        elif "load key" in command:
            self._load_groq_key()
        elif "browser" in command or "hackerone" in command:
            self._browser_shopify() if "shopify" in command or "hackerone" in command else self._open_browser_url()
        elif "current vector" in command or "live vector" in command or "intel" in command:
            self._run_current_vectors()
        elif "code lab" in command or "language inventory" in command:
            self._run_code_inventory()
        elif "project" in command:
            self._new_project()
        elif "plugin" in command:
            self.status_text.set("Plugins panel is available under Intelligence")
        elif "full access" in command:
            enabled = "off" not in command and "disable" not in command
            self.local_full_access.set(enabled)
            self._toggle_full_access(enabled)
        elif "wifi" in command:
            self._run_wifi_audit()
        elif "forecast" in command or "threat" in command:
            self._refresh_threat_model()
        elif "summary" in command or "report" in command:
            self._refresh_summary()
        elif "bug bounty" in command or "bounty" in command:
            self._run_bug_bounty_autopilot()
        elif "checklist" in command:
            self._show_bounty_checklist()
        elif "search" in command or "web intel" in command:
            self._run_web_search()
        elif "terminal" in command or "kali shell" in command:
            self._run_wsl_terminal_command()
        elif "monitor" in command:
            self._run_wifi_monitor()
        elif "fraud" in command or "card" in command:
            self._run_fraud_analysis()
        elif "cyber" in command and "drone" in command:
            self._run_cybersecurity_drone()
        elif ("defensive" in command or "defense" in command) and "drone" in command:
            self._run_defensive_drone()
        elif "drone" in command:
            self._run_kali_drone()
        elif "autonomous" in command or "automatic" in command:
            self._run_autonomous_cycle()
        elif "ghidra" in command or "reverse" in command:
            self._run_ghidra_inventory()
        elif "web" in command or "audit" in command:
            self._run_web_audit()
        elif "validation" in command or "validate" in command:
            self._run_offense_validation()
        else:
            messagebox.showinfo(APP_NAME, f"Voice command heard, but no matching action was found:\n\n{command}")

    def _export_csv(self):
        if not self.findings:
            messagebox.showinfo(APP_NAME, "No findings to export yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Export findings",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["timestamp", "severity", "category", "target", "title", "detail", "remediation"])
            for item in self.findings:
                writer.writerow([
                    item.timestamp,
                    item.severity,
                    item.category,
                    item.target,
                    item.title,
                    item.detail,
                    item.remediation,
                ])
        messagebox.showinfo(APP_NAME, f"Exported {len(self.findings)} findings.")


if __name__ == "__main__":
    PhoenixGuardian().mainloop()
