const panels = {
  command: {
    title: "Operational Overview",
    state: "Ready",
    rows: [
      ["Scope", "Authorized targets loaded and guardrails enforced", "loading"],
      ["Groq", "Command assistant ready for report drafting and triage", "local"],
      ["Kali", "WSL bridge prepared for local authorized workflows", "ready"],
      ["Reports", "Evidence export queue has clean markdown templates", "clean"],
    ],
  },
  "bug-bounty": {
    title: "Bug Bounty Pipeline",
    state: "Bounty Mode",
    rows: [
      ["Policy", "HackerOne rules and scope must be confirmed before testing", "required"],
      ["Burp", "Proxy workflow ready for manual validation evidence", "standby"],
      ["Vectors", "OWASP, NVD, and CISA intelligence mapped to reports", "active"],
      ["Submit", "Reports stay draft-first until reviewed", "safe"],
    ],
  },
  intelligence: {
    title: "Cyber Intelligence",
    state: "Intel Mode",
    rows: [
      ["CISA", "Known exploited vulnerability watchlist available", "feed"],
      ["NVD", "CVE research lane prepared for scoped technology checks", "feed"],
      ["OSINT", "Public web context can enrich authorized targets", "enabled"],
      ["Memory", "Chat history and project notes stay local", "local"],
    ],
  },
  operations: {
    title: "Operations Bridge",
    state: "Ops Mode",
    rows: [
      ["WSL2", "Kali terminal and drones use local execution", "ready"],
      ["Fraud", "Card transaction CSV forensics support evidence trails", "lab"],
      ["Voice", "Command fallback path supports speech or typed input", "ready"],
      ["Ghidra", "Reverse-engineering case notes and hashes supported", "case"],
    ],
  },
  reports: {
    title: "Executive Reports",
    state: "Report Mode",
    rows: [
      ["Summary", "Findings convert into concise executive briefings", "draft"],
      ["CSV", "Structured exports support local review", "export"],
      ["Redaction", "Sensitive fields can be masked before sharing", "safe"],
      ["Money", "Bounty and remediation estimates show readiness", "forecast"],
    ],
  },
};

const navItems = document.querySelectorAll(".nav-item");
const panelTitle = document.querySelector("#panel-title");
const signalList = document.querySelector("#signal-list");
const systemState = document.querySelector("#system-state");
const runScan = document.querySelector("#run-scan");
const addScope = document.querySelector("#add-scope");
const automationState = document.querySelector("#automation-state");
const riskCount = document.querySelector("#risk-count");
const scopeCount = document.querySelector("#scope-count");
const terminalOutput = document.querySelector("#terminal-output");
const actionButtons = document.querySelectorAll("[data-action]");

let activePanel = "command";

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok || payload.ok === false) {
    throw new Error(payload.error || `Request failed with HTTP ${response.status}`);
  }
  return payload;
}

function renderPanel(key) {
  activePanel = key;
  const panel = panels[key] || panels.command;
  panelTitle.textContent = panel.title;
  systemState.textContent = panel.state;
  renderRows(panel.rows);
}

function renderRows(rows) {
  signalList.innerHTML = rows
    .map(([kind, detail, status]) => `
      <div class="signal-row">
        <span>${escapeHtml(kind)}</span>
        <strong>${escapeHtml(detail)}</strong>
        <em>${escapeHtml(status)}</em>
      </div>
    `)
    .join("");
}

function renderOutput(title, text) {
  signalList.innerHTML = `
    <div class="signal-row output">
      <span>${escapeHtml(title)}</span>
      <pre>${escapeHtml(text || "No output returned.")}</pre>
    </div>
  `;
}

function setTerminal(text) {
  terminalOutput.textContent = text;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function targetValue() {
  return document.querySelector("#target-input").value.trim();
}

async function refreshStatus() {
  const status = await api("/api/status");
  scopeCount.textContent = status.scopeCount;
  riskCount.textContent = status.severity.High || 0;
  automationState.textContent = "Ready";
  systemState.textContent = "API Online";
  const rows = [
    ["Scope", `${status.scopeCount} authorized assets loaded`, "required"],
    ["Findings", `${status.findingsCount} local findings in this web session`, "local"],
    ["Guardrails", "Scope, credential, token, rogue AP, and exploit-delivery locks active", "locked"],
    ["Features", status.features.join(", "), "ready"],
  ];
  if (activePanel === "command") {
    renderRows(rows);
  }
  setTerminal(`$ phoenix api status
app: ${status.app}
scope assets: ${status.scopeCount}
findings: ${status.findingsCount}
guardrails: locked`);
}

async function addTargetToScope() {
  const target = targetValue();
  if (!target) {
    throw new Error("Enter a target first.");
  }
  const result = await api("/api/scope", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
  scopeCount.textContent = result.scope.length;
  systemState.textContent = "Scope Updated";
  renderOutput("Scope Updated", `Added/confirmed: ${result.added}\n\nCurrent scope:\n${result.scope.join("\n") || "empty"}`);
  setTerminal(`$ phoenix scope add ${target}
added: ${result.added}
scope count: ${result.scope.length}`);
}

async function runWebAudit() {
  const target = targetValue();
  if (!target) {
    throw new Error("Enter a target first.");
  }
  automationState.textContent = "Running";
  setTerminal(`$ phoenix web-audit ${target}
scope check: running
guardrails: locked`);
  const result = await api("/api/web-audit", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
  riskCount.textContent = result.findings.filter((item) => item.severity === "High").length;
  automationState.textContent = "Ready";
  systemState.textContent = "Audit Complete";
  const findingText = result.findings
    .map((item) => `[${item.severity}] ${item.title}\n${item.detail}\nFix: ${item.remediation}`)
    .join("\n\n");
  renderOutput("Audit Result", `${result.summary}\n\nFindings\n${findingText || "No findings returned."}\n\nEvidence\n${result.evidence.join("\n")}`);
  setTerminal(`$ phoenix web-audit ${target}
result: complete
new findings: ${result.findings.length}
session findings: ${result.totalFindings}`);
}

async function runAction(action) {
  if (action === "status") {
    await refreshStatus();
    return;
  }
  if (action === "checklist") {
    const result = await api("/api/checklist");
    renderOutput("Bug Bounty Checklist", result.text);
    return;
  }
  if (action === "vectors") {
    const query = encodeURIComponent(targetValue() || "web application API cloud auth bug bounty");
    const result = await api(`/api/current-vectors?query=${query}&target=${query}`);
    renderOutput("Current Vectors", result.text);
    return;
  }
  if (action === "voice") {
    const result = await api("/api/voice-diagnostics");
    renderOutput("Voice Diagnostics", result.text);
    return;
  }
  if (action === "kali") {
    const result = await api("/api/kali-inventory");
    renderOutput("Kali Inventory", result.text);
    return;
  }
  if (action === "summary") {
    const result = await api("/api/report-summary");
    renderOutput("Report Summary", result.summary);
  }
}

async function withBusy(label, task) {
  try {
    systemState.textContent = label;
    await task();
  } catch (error) {
    systemState.textContent = "Action Failed";
    renderOutput("Error", error.message);
    setTerminal(`$ phoenix error
${error.message}`);
  }
}

navItems.forEach((button) => {
  button.addEventListener("click", () => {
    navItems.forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    renderPanel(button.dataset.panel);
  });
});

addScope.addEventListener("click", () => withBusy("Adding Scope", addTargetToScope));
runScan.addEventListener("click", () => withBusy("Running Audit", runWebAudit));
actionButtons.forEach((button) => {
  button.addEventListener("click", () => withBusy("Running Action", () => runAction(button.dataset.action)));
});

renderPanel("command");
refreshStatus().catch((error) => renderOutput("API Offline", error.message));

