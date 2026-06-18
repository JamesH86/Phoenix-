const panelConfig = {
  command: {
    title: "Command Center",
    state: "Command",
    subtitle: "Live local backend, scope, guardrails, memory, and chat-ready actions.",
    controls: ["groq-key", "groq-model"],
    actions: [
      ["status", "Refresh Status"],
      ["guardrails", "Guardrails"],
      ["tools", "Tool Matrix"],
      ["groq", "Ask Groq"],
      ["clear", "Clear Findings"],
    ],
  },
  "bug-bounty": {
    title: "Bug Bounty Workspace",
    state: "Bounty",
    subtitle: "Scope-first testing, Burp readiness, HackerOne prep, and draft reports.",
    controls: ["query", "distro", "hackerone"],
    actions: [
      ["checklist", "Checklist"],
      ["web-audit", "Run Audit"],
      ["autopilot", "Autopilot"],
      ["burp", "Burp Status"],
      ["hackerone", "HackerOne Ready"],
      ["bug-report", "Draft Report"],
    ],
  },
  intelligence: {
    title: "Intelligence Hub",
    state: "Intel",
    subtitle: "Public web context, CVE/vector tracking, wordlists, and research memory.",
    controls: ["query", "browser", "distro"],
    actions: [
      ["vectors", "Current Vectors"],
      ["browser", "Browser Context"],
      ["wordlists", "Wordlists"],
      ["tools", "Tool Matrix"],
      ["status", "Refresh Status"],
    ],
  },
  operations: {
    title: "Operations Bridge",
    state: "Ops",
    subtitle: "Kali WSL, voice diagnostics, defensive response, fraud triage, and guarded commands.",
    controls: ["distro", "wsl", "fraud"],
    actions: [
      ["kali", "Kali Inventory"],
      ["wsl", "Run WSL Command"],
      ["voice", "Voice Diagnostics"],
      ["defensive", "Defensive Drone"],
      ["fraud", "Fraud Report"],
    ],
  },
  reports: {
    title: "Reports & Evidence",
    state: "Reports",
    subtitle: "Executive summaries, evidence handoff, bug bounty drafts, and clean exports.",
    controls: ["fraud", "hackerone"],
    actions: [
      ["summary", "Executive Summary"],
      ["bug-report", "Bug Bounty Draft"],
      ["fraud", "Fraud Workspace"],
      ["guardrails", "Guardrails"],
      ["clear", "Clear Findings"],
    ],
  },
  settings: {
    title: "Settings",
    state: "Settings",
    subtitle: "Provider, HackerOne, WSL, browser, and guardrail configuration.",
    controls: ["groq-key", "groq-model", "hackerone", "distro"],
    actions: [
      ["guardrails", "Guardrails"],
      ["groq", "Test Groq"],
      ["hackerone", "HackerOne Ready"],
      ["voice", "Voice Diagnostics"],
      ["status", "Refresh Status"],
    ],
  },
};

const navItems = document.querySelectorAll(".nav-item");
const panelTitle = document.querySelector("#panel-title");
const panelSubtitle = document.querySelector("#panel-subtitle");
const signalList = document.querySelector("#signal-list");
const systemState = document.querySelector("#system-state");
const runScan = document.querySelector("#run-scan");
const addScope = document.querySelector("#add-scope");
const automationState = document.querySelector("#automation-state");
const riskCount = document.querySelector("#risk-count");
const scopeCount = document.querySelector("#scope-count");
const evidenceQuality = document.querySelector("#evidence-quality");
const terminalOutput = document.querySelector("#terminal-output");
const actionBar = document.querySelector("#action-bar");
const controlDeck = document.querySelector("#control-deck");
const controlLabels = document.querySelectorAll("[data-control]");
const targetInput = document.querySelector("#target-input");
const queryInput = document.querySelector("#query-input");
const browserInput = document.querySelector("#browser-input");
const distroInput = document.querySelector("#distro-input");
const wslInput = document.querySelector("#wsl-input");
const fraudInput = document.querySelector("#fraud-input");
const chatInput = document.querySelector("#chat-input");
const chatOutput = document.querySelector("#chat-output");
const chatSend = document.querySelector("#chat-send");
const groqKeyInput = document.querySelector("#groq-key-input");
const groqModelInput = document.querySelector("#groq-model-input");
const hackeroneHandleInput = document.querySelector("#hackerone-handle-input");
const donut = document.querySelector("#severity-donut");
const donutTotal = document.querySelector("#donut-total");
const legend = document.querySelector("#severity-legend");

let activePanel = "command";
let lastStatus = null;

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

function targetValue() {
  return targetInput.value.trim();
}

function distroValue() {
  return distroInput.value.trim() || "kali-linux";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderPanel(key) {
  activePanel = key;
  const panel = panelConfig[key] || panelConfig.command;
  panelTitle.textContent = panel.title;
  panelSubtitle.textContent = panel.subtitle;
  systemState.textContent = panel.state;
  actionBar.innerHTML = panel.actions
    .map(([action, label]) => `<button data-action="${escapeHtml(action)}">${escapeHtml(label)}</button>`)
    .join("");
  actionBar.querySelectorAll("[data-action]").forEach((button) => {
    button.addEventListener("click", () => withBusy(button.textContent, () => runAction(button.dataset.action)));
  });
  renderControls(panel.controls || []);
  renderRows(defaultRows(key));
  if (lastStatus) {
    updateKpis(lastStatus);
  }
}

function renderControls(controls) {
  const visible = new Set(controls);
  controlLabels.forEach((label) => {
    const isVisible = visible.has(label.dataset.control);
    label.hidden = !isVisible;
  });
  controlDeck.hidden = visible.size === 0;
}

function defaultRows(key) {
  const rows = {
    command: [
      ["API", "Local Python backend is the source of truth for actions", "live"],
      ["Scope", "Add targets before remote workflows run", "required"],
      ["Chat", "Groq uses local key input or saved environment configuration", "ready"],
      ["Memory", "Session findings and report evidence remain local", "local"],
    ],
    "bug-bounty": [
      ["Scope", "Every test starts with allowlist confirmation", "locked"],
      ["Autopilot", "Collects safe evidence, CVE context, Burp status, and report draft", "scoped"],
      ["HackerOne", "Draft-first workflow keeps review before submission", "review"],
      ["Reports", "Markdown evidence is generated from current findings", "ready"],
    ],
    intelligence: [
      ["Vectors", "Live public vulnerability context is available", "feed"],
      ["Browser", "Fetch public page context for policy and scope review", "ready"],
      ["Wordlists", "Inventory local Kali lists without exposing secrets", "local"],
      ["Tools", "Matrix shows what is wired and how it is allowed to run", "mapped"],
    ],
    operations: [
      ["Kali", "WSL distro inventory runs locally", "local"],
      ["Terminal", "Guarded WSL bridge blocks unsafe intent", "guarded"],
      ["Fraud", "CSV evidence can produce lawful handoff reports", "ready"],
      ["Voice", "Speech diagnostics and typed fallback are available", "ready"],
    ],
    reports: [
      ["Executive", "Summary updates from live session findings", "ready"],
      ["Bounty", "Draft reports require scope and review", "draft"],
      ["Fraud", "Evidence handoff supports card abuse triage", "lawful"],
      ["Export", "Use generated text as clean report source", "local"],
    ],
    settings: [
      ["Groq", "Paste key locally for chat checks; avoid committing secrets", "local"],
      ["HackerOne", "Handle field prepares readiness guidance", "draft"],
      ["WSL", "Distro field selects local Kali integration", "local"],
      ["Guardrails", "Locked safety controls are visible and auditable", "locked"],
    ],
  };
  return rows[key] || rows.command;
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

function renderJson(title, value) {
  renderOutput(title, JSON.stringify(value, null, 2));
}

function setTerminal(text) {
  terminalOutput.textContent = text;
}

function appendTerminal(text) {
  terminalOutput.textContent = `${terminalOutput.textContent}\n${text}`.trim();
}

function updateKpis(status) {
  lastStatus = status;
  const severity = status.severity || {};
  const high = severity.High || 0;
  const med = severity.Medium || 0;
  const low = severity.Low || 0;
  const info = severity.Info || severity.Informational || 0;
  const total = high + med + low + info;
  scopeCount.textContent = status.scopeCount;
  riskCount.textContent = high;
  evidenceQuality.textContent = total ? `${Math.min(98, 70 + total * 4)}%` : "Ready";
  donutTotal.textContent = String(total);
  const highPct = total ? Math.round((high / total) * 100) : 0;
  const medPct = total ? Math.round((med / total) * 100) : 0;
  const lowPct = total ? Math.round((low / total) * 100) : 0;
  donut.style.background = `conic-gradient(#fb4d5d 0 ${highPct}%, #f59e0b ${highPct}% ${highPct + medPct}%, #22d3ee ${highPct + medPct}% ${highPct + medPct + lowPct}%, #7c3aed ${highPct + medPct + lowPct}% 100%)`;
  legend.innerHTML = [
    ["high", "High", high],
    ["med", "Medium", med],
    ["low", "Low", low],
    ["info", "Info", info],
  ]
    .map(([cls, label, count]) => `<li><span class="dot ${cls}"></span>${label} <strong>${count}</strong></li>`)
    .join("");
}

async function refreshStatus() {
  const status = await api("/api/status");
  updateKpis(status);
  automationState.textContent = "Ready";
  systemState.textContent = "API Online";
  if (activePanel === "command") {
    renderRows([
      ["Scope", `${status.scopeCount} authorized assets loaded`, "required"],
      ["Findings", `${status.findingsCount} local findings in this web session`, "local"],
      ["Guardrails", "Scope, credential, token, rogue AP, exploit-delivery, and review locks active", "locked"],
      ["Features", status.features.join(", "), "ready"],
    ]);
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
  automationState.textContent = "Ready";
  systemState.textContent = "Audit Complete";
  await refreshStatus();
  renderOutput("Audit Result", formatFindings(result));
  setTerminal(`$ phoenix web-audit ${target}
result: complete
new findings: ${result.findings.length}
session findings: ${result.totalFindings}`);
}

function formatFindings(result) {
  const findingText = (result.findings || [])
    .map((item) => `[${item.severity}] ${item.title}\n${item.detail}\nFix: ${item.remediation}`)
    .join("\n\n");
  return `${result.summary || "No summary returned."}\n\nFindings\n${findingText || "No findings returned."}\n\nEvidence\n${(result.evidence || []).join("\n\n")}`;
}

async function runAction(action) {
  if (action === "status") {
    await refreshStatus();
    return;
  }
  if (action === "clear") {
    const result = await api("/api/clear-findings", { method: "POST", body: "{}" });
    await refreshStatus();
    renderJson("Findings Cleared", result);
    return;
  }
  if (action === "checklist") {
    const result = await api("/api/checklist");
    renderOutput("Bug Bounty Checklist", result.text);
    return;
  }
  if (action === "web-audit") {
    await runWebAudit();
    return;
  }
  if (action === "autopilot") {
    const result = await api("/api/bug-bounty-autopilot", {
      method: "POST",
      body: JSON.stringify({ target: targetValue(), distro: distroValue() }),
    });
    await refreshStatus();
    renderOutput("Bug Bounty Autopilot", formatFindings(result));
    return;
  }
  if (action === "bug-report") {
    const result = await api("/api/bug-bounty-report", {
      method: "POST",
      body: JSON.stringify({ target: targetValue() }),
    });
    renderOutput("Bug Bounty Report Draft", result.report);
    return;
  }
  if (action === "vectors") {
    const query = encodeURIComponent(queryInput.value.trim() || targetValue() || "web application API cloud auth bug bounty");
    const target = encodeURIComponent(targetValue());
    const result = await api(`/api/current-vectors?query=${query}&target=${target}`);
    renderOutput("Current Vectors", result.text);
    return;
  }
  if (action === "browser") {
    const result = await api("/api/browser-context", {
      method: "POST",
      body: JSON.stringify({ url: browserInput.value.trim() || "https://example.com" }),
    });
    renderOutput("Browser Context", result.text);
    return;
  }
  if (action === "wordlists") {
    const result = await api(`/api/wordlists?distro=${encodeURIComponent(distroValue())}`);
    renderOutput("Wordlist Catalog", result.text);
    return;
  }
  if (action === "voice") {
    const result = await api("/api/voice-diagnostics");
    renderOutput("Voice Diagnostics", result.text);
    return;
  }
  if (action === "kali") {
    const result = await api(`/api/kali-inventory?distro=${encodeURIComponent(distroValue())}`);
    renderOutput("Kali Inventory", result.text);
    return;
  }
  if (action === "wsl") {
    const result = await api("/api/wsl-command", {
      method: "POST",
      body: JSON.stringify({ command: wslInput.value.trim(), distro: distroValue() }),
    });
    renderOutput("WSL Command", result.text);
    appendTerminal(`\n$ ${result.command}\n${result.text}`);
    return;
  }
  if (action === "defensive") {
    const result = await api("/api/defensive-drone", {
      method: "POST",
      body: JSON.stringify({ target: targetValue(), fraudPath: fraudInput.value.trim() }),
    });
    await refreshStatus();
    renderOutput("Defensive Drone", formatFindings(result));
    return;
  }
  if (action === "fraud") {
    const result = await api("/api/fraud-report", {
      method: "POST",
      body: JSON.stringify({ path: fraudInput.value.trim() }),
    });
    await refreshStatus();
    renderOutput("Fraud Evidence Report", result.report || formatFindings(result));
    return;
  }
  if (action === "burp") {
    const result = await api("/api/burp-status");
    renderOutput("Burp Suite Status", result.text);
    return;
  }
  if (action === "hackerone") {
    const handle = encodeURIComponent(hackeroneHandleInput.value.trim() || "program");
    const result = await api(`/api/hackerone-readiness?handle=${handle}`);
    renderOutput("HackerOne Readiness", result.text);
    return;
  }
  if (action === "summary") {
    const result = await api("/api/report-summary");
    renderOutput("Executive Summary", result.summary);
    return;
  }
  if (action === "guardrails") {
    const result = await api("/api/guardrails");
    renderGuardrails(result.guardrails);
    return;
  }
  if (action === "tools") {
    const result = await api("/api/tool-matrix");
    renderToolMatrix(result.tools);
    return;
  }
  if (action === "groq") {
    await sendChat();
  }
}

async function sendChat() {
  const message = chatInput.value.trim() || "Give me a concise Phoenix Guardian status report.";
  appendChat("user", message);
  chatInput.value = "";
  const result = await api("/api/groq-chat", {
    method: "POST",
    body: JSON.stringify({
      message,
      apiKey: groqKeyInput.value.trim(),
      model: groqModelInput.value.trim() || "llama-3.1-8b-instant",
    }),
  });
  appendChat("assistant", result.text);
  renderOutput("Groq Command", result.text);
}

function appendChat(role, text) {
  const node = document.createElement("div");
  node.className = `chat-message ${role}`;
  node.textContent = text;
  chatOutput.appendChild(node);
  chatOutput.scrollTop = chatOutput.scrollHeight;
}

function renderGuardrails(guardrails) {
  signalList.innerHTML = Object.entries(guardrails)
    .map(([key, item]) => `
      <div class="guardrail-row">
        <div>
          <strong>${escapeHtml(item.label)}</strong>
          <p>${escapeHtml(item.description)}</p>
        </div>
        <button class="toggle ${item.enabled ? "on" : ""}" aria-label="${escapeHtml(item.label)}" title="${escapeHtml(key)}" disabled>
          <span></span>
        </button>
      </div>
    `)
    .join("");
}

function renderToolMatrix(tools) {
  signalList.innerHTML = `
    <div class="tool-grid">
      ${tools
        .map((tool) => `
          <article class="tool-card">
            <span>${escapeHtml(tool.tab)}</span>
            <strong>${escapeHtml(tool.name)}</strong>
            <p>${escapeHtml(tool.mode)}</p>
            <em>${escapeHtml(tool.status)}</em>
          </article>
        `)
        .join("")}
    </div>
  `;
}

async function withBusy(label, task) {
  try {
    systemState.textContent = label;
    automationState.textContent = "Running";
    await task();
    automationState.textContent = "Ready";
  } catch (error) {
    systemState.textContent = "Action Failed";
    automationState.textContent = "Needs Review";
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
chatSend.addEventListener("click", () => withBusy("Asking Groq", sendChat));
chatInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    withBusy("Asking Groq", sendChat);
  }
});

renderPanel("command");
refreshStatus().catch((error) => renderOutput("API Offline", error.message));
