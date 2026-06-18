const panels = {
  command: {
    title: "Operational Overview",
    state: "Ready",
    rows: [
      ["Scope", "Authorized targets loaded and guardrails enforced", "12 assets"],
      ["Groq", "Command assistant ready for report drafting and triage", "online"],
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
const automationState = document.querySelector("#automation-state");
const riskCount = document.querySelector("#risk-count");
const terminalOutput = document.querySelector("#terminal-output");

function renderPanel(key) {
  const panel = panels[key] || panels.command;
  panelTitle.textContent = panel.title;
  systemState.textContent = panel.state;
  signalList.innerHTML = panel.rows
    .map(([kind, detail, status]) => `
      <div class="signal-row">
        <span>${kind}</span>
        <strong>${detail}</strong>
        <em>${status}</em>
      </div>
    `)
    .join("");
}

navItems.forEach((button) => {
  button.addEventListener("click", () => {
    navItems.forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    renderPanel(button.dataset.panel);
  });
});

runScan.addEventListener("click", () => {
  automationState.textContent = "Queued";
  riskCount.textContent = "5";
  terminalOutput.textContent = `$ phoenix mission --target ${document.querySelector("#target-input").value}
scope check: passed
guardrails: locked
automation: queued
next: run authorized web posture and evidence report`;
  setTimeout(() => {
    automationState.textContent = "Ready";
    systemState.textContent = "Mission Queued";
  }, 500);
});

renderPanel("command");

