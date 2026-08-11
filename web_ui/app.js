const panelConfig = {
  command: {
    title: "Command Center",
    state: "Command",
    subtitle: "One-click assessment, verified code healing, known-good snapshots, and automatic rollback.",
    controls: ["control-key", "groq-key", "groq-model"],
    actions: [
      ["security-basics", "Security Basics"],
      ["platform-readiness", "Platform Readiness"],
      ["protect", "Authorize & Protect"],
      ["tier1-status", "Tier-1 Status"],
      ["coverage", "Security Coverage"],
      ["remediation-status", "Protection Status"],
      ["status", "Refresh Status"],
      ["guardrails", "Guardrails"],
      ["tools", "Tool Matrix"],
      ["control-key", "Control Key"],
      ["clear", "Clear Findings"],
    ],
  },
  "bug-bounty": {
    title: "Bug Bounty Lab",
    state: "Bug Bounty",
    subtitle: "A dedicated $150+ workspace for real scope-first audits, safe validation, and submission-ready evidence.",
    controls: ["query", "distro", "hackerone"],
    actions: [
      ["checklist", "Security Checklist"],
      ["web-audit", "Run Audit"],
      ["autopilot", "Scoped Autopilot"],
      ["burp", "Burp Status"],
      ["hackerone", "External Program Ready"],
      ["bug-report", "Finding Report Draft"],
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
    subtitle: "Cross-platform inventory, verified remediation, voice diagnostics, defensive response, and fraud triage.",
    controls: ["distro", "fraud", "research-notes"],
    actions: [
      ["platform-readiness", "Platform Readiness"],
      ["learning-vectors", "Guided Learning"],
      ["research-notebook", "Save Asset Notebook"],
      ["kali-bridge", "Kali Bridge"],
      ["prepare-kali", "Prepare Kali Toolkit"],
      ["protect", "Authorize & Protect"],
      ["remediation-status", "Protection Status"],
      ["kali", "Kali Inventory"],
      ["voice", "Voice Diagnostics"],
      ["defensive", "Defensive Drone"],
      ["fraud", "Fraud Report"],
    ],
  },
  reports: {
    title: "Reports & Evidence",
    state: "Reports",
    subtitle: "Executive summaries, private evidence handoff, finding drafts, and clean exports.",
    controls: ["fraud", "hackerone"],
    actions: [
      ["summary", "Executive Summary"],
      ["bug-report", "Finding Report Draft"],
      ["fraud", "Fraud Workspace"],
      ["guardrails", "Guardrails"],
      ["clear", "Clear Findings"],
    ],
  },
  plans: {
    title: "Plans & Access",
    state: "Plans",
    subtitle: "Choose the operating depth that matches your mission. Every control key has a fixed monthly term.",
    controls: ["control-key"],
    actions: [
      ["plans", "Compare Plans"],
      ["square-status", "Square Connection"],
      ["subscription-status", "Access Status"],
      ["government-compliance", "Government Controls"],
      ["evidence-seal", "Seal Evidence"],
    ],
  },
  settings: {
    title: "Settings",
    state: "Settings",
    subtitle: "Organization profile, private first-party control key, optional providers, and locked safety boundaries.",
    controls: ["organization-name", "business-unit", "environment", "primary-domain", "security-contact", "asset-owner", "maintenance-window", "data-region", "control-key", "groq-key", "groq-model", "hackerone", "distro"],
    actions: [
      ["install-app", "Install Phoenix App"],
      ["save-enterprise", "Save Enterprise Profile"],
      ["enterprise-profile", "Enterprise Profile"],
      ["control-key", "Control Key"],
      ["rotate-key", "Rotate Key"],
      ["guardrails", "Guardrails"],
      ["groq", "Test AI"],
      ["hackerone", "External Program Ready"],
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
const protectSystem = document.querySelector("#protect-system");
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
const fraudInput = document.querySelector("#fraud-input");
const chatInput = document.querySelector("#chat-input");
const chatOutput = document.querySelector("#chat-output");
const chatSend = document.querySelector("#chat-send");
const groqKeyInput = document.querySelector("#groq-key-input");
const controlKeyInput = document.querySelector("#control-key-input");
const groqModelInput = document.querySelector("#groq-model-input");
const hackeroneHandleInput = document.querySelector("#hackerone-handle-input");
const organizationNameInput = document.querySelector("#organization-name-input");
const businessUnitInput = document.querySelector("#business-unit-input");
const environmentInput = document.querySelector("#environment-input");
const primaryDomainInput = document.querySelector("#primary-domain-input");
const securityContactInput = document.querySelector("#security-contact-input");
const assetOwnerInput = document.querySelector("#asset-owner-input");
const maintenanceWindowInput = document.querySelector("#maintenance-window-input");
const dataRegionInput = document.querySelector("#data-region-input");
const researchNotesInput = document.querySelector("#research-notes-input");
const organizationNameDisplay = document.querySelector("#organization-name-display");
const activeTierSide = document.querySelector("#active-tier-side");
const tierExpirySide = document.querySelector("#tier-expiry-side");
const activeTierBadge = document.querySelector("#active-tier-badge");
const tierTermLabel = document.querySelector("#tier-term-label");
const planLockBanner = document.querySelector("#plan-lock-banner");
const tierShortcutButtons = document.querySelectorAll("[data-tier-shortcut]");
const donut = document.querySelector("#severity-donut");
const donutTotal = document.querySelector("#donut-total");
const legend = document.querySelector("#severity-legend");
const duplicateTabBanner = document.querySelector("#duplicate-tab-banner");
const duplicateTabRetry = document.querySelector("#duplicate-tab-retry");

let activePanel = "command";
let lastStatus = null;
let activeRunId = "";
let activeAction = false;
let isPrimaryTab = true;
let singletonController = null;
let activeSubscription = { tier: "unlicensed", tier_name: "No active plan", features: [] };
let deferredInstallPrompt = null;

const CONTROL_KEY_STORAGE = "phoenix-control-key";
const RESEARCH_NOTES_STORAGE = "phoenix-research-notebook";
const SQUARE_PURCHASE_STORAGE = "phoenix-square-purchase";
const SQUARE_PAID_TIERS = new Set(["solo", "base", "enterprise", "government"]);
const SQUARE_PENDING_STATUSES = new Set(["created", "pending_payment"]);
const SQUARE_STATUS_ATTEMPTS = 6;
const SQUARE_STATUS_DELAY_MS = 1500;
const ACTION_FEATURES = {
  protect: "autonomous_remediation",
  "remediation-status": "autonomous_remediation",
  "enterprise-profile": "enterprise_profile",
  "save-enterprise": "enterprise_profile",
  vectors: "security_intelligence",
  browser: "browser_context",
  checklist: "bug_bounty",
  "web-audit": "bug_bounty",
  "bug-report": "bug_bounty",
  burp: "bug_bounty",
  hackerone: "bug_bounty",
  kali: "tool_inventory",
  "kali-bridge": "tool_inventory",
  "prepare-kali": "tool_inventory",
  "learning-vectors": "guided_learning_vectors",
  "research-notebook": "researcher_workspace",
  wordlists: "tool_inventory",
  defensive: "fraud_response",
  fraud: "fraud_response",
  autopilot: "security_program_autopilot",
  summary: "reports",
  clear: "reports",
  "government-compliance": "government_compliance",
  "evidence-seal": "evidence_integrity",
  "control-key": "owner_admin",
  "rotate-key": "owner_admin",
};
const FEATURE_TIER_NAMES = {
  guided_learning_vectors: "Solo",
  researcher_workspace: "Solo",
  scope_manage: "Base",
  web_audit: "Base",
  reports: "Base",
  bug_bounty: "Base",
  security_intelligence: "Base",
  autonomous_remediation: "Enterprise",
  enterprise_profile: "Enterprise",
  browser_context: "Enterprise",
  tool_inventory: "Enterprise",
  fraud_response: "Enterprise",
  security_program_autopilot: "Enterprise",
  government_compliance: "Government",
  evidence_integrity: "Government",
  owner_admin: "Owner",
};

function loadControlKey() {
  const hash = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const keyFromLauncher = hash.get("key") || "";
  if (keyFromLauncher) {
    sessionStorage.setItem(CONTROL_KEY_STORAGE, keyFromLauncher);
    history.replaceState(null, document.title, `${window.location.pathname}${window.location.search}`);
  }
  return keyFromLauncher || sessionStorage.getItem(CONTROL_KEY_STORAGE) || "";
}

function currentControlKey() {
  const typed = controlKeyInput.value.trim();
  if (typed) {
    sessionStorage.setItem(CONTROL_KEY_STORAGE, typed);
    return typed;
  }
  return sessionStorage.getItem(CONTROL_KEY_STORAGE) || "";
}

loadControlKey();

async function api(path, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  if (method !== "GET" && !isPrimaryTab) {
    throw new Error("This is a read-only duplicate tab. Return to the primary Phoenix tab to run changes.");
  }
  const key = currentControlKey();
  const headers = {
    "Content-Type": "application/json",
    ...(key ? { Authorization: `Bearer ${key}` } : {}),
    ...(options.headers || {}),
  };
  const { headers: _ignoredHeaders, ...requestOptions } = options;
  const response = await fetch(path, {
    ...requestOptions,
    headers,
  });
  const payload = await response.json().catch(() => ({ ok: false, error: `HTTP ${response.status}` }));
  if (!response.ok || payload.ok === false) {
    if (response.status === 401) {
      throw new Error("A valid monthly Phoenix control key is required. Start the free Demo or enter an active key in Plans.");
    }
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

function redactSensitiveNumbers(value) {
  return window.PhoenixRedaction?.redactSensitiveNumbers(value) ?? "[redacted output]";
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
  if (key === "plans") {
    renderPlans().catch((error) => renderOutput("Plans", error.message));
  } else {
    applyEntitlements();
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
      ["Tier-1 Loop", "Inventory, assess, prioritize, respond, verify, and audit the enrolled application", "autonomous"],
      ["Permission", "Authorize once; Phoenix completes registered response without repeated prompts", "one click"],
      ["Healing", "Only the enrolled repository and registered reversible actions can change", "bounded"],
      ["Rollback", "Failed verification restores the known-good application snapshot", "automatic"],
      ["API", "A free first-party phx_local_ control key authenticates every local API call", "locked"],
    ],
    "bug-bounty": [
      ["$150+ Access", "Live Bug Bounty tooling begins at Base; lower plans remain learning-only", "gated"],
      ["Scope", "Every real test starts with exact allowlist confirmation", "locked"],
      ["Autopilot", "Enterprise adds registered Kali evidence, CVE context, and report automation", "advanced"],
      ["External programs", "Provider-neutral preparation keeps private evidence local", "private"],
      ["Reports", "Sanitized evidence drafts are generated from current findings", "ready"],
    ],
    intelligence: [
      ["Vectors", "Live public vulnerability context is available", "feed"],
      ["Browser", "Fetch public page context for policy and scope review", "ready"],
      ["Wordlists", "Inventory local Kali lists without exposing secrets", "local"],
      ["Tools", "Matrix shows what is wired and how it is allowed to run", "mapped"],
    ],
    operations: [
      ["Platform", "macOS containers, Windows WSL2, and Linux capabilities are inventoried without elevation", "cross-platform"],
      ["MacBook Kali", "Docker Desktop or Colima runs a confined official Kali image with no host mounts", "registered"],
      ["Commands", "Arbitrary shell execution is disabled; registered actions only", "locked"],
      ["Fraud", "CSV evidence can produce lawful handoff reports", "ready"],
      ["Voice", "Speech diagnostics and typed fallback are available", "ready"],
    ],
    reports: [
      ["Executive", "Summary updates from live session findings", "ready"],
      ["Findings", "Draft reports require explicit enrolled scope", "draft"],
      ["Fraud", "Evidence handoff supports card abuse triage", "lawful"],
      ["Export", "Use generated text as clean report source", "local"],
    ],
    plans: [
      ["Demo", "Free read-only posture preview, checklist, local guidance, and sample reports", "free"],
      ["Solo", "Guided learning, a private research workspace, and platform readiness—no live audits", "$50 / month"],
      ["Base", "Dedicated Bug Bounty, real scoped audits, public vectors, findings, and reports", "$150 / month"],
      ["Enterprise", "Autonomous remediation, cross-platform Kali, tool inventory, and fraud response", "$1,000 / month"],
      ["Government", "Enterprise controls plus compliance mapping and evidence integrity", "$1,500 / month"],
    ],
    settings: [
      ["Control API", "Phoenix generates its own free local key and never returns it in status", "private"],
      ["AI", "Free keyless local guidance works without Groq; a personal provider key is optional", "local"],
      ["Organization", "A reusable private profile configures Phoenix without code changes", "ready"],
      ["External program", "Optional handle prepares provider-neutral readiness guidance", "draft"],
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
      <pre>${escapeHtml(redactSensitiveNumbers(text || "No output returned."))}</pre>
    </div>
  `;
}

function appendOutputAction(label, busyLabel, task) {
  const row = signalList.querySelector(".signal-row.output");
  if (!row) return;
  const actions = document.createElement("div");
  actions.className = "action-bar";
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", () => withBusy(busyLabel, task));
  actions.append(button);
  row.append(actions);
}

function renderJson(title, value) {
  renderOutput(title, JSON.stringify(value, null, 2));
}

function setTerminal(text) {
  terminalOutput.textContent = redactSensitiveNumbers(text);
}

function appendTerminal(text) {
  terminalOutput.textContent = redactSensitiveNumbers(`${terminalOutput.textContent}\n${text}`.trim());
}

function applyEnterpriseProfile(profile = {}) {
  organizationNameInput.value = profile.organization_name || "Your Organization";
  businessUnitInput.value = profile.business_unit || "Security Operations";
  environmentInput.value = profile.environment || "Production";
  primaryDomainInput.value = profile.primary_domain || "";
  securityContactInput.value = profile.security_contact || "";
  assetOwnerInput.value = profile.asset_owner || "";
  maintenanceWindowInput.value = profile.maintenance_window || "Organization policy";
  dataRegionInput.value = profile.data_region || "Local";
  if (organizationNameDisplay) organizationNameDisplay.textContent = profile.organization_name || "Your Organization";
}

function hasFeature(feature) {
  return !feature || (activeSubscription.features || []).includes(feature);
}

function minimumTier(feature) {
  return FEATURE_TIER_NAMES[feature] || "a higher tier";
}

function applyEntitlements(subscription = activeSubscription) {
  activeSubscription = subscription || activeSubscription;
  const tierName = activeSubscription.tier_name || "Demo";
  activeTierSide.textContent = tierName;
  activeTierBadge.textContent = tierName;
  tierExpirySide.textContent = activeSubscription.expires_at ? "Monthly key active" : "Owner monthly access";
  if (tierTermLabel) tierTermLabel.textContent = `${tierName} access`;
  tierShortcutButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.tierShortcut === activeSubscription.tier);
  });

  let lockedCount = 0;
  actionBar.querySelectorAll("[data-action]").forEach((button) => {
    const feature = ACTION_FEATURES[button.dataset.action] || "";
    const locked = Boolean(feature) && !hasFeature(feature);
    button.disabled = locked || !isPrimaryTab;
    button.classList.toggle("plan-locked", locked);
    button.title = locked ? `${minimumTier(feature)} tier required` : "";
    if (locked) lockedCount += 1;
  });
  const topControls = [
    [addScope, "scope_manage"],
    [runScan, "web_audit"],
    [protectSystem, "autonomous_remediation"],
  ];
  topControls.forEach(([button, feature]) => {
    const locked = !hasFeature(feature);
    button.disabled = locked || !isPrimaryTab;
    button.classList.toggle("plan-locked", locked);
    button.title = locked ? `${minimumTier(feature)} tier required` : "";
  });
  document.querySelectorAll('[data-ui-locked="true"]').forEach((button) => {
    button.disabled = true;
  });
  planLockBanner.hidden = lockedCount === 0;
  planLockBanner.textContent = lockedCount
    ? `${tierName} is active. Locked controls remain visible so you can see exactly what the next tier adds.`
    : "";
}

async function renderPlans() {
  const [result, billingResult] = await Promise.all([
    api("/api/subscriptions/catalog"),
    api("/api/billing/square/status").catch(() => ({ square: { checkout_ready: false, environment: "unavailable" } })),
  ]);
  const tiers = result.tiers || [];
  const square = billingResult.square || billingResult;
  const squareConfigured = Boolean(square.configured);
  const checkoutReady = Boolean(square.checkout_ready);
  const webhookReady = Boolean(square.webhook_ready);
  const automaticDeliveryReady = Boolean(square.automatic_delivery_ready ?? webhookReady);
  const squareReady = checkoutReady && automaticDeliveryReady;
  const squareLabel = squareReady
    ? square.environment === "sandbox"
      ? "Square Sandbox is ready for test payments and signed webhook delivery"
      : "Square checkout and signed webhook delivery are ready"
    : squareConfigured
      ? "Square server configuration is present, but signed webhook delivery is still required"
      : "Square checkout is not configured";
  signalList.innerHTML = `
    <div class="pricing-grid">
      ${tiers.map((tier) => {
        const isCurrent = tier.id === activeSubscription.tier || activeSubscription.tier === "owner";
        const price = tier.price_monthly_usd ? `$${tier.price_monthly_usd.toLocaleString()}` : "Free";
        const isPaid = tier.id !== "demo";
        const action = isPaid ? "square-checkout" : "start-demo";
        const buttonText = isCurrent
          ? "Included in current access"
          : !isPaid
            ? "Start free Demo"
            : squareReady
              ? square.environment === "sandbox" ? "Test 30-day access with Square" : "Buy 30-day access with Square"
              : squareConfigured ? "Square webhook required" : "Square setup required";
        const vectorSummary = (tier.defense_vectors || []).slice(0, 4).join(" · ");
        const uiLocked = isCurrent || (isPaid && !squareReady);
        return `<article class="pricing-card tier-${escapeHtml(tier.id)} ${tier.id === "enterprise" ? "featured" : ""}">
          <span class="plan-kicker">${escapeHtml(tier.id === "enterprise" ? "Most complete business plan" : tier.audience)}</span>
          <h3>${escapeHtml(tier.name)}</h3>
          <div class="plan-price">${escapeHtml(price)} ${tier.price_monthly_usd ? "<small>/ month</small>" : ""}</div>
          <p>${escapeHtml(tier.audience)}</p>
          <div class="plan-vector"><strong>${(tier.defense_vectors || []).length}</strong> defense vectors<span>${escapeHtml(vectorSummary)}</span></div>
          <ul>${(tier.highlights || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
          <button type="button" data-plan-action="${action}" data-tier="${escapeHtml(tier.id)}" data-ui-locked="${uiLocked ? "true" : "false"}" ${uiLocked ? "disabled" : ""}>${escapeHtml(buttonText)}</button>
        </article>`;
      }).join("")}
    </div>
    <div class="plan-lock-banner">${escapeHtml(squareLabel)}. Each completed purchase issues one non-renewing 30-day key after Phoenix verifies the exact tier amount, location, order, and signed server event. <span class="action-bar"><button type="button" data-plan-action="enter-key">Activate an existing key</button></span></div>`;
  signalList.querySelectorAll('[data-plan-action="start-demo"]').forEach((button) => {
    button.addEventListener("click", () => withBusy("Starting Demo", startFreeDemo));
  });
  signalList.querySelectorAll('[data-plan-action="square-checkout"]').forEach((button) => {
    button.addEventListener("click", () => withBusy("Opening Square", () => beginSquarePurchase(button.dataset.tier)));
  });
  signalList.querySelector('[data-plan-action="enter-key"]')?.addEventListener("click", focusSubscriptionKey);
  applyEntitlements();
}

async function startFreeDemo() {
  const result = await api("/api/subscriptions/demo", { method: "POST", body: "{}" });
  sessionStorage.setItem(CONTROL_KEY_STORAGE, result.control_key);
  controlKeyInput.value = "";
  await refreshStatus();
  await renderPlans();
}

function focusSubscriptionKey() {
  controlKeyInput.focus();
  controlKeyInput.scrollIntoView({ behavior: "smooth", block: "center" });
  renderOutput("Activate Monthly Access", "Enter the control key delivered after verified payment. Phoenix validates its tier and expiration locally on every request.");
}

async function showSquareStatus() {
  const result = await api("/api/billing/square/status");
  const square = result.square || result;
  const squareConfigured = Boolean(square.configured);
  const automaticDeliveryReady = Boolean(square.automatic_delivery_ready ?? square.webhook_ready);
  const environment = square.environment === "sandbox"
    ? "Sandbox (test payments only)"
    : square.environment === "production"
      ? "Production"
      : "Not configured";
  renderOutput(
    "Square Billing Connection",
    `Environment: ${environment}\nServer configuration: ${squareConfigured ? "present" : "not configured"}\nCheckout link creation: ${square.checkout_ready ? "ready" : squareConfigured ? "blocked until signed delivery is ready" : "not configured"}\nWebhook signature verification: ${square.webhook_ready ? "configured" : "not configured"}\nAutomatic key delivery: ${automaticDeliveryReady ? "ready" : "not ready"}\nCurrency: ${square.currency || "USD"}\n\nSquare credentials remain server-side and are never returned to this browser.`,
  );
}

async function beginSquarePurchase(tier) {
  if (!SQUARE_PAID_TIERS.has(tier)) {
    throw new Error("Choose a paid Phoenix tier before opening Square checkout.");
  }
  const result = await api("/api/billing/square/checkout", {
    method: "POST",
    body: JSON.stringify({ tier }),
  });
  const purchaseId = String(result.purchase_id || "");
  const claimToken = String(result.claim_token || "");
  const serverTier = String(result.tier || tier);
  let checkoutUrl;
  try {
    checkoutUrl = new URL(String(result.checkout_url || ""));
  } catch (_error) {
    throw new Error("Square returned an invalid checkout link.");
  }
  if (!purchaseId || !claimToken || !SQUARE_PAID_TIERS.has(serverTier) || checkoutUrl.protocol !== "https:" || checkoutUrl.username || checkoutUrl.password) {
    throw new Error("Phoenix could not validate the Square checkout response.");
  }
  sessionStorage.setItem(SQUARE_PURCHASE_STORAGE, JSON.stringify({
    purchase_id: purchaseId,
    claim_token: claimToken,
    tier: serverTier,
  }));
  window.location.assign(checkoutUrl.href);
}

function squarePurchaseRecord(result) {
  return result?.purchase && typeof result.purchase === "object" ? result.purchase : (result || {});
}

function squareClaimRecord(result) {
  return result?.claim && typeof result.claim === "object" ? result.claim : (result || {});
}

function normalizedSquareStatus(value) {
  return String(value || "").trim().toLowerCase().replaceAll("-", "_");
}

function waitForSquare(delay = SQUARE_STATUS_DELAY_MS) {
  return new Promise((resolve) => window.setTimeout(resolve, delay));
}

async function copyActiveProductKey() {
  const controlKey = sessionStorage.getItem(CONTROL_KEY_STORAGE) || "";
  if (!controlKey) throw new Error("No active product key is available to copy in this browser session.");
  if (!navigator.clipboard?.writeText) throw new Error("Clipboard access is unavailable. Use the masked control-key field in Plans on this device.");
  await navigator.clipboard.writeText(controlKey);
  renderOutput("Product Key Copied", "The active Phoenix product key is on your clipboard. Keep it private and paste it only into Phoenix on a device you control.");
}

async function resumeSquarePurchase() {
  const stored = sessionStorage.getItem(SQUARE_PURCHASE_STORAGE);
  if (!stored) return;
  let purchase;
  try {
    purchase = JSON.parse(stored);
  } catch (_error) {
    sessionStorage.removeItem(SQUARE_PURCHASE_STORAGE);
    return;
  }
  if (!purchase?.purchase_id || !purchase?.claim_token || !SQUARE_PAID_TIERS.has(purchase?.tier)) {
    sessionStorage.removeItem(SQUARE_PURCHASE_STORAGE);
    return;
  }
  let purchaseStatus = "";
  for (let attempt = 0; attempt < SQUARE_STATUS_ATTEMPTS; attempt += 1) {
    const result = await api("/api/billing/square/purchase", {
      method: "POST",
      body: JSON.stringify({ purchase_id: purchase.purchase_id, claim_token: purchase.claim_token }),
    });
    purchaseStatus = normalizedSquareStatus(squarePurchaseRecord(result).status);
    if (purchaseStatus === "paid" || purchaseStatus === "claimed") break;
    if (!SQUARE_PENDING_STATUSES.has(purchaseStatus)) {
      renderOutput("Square Payment Status", `Purchase status: ${purchaseStatus || "unknown"}. No product key has been issued.`);
      return;
    }
    renderOutput(
      "Square Payment Pending",
      "Waiting for Square's signed payment confirmation. Phoenix will not issue a product key until the completed payment is verified.",
    );
    if (attempt < SQUARE_STATUS_ATTEMPTS - 1) await waitForSquare();
  }
  if (purchaseStatus === "claimed") {
    sessionStorage.removeItem(SQUARE_PURCHASE_STORAGE);
    const keyAvailable = Boolean(currentControlKey());
    renderOutput(
      "Square Purchase Already Activated",
      keyAvailable
        ? "This purchase was already claimed and the active key remains in this browser session."
        : "This one-time purchase claim was already used. Return to the browser session where the key was activated or contact the Phoenix owner.",
    );
    if (keyAvailable) appendOutputAction("Copy Product Key", "Copying Product Key", copyActiveProductKey);
    return;
  }
  if (purchaseStatus !== "paid") {
    renderOutput(
      "Square Payment Still Pending",
      "Square has not yet delivered a signed completed-payment event. No key was issued. Check again shortly; Phoenix will keep the private purchase claim in this browser session.",
    );
    appendOutputAction("Check Square Again", "Checking Square", resumeSquarePurchase);
    return;
  }
  const claimed = await api("/api/billing/square/claim", {
    method: "POST",
    body: JSON.stringify({ purchase_id: purchase.purchase_id, claim_token: purchase.claim_token }),
  });
  const claim = squareClaimRecord(claimed);
  const controlKey = String(claim.control_key || "");
  const subscription = claim.subscription && typeof claim.subscription === "object" ? claim.subscription : {};
  if (!/^phx_(solo|base|enterprise|government)_[A-Za-z0-9_-]{32,128}$/.test(controlKey)) {
    throw new Error("Phoenix received an invalid product-key claim response.");
  }
  sessionStorage.setItem(CONTROL_KEY_STORAGE, controlKey);
  sessionStorage.removeItem(SQUARE_PURCHASE_STORAGE);
  controlKeyInput.value = "";
  await refreshStatus();
  const expiresAt = subscription.expires_at ? new Date(subscription.expires_at) : null;
  const expiryText = expiresAt && !Number.isNaN(expiresAt.getTime())
    ? ` through ${expiresAt.toLocaleString()}`
    : " for 30 days";
  renderOutput("Square Payment Verified", `${subscription.tier_name || purchase.tier} access is active${expiryText}. The key is stored privately in this browser session and can be copied once you are ready to move it to another Phoenix device.`);
  appendOutputAction("Copy Product Key", "Copying Product Key", copyActiveProductKey);
}

function enterpriseProfilePayload() {
  return {
    organization_name: organizationNameInput.value.trim(),
    business_unit: businessUnitInput.value.trim(),
    environment: environmentInput.value,
    primary_domain: primaryDomainInput.value.trim(),
    security_contact: securityContactInput.value.trim(),
    asset_owner: assetOwnerInput.value.trim(),
    maintenance_window: maintenanceWindowInput.value.trim(),
    data_region: dataRegionInput.value.trim(),
  };
}

async function saveEnterpriseProfile() {
  const result = await api("/api/enterprise/profile", {
    method: "POST",
    body: JSON.stringify(enterpriseProfilePayload()),
  });
  applyEnterpriseProfile(result.profile);
  renderOutput("Enterprise Profile Saved", "Private organization configuration is active. No source-code edits are required.");
}

async function showEnterpriseProfile() {
  const result = await api("/api/enterprise/profile");
  applyEnterpriseProfile(result.profile);
  const safeProfile = { ...result.profile };
  if (safeProfile.security_contact) safeProfile.security_contact = "configured and private";
  renderJson("Enterprise Profile", safeProfile);
}

function updateKpis(status) {
  lastStatus = status;
  const severity = status.severity || {};
  const high = severity.High || 0;
  const med = severity.Medium || 0;
  const low = severity.Low || 0;
  const info = severity.Info || severity.Informational || 0;
  const total = high + med + low + info;
  activeSubscription = status.subscription || activeSubscription;
  applyEntitlements(activeSubscription);
  scopeCount.textContent = status.scopeCount ? "Enrolled" : "None";
  riskCount.textContent = high ? "Detected" : "None";
  evidenceQuality.textContent = total ? "Collected" : "Ready";
  if (status.groqConfigured) {
    groqKeyInput.placeholder = "Saved local Groq key is active";
    if (!groqModelInput.value.trim()) {
      groqModelInput.value = "auto";
    }
  }
  controlKeyInput.placeholder = "Configured privately · value never displayed";
  const remediation = status.remediation || {};
  if (remediation.active_run_id || remediation.activeRun) {
    automationState.textContent = "Healing";
  }
  donutTotal.textContent = total ? "Signals" : "None";
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
    .map(([cls, label, count]) => `<li><span class="dot ${cls}"></span>${label} <strong>${count ? "Detected" : "None"}</strong></li>`)
    .join("");
}

async function refreshStatus() {
  const status = await api("/api/status");
  applyEnterpriseProfile(status.enterprise || {});
  updateKpis(status);
  automationState.textContent = "Ready";
  systemState.textContent = "API Online";
  if (activePanel === "command") {
    renderRows([
      ["Protection", status.remediation?.active_run_id ? "An authorized protection run is active" : "Ready for one-click authorization", status.remediation?.active_run_id ? "running" : "ready"],
      ["Access", `${status.subscription?.tier_name || "Demo"} · monthly control key`, "active"],
      ["AI", status.aiProvider || "Phoenix Local (free, keyless)", status.groqConfigured ? "hosted" : "local"],
      ["Control API", "Authenticated; secret identifiers are not displayed", "locked"],
      ["Guardrails", "Scope, credential, token, rogue AP, exploit-delivery, and review locks active", "locked"],
    ]);
  }
  setTerminal(`$ phoenix api status
app: ${status.app}
scope assets: ${status.scopeCount ? "enrolled" : "none"}
findings: ${status.findingsCount ? "present" : "none"}
ai: ${status.aiProvider || "Phoenix Local (free, keyless)"}
control api: authenticated; identifiers hidden
tier: ${status.subscription?.tier_name || "Demo"}
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
  scopeCount.textContent = result.scope.length ? "Enrolled" : "None";
  systemState.textContent = "Scope Updated";
  renderOutput("Scope Updated", `Added/confirmed: ${result.added}\n\nCurrent scope:\n${result.scope.join("\n") || "empty"}`);
  setTerminal(`$ phoenix scope add ${target}
status: ${result.added ? "authorized" : "already authorized"}
scope: enrolled`);
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
new findings: ${result.findings.length ? "present" : "none"}
session findings: ${result.totalFindings ? "present" : "none"}`);
}

function formatFindings(result) {
  const findingText = (result.findings || [])
    .map((item) => `[${item.severity}] ${item.title}\n${item.detail}\nFix: ${item.remediation}`)
    .join("\n\n");
  return `${result.summary || "No summary returned."}\n\nFindings\n${findingText || "No findings returned."}\n\nEvidence\n${(result.evidence || []).join("\n\n")}`;
}

const REMEDIATION_PHASES = ["preflight", "inventory", "assess", "plan", "snapshot", "apply", "verify", "report"];
const TERMINAL_RUN_STATES = new Set(["succeeded", "failed", "rolled_back", "cancelled", "completed"]);

function runId(run) {
  return run.run_id || run.runId || run.id || "";
}

function runPhase(run) {
  return String(run.phase || run.state || run.status || "preflight").toLowerCase();
}

function renderRemediationRun(run) {
  const phase = runPhase(run);
  const state = String(run.status || run.state || phase);
  const terminal = TERMINAL_RUN_STATES.has(state.toLowerCase());
  const phaseIndex = terminal ? REMEDIATION_PHASES.length - 1 : Math.max(0, REMEDIATION_PHASES.indexOf(phase));
  const rawProgress = Number(run.progress ?? run.percent ?? (terminal ? 100 : ((phaseIndex + 1) / REMEDIATION_PHASES.length) * 100));
  const progress = Math.max(0, Math.min(100, Number.isFinite(rawProgress) ? rawProgress : 0));
  const events = run.events || run.audit || run.history || [];
  const eventText = events
    .slice(-8)
    .map((item) => typeof item === "string" ? item : `${item.phase || item.event || item.type || "event"}: ${item.message || item.detail || item.status || "complete"}`)
    .join("\n");
  const summary = run.summary || run.message || run.result?.summary || "Phoenix is protecting the enrolled local application with registered, reversible actions.";
  signalList.innerHTML = `
    <section class="run-card">
      <header>
        <div>
          <span>Authorized protection run</span>
          <strong>${escapeHtml(state)}</strong>
        </div>
        <em>${escapeHtml(phase)}</em>
      </header>
      <div class="run-progress" aria-label="Remediation progress"><span style="width:${progress}%"></span></div>
      <div class="run-steps">
        ${REMEDIATION_PHASES.map((item, index) => `<div class="run-step ${index < phaseIndex ? "done" : index === phaseIndex ? "active" : ""}">${escapeHtml(item)}</div>`).join("")}
      </div>
      <div class="signal-row output"><pre>${escapeHtml(redactSensitiveNumbers(`${summary}${eventText ? `\n\nRecent audit events\n${eventText}` : ""}`))}</pre></div>
      <div class="run-actions">
        ${runId(run) ? '<button type="button" data-run-action="refresh">Refresh</button>' : ""}
        ${runId(run) && ["succeeded", "failed", "completed"].includes(state.toLowerCase()) ? '<button type="button" data-run-action="rollback">Rollback</button>' : ""}
      </div>
    </section>`;
  signalList.querySelector('[data-run-action="refresh"]')?.addEventListener("click", () => withBusy("Refreshing Protection", refreshActiveRun));
  signalList.querySelector('[data-run-action="rollback"]')?.addEventListener("click", () => withBusy("Rolling Back", rollbackActiveRun));
}

async function refreshActiveRun() {
  if (!activeRunId) {
    const status = await api("/api/remediation/status");
    const run = status.run || status.latest_run || status.latest || status;
    activeRunId = runId(run);
    if (!activeRunId) {
      renderJson("Protection Status", status);
      return;
    }
  }
  const result = await api(`/api/remediation/runs/${encodeURIComponent(activeRunId)}`);
  const run = result.run || result;
  renderRemediationRun(run);
  return run;
}

async function pollRemediationRun() {
  for (let attempt = 0; attempt < 180 && activeRunId; attempt += 1) {
    const run = await refreshActiveRun();
    const state = String(run?.status || run?.state || "").toLowerCase();
    if (TERMINAL_RUN_STATES.has(state)) {
      automationState.textContent = state === "succeeded" || state === "completed" ? "Protected" : "Needs Review";
      systemState.textContent = state === "succeeded" || state === "completed" ? "Verified" : state;
      return run;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return null;
}

async function protectCurrentSystem() {
  automationState.textContent = "Preflight";
  systemState.textContent = "Protecting";
  setTerminal("$ phoenix protect --authorized-local --verify --rollback-on-failure\nregistered actions only\npreflight: starting");
  const idempotencyKey = `web-${Date.now()}-${crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2)}`;
  const result = await api("/api/tier1/run", {
    method: "POST",
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({ apply: true, authorization: true }),
  });
  const report = result.report || result;
  const run = report.response?.remediation;
  if (!run?.ok) {
    renderJson("Tier-1 Security Report", report);
    automationState.textContent = "Needs Review";
    return;
  }
  activeRunId = runId(run);
  renderRemediationRun(run);
  await pollRemediationRun();
}

async function showTier1Status() {
  const result = await api("/api/tier1/status");
  renderJson("Autonomous Tier-1 Status", result);
}

async function showSecurityCoverage() {
  const result = await api("/api/tier1/coverage");
  const lines = (result.functions || []).flatMap((item) => [
    `${item.function}: ${item.status}`,
    `Automated: ${(item.automated || []).join(", ") || "none"}`,
    `Needs organization/adapter: ${(item.requires_organization || item.requires_adapter || []).join(", ") || "none"}`,
    "",
  ]);
  renderOutput("Security Coverage", `${result.claim}\n\n${lines.join("\n")}`);
}

async function showSubscriptionStatus() {
  const result = await api("/api/subscriptions/status");
  const subscription = result.subscription || {};
  renderOutput(
    "Monthly Access Status",
    `Tier: ${subscription.tier_name || "Demo"}\nStatus: ${subscription.active === false ? "expired" : "active"}\nTerm: 30 days\nExpires: ${subscription.expires_at || "owner-managed monthly key"}\n\nEnabled controls\n${(subscription.features || []).join("\n")}`,
  );
}

async function showGovernmentCompliance() {
  const result = await api("/api/government/compliance");
  renderJson("Government Control Assurance", result);
}

async function sealGovernmentEvidence() {
  const result = await api("/api/government/evidence-seal", { method: "POST", body: "{}" });
  renderJson("Evidence Integrity Seal", result);
}

async function rollbackActiveRun() {
  if (!activeRunId) {
    throw new Error("No remediation run is selected.");
  }
  const result = await api(`/api/remediation/runs/${encodeURIComponent(activeRunId)}/rollback`, {
    method: "POST",
    body: "{}",
  });
  renderRemediationRun(result.run || result);
}

async function showControlKeyStatus() {
  await api("/api/control-key");
  renderOutput("Phoenix Control API Key", "Configured and authenticated. The key and its identifiers stay hidden in the protected local key store and this browser session.");
}

async function rotateControlKey() {
  const result = await api("/api/control-key/rotate", { method: "POST", body: "{}" });
  const newKey = result.controlKey;
  sessionStorage.setItem(CONTROL_KEY_STORAGE, newKey);
  controlKeyInput.value = newKey;
  renderOutput("Phoenix Control Key Rotated", "The new key was stored in this masked browser field and protected local key store. The previous key is invalid.");
}

async function selectedFraudCsv() {
  const file = fraudInput.files?.[0];
  if (!file) {
    return "";
  }
  if (file.size > 1024 * 1024) {
    throw new Error("Fraud CSV imports are limited to 1 MB.");
  }
  return file.text();
}

async function runAction(action) {
  if (action === "install-app") {
    await installPhoenixApp();
    return;
  }
  if (action === "security-basics") {
    const result = await api("/api/security-basics");
    renderJson("Security Basics", result);
    return;
  }
  if (action === "plans") {
    await renderPlans();
    return;
  }
  if (action === "square-status") {
    await showSquareStatus();
    return;
  }
  if (action === "subscription-status") {
    await showSubscriptionStatus();
    return;
  }
  if (action === "government-compliance") {
    await showGovernmentCompliance();
    return;
  }
  if (action === "evidence-seal") {
    await sealGovernmentEvidence();
    return;
  }
  if (action === "save-enterprise") {
    await saveEnterpriseProfile();
    return;
  }
  if (action === "enterprise-profile") {
    await showEnterpriseProfile();
    return;
  }
  if (action === "protect") {
    await protectCurrentSystem();
    return;
  }
  if (action === "tier1-status") {
    await showTier1Status();
    return;
  }
  if (action === "coverage") {
    await showSecurityCoverage();
    return;
  }
  if (action === "remediation-status") {
    await refreshActiveRun();
    return;
  }
  if (action === "control-key") {
    await showControlKeyStatus();
    return;
  }
  if (action === "rotate-key") {
    await rotateControlKey();
    return;
  }
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
    renderOutput("Security Program Checklist", result.text);
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
    renderOutput("Scoped Security Autopilot", formatFindings(result));
    return;
  }
  if (action === "bug-report") {
    const result = await api("/api/bug-bounty-report", {
      method: "POST",
      body: JSON.stringify({ target: targetValue() }),
    });
    renderOutput("Finding Report Draft", result.report);
    return;
  }
  if (action === "vectors") {
    const query = encodeURIComponent(queryInput.value.trim() || targetValue() || "enterprise application API cloud identity security");
    const target = encodeURIComponent(targetValue());
    const result = await api(`/api/current-vectors?query=${query}&target=${target}`);
    renderOutput("Current Vectors", result.text);
    return;
  }
  if (action === "browser") {
    const url = browserInput.value.trim();
    if (!url) throw new Error("Enter an approved public URL first.");
    const result = await api("/api/browser-context", {
      method: "POST",
      body: JSON.stringify({ url }),
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
  if (action === "kali-bridge") {
    const result = await api(`/api/kali-bridge?distro=${encodeURIComponent(distroValue())}`);
    renderJson("Cross-platform Kali Bridge", result.bridge);
    return;
  }
  if (action === "prepare-kali") {
    const result = await api("/api/kali-bridge/prepare", {
      method: "POST",
      body: JSON.stringify({ authorization: true }),
    });
    renderJson("Kali Toolkit Preparation", result);
    return;
  }
  if (action === "platform-readiness") {
    const result = await api("/api/platform-readiness");
    renderJson("Platform Readiness", result);
    return;
  }
  if (action === "learning-vectors") {
    const result = await api("/api/learning-vectors");
    renderJson("Guided Cybersecurity Pathway", result);
    return;
  }
  if (action === "research-notebook") {
    const note = researchNotesInput.value.trim();
    localStorage.setItem(RESEARCH_NOTES_STORAGE, note);
    renderOutput("Private Asset Notebook", note ? "Saved on this device only. No note contents were sent to Phoenix or a third party." : "The device-local notebook was cleared.");
    return;
  }
  if (action === "defensive") {
    const csvText = await selectedFraudCsv();
    const result = await api("/api/defensive-drone", {
      method: "POST",
      body: JSON.stringify({ target: targetValue(), csvText }),
    });
    await refreshStatus();
    renderOutput("Defensive Drone", formatFindings(result));
    return;
  }
  if (action === "fraud") {
    const csvText = await selectedFraudCsv();
    const result = await api("/api/fraud-report", {
      method: "POST",
      body: JSON.stringify({ csvText }),
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
    const handle = encodeURIComponent(hackeroneHandleInput.value.trim() || "external program");
    const result = await api(`/api/hackerone-readiness?handle=${handle}`);
    renderOutput("External Program Readiness", result.text);
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

async function installPhoenixApp() {
  if (window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone === true) {
    renderOutput("Phoenix App", "Phoenix is already running as an installed app on this device.");
    return;
  }
  if (deferredInstallPrompt) {
    deferredInstallPrompt.prompt();
    const choice = await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    renderOutput("Phoenix App", choice.outcome === "accepted" ? "Phoenix installation was accepted." : "Installation was dismissed; you can try again from Settings.");
    return;
  }
  const appleMobile = /iPad|iPhone|iPod/.test(navigator.userAgent);
  const message = appleMobile
    ? "On iPhone or iPad, open the Share menu and choose Add to Home Screen. Use the private Phoenix HTTPS address so the installed app can reach its authorized host."
    : "Use your browser menu and choose Install Phoenix, Install app, or Add to Dock. If the option is unavailable, open Phoenix through its private HTTPS address first.";
  renderOutput("Install Phoenix", message);
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
        model: groqModelInput.value.trim() || "auto",
      }),
    });
  appendChat("assistant", result.text);
  renderOutput("Phoenix AI", result.text);
}

function appendChat(role, text) {
  const node = document.createElement("div");
  node.className = `chat-message ${role}`;
  node.textContent = redactSensitiveNumbers(text);
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
  if (activeAction) {
    throw new Error("Phoenix is already running an action in this tab.");
  }
  activeAction = true;
  const priorButtonStates = new Map();
  document.querySelectorAll("button").forEach((button) => {
    if (button !== duplicateTabRetry) {
      priorButtonStates.set(button, button.disabled);
      button.disabled = true;
    }
  });
  try {
    systemState.textContent = label;
    automationState.textContent = "Running";
    await task();
    if (automationState.textContent === "Running") {
      automationState.textContent = "Ready";
    }
  } catch (error) {
    systemState.textContent = "Action Failed";
    automationState.textContent = "Needs Review";
    renderOutput("Error", error.message);
    setTerminal(`$ phoenix error
${error.message}`);
  } finally {
    activeAction = false;
    if (isPrimaryTab) {
      priorButtonStates.forEach((wasDisabled, button) => {
        if (button.isConnected) button.disabled = wasDisabled;
      });
      document.querySelectorAll(".toggle").forEach((button) => {
        button.disabled = true;
      });
      applyEntitlements();
    }
  }
}

function setPrimaryTab(primary, detail = "") {
  isPrimaryTab = Boolean(primary);
  duplicateTabBanner.hidden = isPrimaryTab;
  document.querySelectorAll("button, input, textarea, select").forEach((control) => {
    if (control !== duplicateTabRetry) {
      control.disabled = !isPrimaryTab;
    }
  });
  if (!isPrimaryTab) {
    systemState.textContent = "Read Only";
    automationState.textContent = "Primary Tab Active";
    duplicateTabBanner.querySelector("p").textContent = detail || "This tab is read-only so a second click cannot start a duplicate remediation run.";
  } else {
    systemState.textContent = "Ready";
    automationState.textContent = "Ready";
    applyEntitlements();
  }
}

function initializeSingleton() {
  if (!window.PhoenixSingleton?.start) {
    setPrimaryTab(true);
    return;
  }
  singletonController = window.PhoenixSingleton.start({
    onPrimary: () => setPrimaryTab(true),
    onSecondary: (detail) => setPrimaryTab(false, typeof detail === "string" ? detail : ""),
    onStatus: (status) => {
      if (!isPrimaryTab && status?.message) {
        duplicateTabBanner.querySelector("p").textContent = status.message;
      }
    },
  });
}

navItems.forEach((button) => {
  button.addEventListener("click", () => {
    navItems.forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    renderPanel(button.dataset.panel);
  });
});

tierShortcutButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const plansButton = Array.from(navItems).find((item) => item.dataset.panel === "plans");
    plansButton?.click();
  });
});

addScope.addEventListener("click", () => withBusy("Adding Scope", addTargetToScope));
runScan.addEventListener("click", () => withBusy("Running Audit", runWebAudit));
protectSystem.addEventListener("click", () => withBusy("Protecting System", protectCurrentSystem));
chatSend.addEventListener("click", () => withBusy("Asking Phoenix AI", sendChat));
controlKeyInput.addEventListener("change", () => {
  const key = controlKeyInput.value.trim();
  if (key) {
    sessionStorage.setItem(CONTROL_KEY_STORAGE, key);
    refreshStatus().catch((error) => renderOutput("Control Key", error.message));
  }
});
duplicateTabRetry.addEventListener("click", () => {
  if (singletonController?.retry) {
    singletonController.retry();
  } else {
    window.location.reload();
  }
});
chatInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    withBusy("Asking Phoenix AI", sendChat);
  }
});

window.addEventListener("beforeinstallprompt", (event) => {
  event.preventDefault();
  deferredInstallPrompt = event;
});

window.addEventListener("appinstalled", () => {
  deferredInstallPrompt = null;
  setTerminal("$ phoenix app installed\nstandalone shell: ready\nprivate backend: authorization required");
});

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch(() => {
      // The live API remains available even if this browser blocks offline-shell registration.
    });
  });
}

initializeSingleton();
researchNotesInput.value = localStorage.getItem(RESEARCH_NOTES_STORAGE) || "";
const requestedPanel = new URLSearchParams(window.location.search).get("panel");
const initialPanel = panelConfig[requestedPanel] ? requestedPanel : "command";
navItems.forEach((item) => item.classList.toggle("active", item.dataset.panel === initialPanel));
renderPanel(initialPanel);

async function initializePhoenix() {
  try {
    await refreshStatus();
  } catch (error) {
    renderOutput("API Offline", error.message);
    return;
  }
  try {
    await resumeSquarePurchase();
  } catch (error) {
    renderOutput("Square Payment", error.message);
  }
}

initializePhoenix();
