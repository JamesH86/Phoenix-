(() => {
  "use strict";

  const PURCHASE_STORAGE_KEY = "phoenix.square.purchase.v1";
  const LICENSE_STORAGE_KEY = "phoenix.license.v1";
  const POLL_LIMIT = 20;
  const POLL_DELAY_MS = 3_000;
  const SQUARE_CHECKOUT_HOSTS = new Set(["square.link", "checkout.square.site"]);

  const environmentPill = document.querySelector("#environmentPill");
  const environmentLabel = document.querySelector("#environmentLabel");
  const checkoutNotice = document.querySelector("#checkoutNotice");
  const buyButtons = [...document.querySelectorAll("[data-tier]")];
  const purchasePanel = document.querySelector("#purchasePanel");
  const purchaseKicker = document.querySelector("#purchaseKicker");
  const purchaseTitle = document.querySelector("#purchaseTitle");
  const purchaseMessage = document.querySelector("#purchaseMessage");
  const checkPaymentButton = document.querySelector("#checkPaymentButton");
  const licensePanel = document.querySelector("#licensePanel");
  const licenseOutput = document.querySelector("#licenseOutput");
  const licenseMeta = document.querySelector("#licenseMeta");
  const toggleLicenseButton = document.querySelector("#toggleLicenseButton");
  const copyLicenseButton = document.querySelector("#copyLicenseButton");
  const toast = document.querySelector("#toast");

  let gatewayStatus = null;
  let pollCount = 0;
  let pollTimer = null;

  function storageGet(key) {
    try {
      const raw = sessionStorage.getItem(key);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  function storageSet(key, value) {
    try {
      sessionStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch {
      return false;
    }
  }

  function storageRemove(key) {
    try {
      sessionStorage.removeItem(key);
    } catch {
      // Storage is an enhancement; API verification remains authoritative.
    }
  }

  function notify(message) {
    toast.textContent = message;
    toast.hidden = false;
    window.setTimeout(() => {
      toast.hidden = true;
    }, 3_500);
  }

  function setEnvironment(kind, label) {
    environmentPill.className = `environment-pill environment-${kind}`;
    environmentLabel.textContent = label;
  }

  function setButtons(enabled, label) {
    for (const button of buyButtons) {
      button.disabled = !enabled;
      button.textContent = label;
    }
  }

  function showPurchase({ kicker, title, message, canCheck = true }) {
    purchasePanel.hidden = false;
    purchaseKicker.textContent = kicker;
    purchaseTitle.textContent = title;
    purchaseMessage.textContent = message;
    checkPaymentButton.hidden = !canCheck;
  }

  function showLicense(license) {
    licenseOutput.type = "password";
    toggleLicenseButton.textContent = "Show";
    licenseOutput.value = license.license_token;
    licenseMeta.textContent = `${license.tier} access · expires ${new Date(license.expires_at).toLocaleString()}`;
    licensePanel.hidden = false;
    purchasePanel.hidden = true;
    licensePanel.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  async function api(path, body) {
    const response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(payload.error || "request_failed");
      error.code = payload.error || "request_failed";
      throw error;
    }
    return payload;
  }

  function newPurchaseId() {
    if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  async function beginPurchase(button) {
    if (!gatewayStatus?.ready) return;
    const tier = button.dataset.tier;
    const purchaseId = newPurchaseId();
    const originalLabel = button.textContent;
    button.disabled = true;
    button.textContent = "Opening Square…";
    try {
      const returnUrl = new URL(window.location.pathname, window.location.origin).toString();
      const result = await api("/api/checkout", {
        tier,
        purchase_id: purchaseId,
        return_url: returnUrl,
      });
      const checkoutUrl = new URL(result.checkout_url);
      if (checkoutUrl.protocol !== "https:" || !SQUARE_CHECKOUT_HOSTS.has(checkoutUrl.hostname)) {
        throw new Error("invalid_checkout_destination");
      }
      const saved = storageSet(PURCHASE_STORAGE_KEY, {
        purchase_receipt: result.purchase_receipt,
        purchase_id: result.purchase_id,
        tier: result.tier,
        created_at: new Date().toISOString(),
      });
      if (!saved) throw new Error("session_storage_unavailable");
      window.location.assign(checkoutUrl.toString());
    } catch (error) {
      button.disabled = false;
      button.textContent = originalLabel;
      notify(
        error.code === "service_not_ready"
          ? "Secure checkout is still being connected."
          : "Square checkout could not be opened. Please try again.",
      );
    }
  }

  function schedulePoll() {
    if (pollCount >= POLL_LIMIT) {
      showPurchase({
        kicker: "Payment not confirmed yet",
        title: "Square is still processing",
        message: "Use Check payment in a moment. Phoenix will not issue access until Square confirms completion.",
      });
      return;
    }
    window.clearTimeout(pollTimer);
    pollTimer = window.setTimeout(checkPurchase, POLL_DELAY_MS);
  }

  async function claimPurchase(purchase) {
    const license = await api("/api/claim", {
      purchase_receipt: purchase.purchase_receipt,
    });
    storageSet(LICENSE_STORAGE_KEY, license);
    storageRemove(PURCHASE_STORAGE_KEY);
    showLicense(license);
  }

  async function checkPurchase() {
    const purchase = storageGet(PURCHASE_STORAGE_KEY);
    if (!purchase?.purchase_receipt) return;
    pollCount += 1;
    checkPaymentButton.disabled = true;
    showPurchase({
      kicker: "Secure verification",
      title: "Checking your Square payment…",
      message: "Phoenix is matching the live order, payment, amount, location, and application.",
      canCheck: false,
    });
    try {
      const status = await api("/api/purchase-status", {
        purchase_receipt: purchase.purchase_receipt,
      });
      if (status.state === "active") {
        await claimPurchase(purchase);
        return;
      }
      if (status.state === "expired" || status.state === "refunded" || status.state === "cancelled" || status.state === "failed") {
        storageRemove(PURCHASE_STORAGE_KEY);
        showPurchase({
          kicker: "Access not issued",
          title: `Purchase ${status.state}`,
          message: "No license was created. Review the transaction in Square or start a new checkout.",
          canCheck: false,
        });
        return;
      }
      showPurchase({
        kicker: "Awaiting Square",
        title: "Payment has not completed yet",
        message: "This page will check again automatically. Access stays locked until payment is complete.",
      });
      schedulePoll();
    } catch (error) {
      showPurchase({
        kicker: "Verification paused",
        title: "We could not confirm the payment",
        message:
          error.code === "invalid_purchase_receipt"
            ? "The saved purchase receipt is no longer valid. Start a new checkout."
            : "Use Check payment to try the secure verification again.",
      });
    } finally {
      checkPaymentButton.disabled = false;
    }
  }

  async function loadGateway() {
    try {
      const response = await fetch("/api/status", { cache: "no-store", credentials: "same-origin" });
      const status = await response.json();
      if (!response.ok) throw new Error("status_failed");
      gatewayStatus = status;
      const liveProduction =
        status.square_environment === "production" &&
        status.ready === true &&
        status.components?.live_webhook === true;
      const sandboxReady = status.square_environment === "sandbox" && status.ready === true;

      if (liveProduction) {
        setEnvironment("live", "Live checkout verified");
        setButtons(true, "Buy with Square");
        checkoutNotice.textContent = "Live Square checkout is connected. Licenses issue only after verified payment.";
      } else if (sandboxReady) {
        setEnvironment("sandbox", "Sandbox · test payments only");
        setButtons(true, "Test with Square");
        checkoutNotice.textContent = "Sandbox mode is active. No real payment or live license sale will be accepted.";
      } else {
        setEnvironment("offline", "Sales not ready");
        setButtons(false, "Checkout unavailable");
        checkoutNotice.textContent =
          status.square_environment === "production"
            ? "Real purchases are disabled until Square, the live webhook, and license signing are all verified."
            : "Sandbox checkout is still being configured.";
      }

      const savedLicense = storageGet(LICENSE_STORAGE_KEY);
      if (savedLicense?.license_token) showLicense(savedLicense);
      else if (storageGet(PURCHASE_STORAGE_KEY)?.purchase_receipt && status.ready) checkPurchase();
    } catch {
      setEnvironment("offline", "Checkout connection unavailable");
      setButtons(false, "Checkout unavailable");
      checkoutNotice.textContent = "Secure checkout cannot be reached right now. No payment has been started.";
    }
  }

  for (const button of buyButtons) {
    button.addEventListener("click", () => beginPurchase(button));
  }
  checkPaymentButton.addEventListener("click", () => {
    pollCount = 0;
    checkPurchase();
  });
  toggleLicenseButton.addEventListener("click", () => {
    const reveal = licenseOutput.type === "password";
    licenseOutput.type = reveal ? "text" : "password";
    toggleLicenseButton.textContent = reveal ? "Hide" : "Show";
  });
  copyLicenseButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(licenseOutput.value);
      notify("Signed license copied. Keep it private.");
    } catch {
      licenseOutput.type = "text";
      licenseOutput.select();
      notify("Select and copy the license, then keep it private.");
    }
  });

  loadGateway();
})();
