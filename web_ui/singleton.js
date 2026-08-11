(function attachPhoenixSingleton(windowObject) {
  "use strict";

  const LEASE_KEY = "phoenix-guardian-primary";
  const SIGNAL_KEY = "phoenix-guardian-signal";
  const CHANNEL_NAME = "phoenix-guardian-singleton";
  const LEASE_TTL_MS = 5000;
  const HEARTBEAT_MS = 2000;
  const CLAIM_SETTLE_MS = 60;

  let activeController = null;

  function safeCall(callback, ...args) {
    if (typeof callback !== "function") {
      return;
    }
    try {
      callback(...args);
    } catch (error) {
      if (windowObject.console && typeof windowObject.console.error === "function") {
        windowObject.console.error("Phoenix singleton callback failed", error);
      }
    }
  }

  function randomTabId() {
    const cryptoObject = windowObject.crypto;
    if (cryptoObject && typeof cryptoObject.randomUUID === "function") {
      return cryptoObject.randomUUID();
    }
    if (cryptoObject && typeof cryptoObject.getRandomValues === "function") {
      const bytes = new Uint8Array(16);
      cryptoObject.getRandomValues(bytes);
      return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
    }
    return `tab-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  }

  function start(options) {
    if (activeController) {
      return activeController;
    }

    const callbacks = options || {};
    const tabId = randomTabId();
    let role = "secondary";
    let strategy = "pending";
    let primaryTabId = null;
    let released = false;
    let secondaryNotified = false;
    let lastStatus;
    let monitorTimer = null;
    let claimTimer = null;
    let webLockAttemptPending = false;
    let webLockRelease = null;
    let channel = null;

    const controller = {
      get isPrimary() {
        return !released && role === "primary";
      },
      get tabId() {
        return tabId;
      },
      get method() {
        return strategy;
      },
      publishStatus,
      release,
    };
    activeController = controller;

    function storageObject() {
      try {
        return windowObject.localStorage || null;
      } catch (_error) {
        return null;
      }
    }

    function parseJson(value) {
      try {
        return value ? JSON.parse(value) : null;
      } catch (_error) {
        return null;
      }
    }

    function readLease() {
      const storage = storageObject();
      if (!storage) {
        return null;
      }
      try {
        const lease = parseJson(storage.getItem(LEASE_KEY));
        if (!lease || typeof lease.tabId !== "string" || typeof lease.expiresAt !== "number") {
          return null;
        }
        return lease;
      } catch (_error) {
        return null;
      }
    }

    function writeLease() {
      const storage = storageObject();
      if (!storage) {
        return false;
      }
      const lease = {
        tabId,
        method: strategy,
        expiresAt: Date.now() + LEASE_TTL_MS,
      };
      try {
        storage.setItem(LEASE_KEY, JSON.stringify(lease));
        return true;
      } catch (_error) {
        return false;
      }
    }

    function removeOwnLease() {
      const storage = storageObject();
      if (!storage) {
        return;
      }
      try {
        const lease = readLease();
        if (lease && lease.tabId === tabId) {
          storage.removeItem(LEASE_KEY);
        }
      } catch (_error) {
        // Lease expiry is the final cleanup fallback.
      }
    }

    function postMessage(message) {
      const envelope = {
        ...message,
        from: tabId,
        sentAt: Date.now(),
      };
      if (channel) {
        try {
          channel.postMessage(envelope);
        } catch (_error) {
          // The storage signal below is the compatibility fallback.
        }
      }

      const storage = storageObject();
      if (storage) {
        try {
          storage.setItem(SIGNAL_KEY, JSON.stringify(envelope));
          storage.removeItem(SIGNAL_KEY);
        } catch (_error) {
          // Cross-tab messaging is best-effort when storage is unavailable.
        }
      }
    }

    function notifySecondary(reason, ownerId) {
      const nextOwner = ownerId || null;
      const changedOwner = primaryTabId !== nextOwner;
      primaryTabId = nextOwner;
      if (!secondaryNotified || changedOwner || role !== "secondary") {
        role = "secondary";
        secondaryNotified = true;
        safeCall(callbacks.onSecondary, {
          controller,
          tabId,
          primaryTabId,
          method: strategy,
          reason,
        });
      }
    }

    function becomePrimary(method) {
      if (released) {
        return;
      }
      const changed = role !== "primary" || strategy !== method;
      role = "primary";
      strategy = method;
      primaryTabId = tabId;
      secondaryNotified = false;
      writeLease();
      postMessage({
        type: "heartbeat",
        method: strategy,
        expiresAt: Date.now() + LEASE_TTL_MS,
      });
      if (changed) {
        safeCall(callbacks.onPrimary, {
          controller,
          tabId,
          method: strategy,
        });
      }
    }

    function stepDown(reason, ownerId) {
      if (role === "primary" && strategy === "web-lock" && webLockRelease) {
        const unlock = webLockRelease;
        webLockRelease = null;
        unlock();
      }
      notifySecondary(reason, ownerId);
    }

    function publishStatus(status) {
      if (!controller.isPrimary) {
        return false;
      }
      lastStatus = status;
      postMessage({
        type: "status",
        payload: status,
      });
      return true;
    }

    function deliverStatus(message) {
      if (message.from === tabId || (message.to && message.to !== tabId)) {
        return;
      }
      safeCall(callbacks.onStatus, message.payload, {
        from: message.from,
        sentAt: message.sentAt,
      });
    }

    function resolveLeaseConflict(message) {
      if (!controller.isPrimary || message.from === tabId) {
        return;
      }
      if (strategy === "web-lock") {
        // The Web Locks API is authoritative when available.
        writeLease();
        return;
      }
      const lease = readLease();
      if (lease && lease.expiresAt > Date.now() && lease.tabId !== tabId) {
        stepDown("another-tab-owns-lease", lease.tabId);
      }
    }

    function handleMessage(message) {
      if (released || !message || message.from === tabId) {
        return;
      }
      if (message.type === "status") {
        deliverStatus(message);
        return;
      }
      if (message.type === "status-request") {
        if (controller.isPrimary && lastStatus !== undefined) {
          postMessage({
            type: "status",
            to: message.from,
            payload: lastStatus,
          });
        }
        return;
      }
      if (message.type === "heartbeat") {
        resolveLeaseConflict(message);
        if (!controller.isPrimary) {
          notifySecondary("primary-heartbeat", message.from);
        }
        return;
      }
      if (message.type === "release" && primaryTabId === message.from) {
        notifySecondary("primary-released", null);
        windowObject.setTimeout(electionTick, 0);
      }
    }

    function onStorage(event) {
      if (released) {
        return;
      }
      if (event.key === SIGNAL_KEY && event.newValue) {
        handleMessage(parseJson(event.newValue));
        return;
      }
      if (event.key !== LEASE_KEY) {
        return;
      }
      const lease = parseJson(event.newValue);
      if (controller.isPrimary) {
        if (strategy !== "web-lock" && lease && lease.tabId !== tabId && lease.expiresAt > Date.now()) {
          stepDown("lease-replaced", lease.tabId);
        }
        return;
      }
      if (lease && lease.expiresAt > Date.now()) {
        notifySecondary("lease-observed", lease.tabId);
      }
    }

    function tryStorageLease() {
      if (released || controller.isPrimary || claimTimer) {
        return;
      }
      const now = Date.now();
      const current = readLease();
      if (current && current.expiresAt > now && current.tabId !== tabId) {
        notifySecondary("lease-held", current.tabId);
        return;
      }
      if (!writeLease()) {
        // Coordination cannot be guaranteed without either Web Locks or storage.
        notifySecondary("coordination-unavailable", null);
        return;
      }
      claimTimer = windowObject.setTimeout(function confirmLease() {
        claimTimer = null;
        if (released) {
          return;
        }
        const confirmed = readLease();
        if (confirmed && confirmed.tabId === tabId && confirmed.expiresAt > Date.now()) {
          becomePrimary("local-storage");
        } else {
          notifySecondary("lease-claim-lost", confirmed && confirmed.tabId);
        }
      }, CLAIM_SETTLE_MS + Math.floor(Math.random() * CLAIM_SETTLE_MS));
    }

    function activateStorageFallback(reason) {
      if (released || strategy === "local-storage") {
        return;
      }
      strategy = "local-storage";
      notifySecondary(reason || "using-storage-fallback", primaryTabId);
      tryStorageLease();
    }

    function tryWebLock() {
      if (released || controller.isPrimary || webLockAttemptPending || strategy !== "web-lock") {
        return;
      }
      const locks = windowObject.navigator && windowObject.navigator.locks;
      if (!locks || typeof locks.request !== "function") {
        activateStorageFallback("web-locks-unavailable");
        return;
      }

      webLockAttemptPending = true;
      let requestPromise;
      try {
        requestPromise = locks.request(
          LEASE_KEY,
          { mode: "exclusive", ifAvailable: true },
          function holdWebLock(lock) {
            webLockAttemptPending = false;
            if (released || strategy !== "web-lock" || !lock) {
              if (!lock && !released) {
                notifySecondary("web-lock-held", primaryTabId);
              }
              return undefined;
            }
            becomePrimary("web-lock");
            return new Promise(function holdUntilRelease(resolve) {
              webLockRelease = resolve;
            });
          },
        );
      } catch (_error) {
        webLockAttemptPending = false;
        activateStorageFallback("web-locks-error");
        return;
      }

      if (!requestPromise || typeof requestPromise.catch !== "function") {
        webLockAttemptPending = false;
        activateStorageFallback("web-locks-invalid");
        return;
      }
      requestPromise.catch(function webLockFailed() {
        webLockAttemptPending = false;
        if (!released) {
          activateStorageFallback("web-locks-error");
        }
      });
    }

    function electionTick() {
      if (released) {
        return;
      }
      if (controller.isPrimary) {
        if (strategy === "local-storage") {
          const lease = readLease();
          if (lease && lease.expiresAt > Date.now() && lease.tabId !== tabId) {
            stepDown("lease-lost", lease.tabId);
            return;
          }
        }
        writeLease();
        postMessage({
          type: "heartbeat",
          method: strategy,
          expiresAt: Date.now() + LEASE_TTL_MS,
        });
        return;
      }
      if (strategy === "web-lock") {
        tryWebLock();
      } else {
        tryStorageLease();
      }
    }

    function release() {
      if (released) {
        return;
      }
      const wasPrimary = controller.isPrimary;
      released = true;
      role = "secondary";
      if (monitorTimer) {
        windowObject.clearInterval(monitorTimer);
      }
      if (claimTimer) {
        windowObject.clearTimeout(claimTimer);
      }
      if (wasPrimary) {
        postMessage({ type: "release" });
      }
      removeOwnLease();
      if (webLockRelease) {
        const unlock = webLockRelease;
        webLockRelease = null;
        unlock();
      }
      if (channel) {
        channel.close();
        channel = null;
      }
      if (typeof windowObject.removeEventListener === "function") {
        windowObject.removeEventListener("storage", onStorage);
        windowObject.removeEventListener("beforeunload", release);
      }
      if (activeController === controller) {
        activeController = null;
      }
    }

    if (typeof windowObject.BroadcastChannel === "function") {
      try {
        channel = new windowObject.BroadcastChannel(CHANNEL_NAME);
        channel.onmessage = (event) => handleMessage(event.data);
      } catch (_error) {
        channel = null;
      }
    }
    if (typeof windowObject.addEventListener === "function") {
      windowObject.addEventListener("storage", onStorage);
      windowObject.addEventListener("beforeunload", release);
    }

    notifySecondary("election-pending", null);
    const locks = windowObject.navigator && windowObject.navigator.locks;
    if (locks && typeof locks.request === "function") {
      strategy = "web-lock";
      tryWebLock();
    } else {
      activateStorageFallback("web-locks-unavailable");
    }
    monitorTimer = windowObject.setInterval(electionTick, HEARTBEAT_MS);
    postMessage({ type: "status-request" });

    return controller;
  }

  windowObject.PhoenixSingleton = Object.freeze({ start });
})(window);
