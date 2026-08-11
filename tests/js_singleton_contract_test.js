const assert = require("node:assert/strict");
const path = require("node:path");

const values = new Map();
const listeners = new Map();

global.window = global;
Object.defineProperty(global, "navigator", {
  configurable: true,
  value: {},
});
global.crypto = {
  randomUUID: () => "contract-test-tab",
};
global.localStorage = {
  getItem(key) {
    return values.has(key) ? values.get(key) : null;
  },
  setItem(key, value) {
    values.set(key, String(value));
  },
  removeItem(key) {
    values.delete(key);
  },
};
global.addEventListener = (name, callback) => listeners.set(name, callback);
global.removeEventListener = (name) => listeners.delete(name);

require(path.join(__dirname, "..", "web_ui", "singleton.js"));

assert.equal(typeof window.PhoenixSingleton, "object");
assert.equal(typeof window.PhoenixSingleton.start, "function");

let primaryCalls = 0;
let secondaryCalls = 0;
const controller = window.PhoenixSingleton.start({
  onPrimary() {
    primaryCalls += 1;
  },
  onSecondary() {
    secondaryCalls += 1;
  },
});

assert.equal(typeof controller.release, "function");
assert.equal(typeof controller.publishStatus, "function");
assert.equal(controller.isPrimary, false);

setTimeout(() => {
  assert.equal(controller.isPrimary, true);
  assert.equal(primaryCalls, 1);
  assert.ok(secondaryCalls >= 1);
  assert.equal(controller.publishStatus({ phase: "ready" }), true);
  controller.release();
  assert.equal(controller.isPrimary, false);
  assert.equal(values.has("phoenix-guardian-primary"), false);

  let webLockCallbackCompleted = false;
  global.navigator.locks = {
    request(_name, _options, callback) {
      const heldLock = callback({ name: "phoenix-guardian-primary" });
      Promise.resolve(heldLock).then(() => {
        webLockCallbackCompleted = true;
      });
      return Promise.resolve(heldLock);
    },
  };
  const webLockController = window.PhoenixSingleton.start({});
  assert.equal(webLockController.isPrimary, true);
  assert.equal(webLockCallbackCompleted, false);
  webLockController.release();

  setTimeout(() => {
    assert.equal(webLockCallbackCompleted, true);
    console.log("Phoenix singleton contract passed");
  }, 0);
}, 180);
