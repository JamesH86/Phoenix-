import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadConfig } from "../lib/config.js";
import { ReceiptError, PurchaseVerificationError } from "../lib/errors.js";
import { verifyLicenseToken } from "../lib/license.js";
import {
  beginCheckout,
  claimVerifiedPurchase,
  publicPurchaseStatus,
  verifyPurchase,
} from "../lib/purchase-service.js";
import { createPurchaseReceipt, verifyPurchaseReceipt } from "../lib/receipt.js";
import { SquareClient } from "../lib/square-client.js";
import { LICENSE_PERIOD_SECONDS, TIERS } from "../lib/tiers.js";
import {
  computeSquareWebhookSignature,
  verifySquareWebhookSignature,
} from "../lib/webhook.js";
import { configureSandboxWebhook } from "../scripts/configure-square-sandbox-webhook.js";

const { privateKey } = generateKeyPairSync("ed25519");
const privateKeyB64 = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
const receiptSecretB64 = randomBytes(32).toString("base64");
const fixedNow = Math.floor(Date.parse("2026-08-09T16:00:00.000Z") / 1000);

function testEnv(overrides = {}) {
  return {
    SQUARE_ENVIRONMENT: "sandbox",
    SQUARE_ACCESS_TOKEN: "sandbox-access-token-placeholder",
    SQUARE_APPLICATION_ID: "sandbox-app-placeholder",
    SQUARE_LOCATION_ID: "sandbox-location-placeholder",
    SQUARE_API_VERSION: "2026-07-15",
    SQUARE_WEBHOOK_NOTIFICATION_URL: "https://billing.example/api/square-webhook",
    SQUARE_WEBHOOK_SIGNATURE_KEY: "sandbox-webhook-signature-placeholder",
    PHOENIX_PURCHASE_RECEIPT_SECRET_B64: receiptSecretB64,
    PHOENIX_LICENSE_ED25519_PRIVATE_KEY_B64: privateKeyB64,
    PHOENIX_LICENSE_KEY_ID: "test-key-1",
    PHOENIX_LICENSE_ISSUER: "https://billing.example",
    PHOENIX_ALLOWED_ORIGINS: "https://app.example,http://127.0.0.1:8787",
    PHOENIX_DEFAULT_RETURN_URL: "https://app.example/plans",
    ...overrides,
  };
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function completedFixtures(config, receipt, overrides = {}) {
  const paymentId = "payment-123456";
  const money = { amount: receipt.amount, currency: receipt.currency };
  const order = {
    id: receipt.order_id,
    location_id: config.squareLocationId,
    reference_id: receipt.purchase_id,
    metadata: {
      phoenix_purchase_id: receipt.purchase_id,
      phoenix_tier: receipt.tier,
      phoenix_application_id: config.squareApplicationId,
    },
    total_money: money,
    state: "COMPLETED",
    tenders: [{ payment_id: paymentId, amount_money: money }],
    ...overrides.order,
  };
  const payment = {
    id: paymentId,
    order_id: receipt.order_id,
    location_id: config.squareLocationId,
    application_details: { application_id: config.squareApplicationId },
    amount_money: money,
    total_money: money,
    refunded_money: { amount: 0, currency: receipt.currency },
    status: "COMPLETED",
    created_at: "2026-08-09T15:55:00.000Z",
    updated_at: "2026-08-09T15:55:01.000Z",
    ...overrides.payment,
  };
  return { order, payment };
}

function clientForFixtures(config, fixtures, calls = []) {
  return new SquareClient(config, async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith(`/orders/${fixtures.order.id}`)) return jsonResponse({ order: fixtures.order });
    if (url.endsWith(`/payments/${fixtures.payment.id}`)) return jsonResponse({ payment: fixtures.payment });
    return jsonResponse({ errors: [{ code: "NOT_FOUND" }] }, 404);
  });
}

test("fixed paid tiers cannot drift", () => {
  assert.deepEqual(
    Object.fromEntries(Object.values(TIERS).map((tier) => [tier.id, tier.amount])),
    { solo: 5000, base: 15000, enterprise: 100000, government: 150000 },
  );
  assert.ok(Object.values(TIERS).every((tier) => tier.currency === "USD" && tier.license_days === 30));
});

test("production configuration fails closed without webhook verification", () => {
  const config = loadConfig(
    testEnv({
      SQUARE_ENVIRONMENT: "production",
      SQUARE_WEBHOOK_NOTIFICATION_URL: "",
      SQUARE_WEBHOOK_SIGNATURE_KEY: "",
    }),
  );
  assert.equal(config.coreReady, true);
  assert.equal(config.webhookReady, false);
  assert.equal(config.serviceReady, false);
  assert.ok(config.issues.includes("SQUARE_WEBHOOK_NOTIFICATION_URL"));
  assert.ok(config.issues.includes("SQUARE_WEBHOOK_SIGNATURE_KEY"));
});

test("purchase receipt is signed, configuration-bound, and expires", () => {
  const config = loadConfig(testEnv());
  const token = createPurchaseReceipt(
    config,
    {
      purchaseId: "123e4567-e89b-42d3-a456-426614174000",
      orderId: "order-123456",
      tier: "solo",
    },
    fixedNow,
  );
  assert.equal(verifyPurchaseReceipt(config, token, fixedNow).tier, "solo");
  assert.throws(() => verifyPurchaseReceipt(config, `${token}x`, fixedNow), ReceiptError);
  assert.throws(
    () => verifyPurchaseReceipt(config, token, fixedNow + 46 * 24 * 60 * 60),
    ReceiptError,
  );
  const otherLocation = loadConfig(testEnv({ SQUARE_LOCATION_ID: "other-location-placeholder" }));
  assert.throws(() => verifyPurchaseReceipt(otherLocation, token, fixedNow), ReceiptError);
});

test("checkout sends one fixed-price Square order and returns no Square credential", async () => {
  const config = loadConfig(testEnv());
  const calls = [];
  const squareClient = new SquareClient(config, async (url, options) => {
    calls.push({ url, options });
    return jsonResponse({
      payment_link: {
        order_id: "order-123456",
        url: "https://square.link/u/example",
      },
    });
  });
  const result = await beginCheckout({
    config,
    squareClient,
    tierId: "base",
    purchaseId: "123e4567-e89b-42d3-a456-426614174000",
    returnUrl: "https://app.example/plans",
    nowSeconds: fixedNow,
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${config.squareBaseUrl}/online-checkout/payment-links`);
  const request = JSON.parse(calls[0].options.body);
  assert.equal(request.order.line_items.length, 1);
  assert.deepEqual(request.order.line_items[0].base_price_money, { amount: 15000, currency: "USD" });
  assert.equal(request.checkout_options.allow_tipping, false);
  assert.equal(request.checkout_options.redirect_url, "https://app.example/plans");
  assert.equal(result.tier, "base");
  assert.equal(Object.hasOwn(result, "access_token"), false);
  assert.equal(verifyPurchaseReceipt(config, result.purchase_receipt, fixedNow).order_id, "order-123456");
});

test("pending order does not call GetPayment or issue access", async () => {
  const config = loadConfig(testEnv());
  const purchaseReceipt = createPurchaseReceipt(
    config,
    {
      purchaseId: "123e4567-e89b-42d3-a456-426614174000",
      orderId: "order-123456",
      tier: "solo",
    },
    fixedNow,
  );
  const receipt = verifyPurchaseReceipt(config, purchaseReceipt, fixedNow);
  const fixtures = completedFixtures(config, receipt, {
    order: { state: "OPEN", tenders: [] },
  });
  const calls = [];
  const verified = await verifyPurchase({
    config,
    squareClient: clientForFixtures(config, fixtures, calls),
    purchaseReceipt,
    nowSeconds: fixedNow,
  });
  assert.equal(verified.state, "pending");
  assert.equal(calls.length, 1);
  assert.deepEqual(publicPurchaseStatus(verified), {
    state: "pending",
    paid: false,
    active: false,
    tier: "solo",
  });
});

test("completed purchase checks RetrieveOrder then GetPayment and signs exactly 30 days", async () => {
  const config = loadConfig(testEnv());
  const purchaseReceipt = createPurchaseReceipt(
    config,
    {
      purchaseId: "123e4567-e89b-42d3-a456-426614174000",
      orderId: "order-123456",
      tier: "enterprise",
    },
    fixedNow,
  );
  const receipt = verifyPurchaseReceipt(config, purchaseReceipt, fixedNow);
  const fixtures = completedFixtures(config, receipt);
  const calls = [];
  const verified = await verifyPurchase({
    config,
    squareClient: clientForFixtures(config, fixtures, calls),
    purchaseReceipt,
    nowSeconds: fixedNow,
  });
  assert.equal(verified.state, "active");
  assert.match(calls[0].url, /\/orders\//u);
  assert.match(calls[1].url, /\/payments\//u);
  const firstClaim = claimVerifiedPurchase(config, verified, fixedNow);
  const secondClaim = claimVerifiedPurchase(config, verified, fixedNow);
  assert.equal(firstClaim.license_token, secondClaim.license_token);
  const decoded = verifyLicenseToken(config.licensePublicKey, firstClaim.license_token);
  assert.ok(decoded);
  assert.equal(decoded.payload.tier, "enterprise");
  assert.equal(decoded.payload.exp - decoded.payload.iat, LICENSE_PERIOD_SECONDS);
  assert.equal(decoded.payload.iat, Math.floor(Date.parse(fixtures.payment.created_at) / 1000));
  assert.equal(JSON.stringify(decoded.payload).includes(fixtures.payment.id), false);
});

test("mismatched application, amount, or refunded payment cannot issue a license", async (t) => {
  const config = loadConfig(testEnv());
  const purchaseReceipt = createPurchaseReceipt(
    config,
    {
      purchaseId: "123e4567-e89b-42d3-a456-426614174000",
      orderId: "order-123456",
      tier: "government",
    },
    fixedNow,
  );
  const receipt = verifyPurchaseReceipt(config, purchaseReceipt, fixedNow);

  await t.test("application mismatch", async () => {
    const fixtures = completedFixtures(config, receipt, {
      payment: { application_details: { application_id: "different-app" } },
    });
    await assert.rejects(
      verifyPurchase({
        config,
        squareClient: clientForFixtures(config, fixtures),
        purchaseReceipt,
        nowSeconds: fixedNow,
      }),
      PurchaseVerificationError,
    );
  });

  await t.test("amount mismatch", async () => {
    const fixtures = completedFixtures(config, receipt, {
      payment: { total_money: { amount: receipt.amount - 1, currency: "USD" } },
    });
    await assert.rejects(
      verifyPurchase({
        config,
        squareClient: clientForFixtures(config, fixtures),
        purchaseReceipt,
        nowSeconds: fixedNow,
      }),
      PurchaseVerificationError,
    );
  });

  await t.test("refund is revoked", async () => {
    const fixtures = completedFixtures(config, receipt, {
      payment: { refunded_money: { amount: 1, currency: "USD" } },
    });
    const verified = await verifyPurchase({
      config,
      squareClient: clientForFixtures(config, fixtures),
      purchaseReceipt,
      nowSeconds: fixedNow,
    });
    assert.equal(verified.state, "refunded");
    assert.throws(() => claimVerifiedPurchase(config, verified, fixedNow), PurchaseVerificationError);
  });
});

test("webhook HMAC uses the exact URL and raw bytes and is replay-safe", () => {
  const config = loadConfig(testEnv());
  const rawBody = Buffer.from('{"type":"payment.updated","data":{"object":{"payment":{"status":"COMPLETED"}}}}');
  const signature = computeSquareWebhookSignature(
    rawBody,
    config.webhookNotificationUrl,
    config.webhookSignatureKey,
  );
  assert.equal(verifySquareWebhookSignature(rawBody, signature, config), true);
  assert.equal(verifySquareWebhookSignature(rawBody, signature, config), true);
  assert.equal(verifySquareWebhookSignature(Buffer.concat([rawBody, Buffer.from(" ")]), signature, config), false);
  assert.equal(
    verifySquareWebhookSignature(
      rawBody,
      signature,
      { ...config, webhookNotificationUrl: "https://billing.example/api/other" },
    ),
    false,
  );
});

async function temporarySandboxCredentials(t) {
  const directory = await mkdtemp(join(tmpdir(), "phoenix-square-webhook-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const credentialsFile = join(directory, "credentials.json");
  await writeFile(
    credentialsFile,
    JSON.stringify({
      environment: "sandbox",
      access_token: "private-test-token",
      application_id: "sandbox-test-application",
      location_id: "sandbox-test-location",
      api_version: "2026-07-15",
    }),
    { mode: 0o600 },
  );
  return credentialsFile;
}

test("Sandbox webhook helper defaults to local validation with zero Square calls", async (t) => {
  const credentialsFile = await temporarySandboxCredentials(t);
  let fetchCalls = 0;
  const result = await configureSandboxWebhook({
    credentialsFile,
    notificationUrl: "https://billing.example/api/square-webhook",
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(result.applied, false);
  assert.equal(fetchCalls, 0);
  const stored = JSON.parse(await readFile(credentialsFile, "utf8"));
  assert.equal(Object.hasOwn(stored, "webhook_signature_key"), false);
});

test("Sandbox webhook helper requires exact confirmation and stores secrets owner-only", async (t) => {
  const credentialsFile = await temporarySandboxCredentials(t);
  const notificationUrl = "https://billing.example/api/square-webhook";
  let fetchCalls = 0;
  await assert.rejects(
    configureSandboxWebhook({
      credentialsFile,
      notificationUrl,
      confirmedUrl: "https://different.example/api/square-webhook",
      apply: true,
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error("must not run");
      },
    }),
    /exactly repeat/u,
  );
  assert.equal(fetchCalls, 0);

  const calls = [];
  const result = await configureSandboxWebhook({
    credentialsFile,
    notificationUrl,
    confirmedUrl: notificationUrl,
    apply: true,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (options.method === "GET") return jsonResponse({ subscriptions: [] });
      return jsonResponse({
        subscription: {
          id: "wbhk_test_subscription",
          enabled: true,
          notification_url: notificationUrl,
          event_types: ["payment.created", "payment.updated"],
          signature_key: "private-test-signature-key",
        },
      });
    },
  });
  assert.equal(result.created, true);
  assert.equal(calls.length, 2);
  const createBody = JSON.parse(calls[1].options.body);
  assert.deepEqual(createBody.subscription.event_types, ["payment.created", "payment.updated"]);
  assert.equal(createBody.subscription.notification_url, notificationUrl);
  const stored = JSON.parse(await readFile(credentialsFile, "utf8"));
  assert.equal(stored.webhook_signature_key, "private-test-signature-key");
  assert.equal(stored.webhook_subscription_id, "wbhk_test_subscription");
  assert.equal((await stat(credentialsFile)).mode & 0o777, 0o600);
});
