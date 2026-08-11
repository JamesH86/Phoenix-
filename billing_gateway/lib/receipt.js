import { createHmac } from "node:crypto";

import { base64UrlDecode, base64UrlEncode, constantTimeEqual } from "./encoding.js";
import { ReceiptError } from "./errors.js";
import { getTier, RECEIPT_LIFETIME_SECONDS } from "./tiers.js";

const RECEIPT_PREFIX = "phxp1";

function receiptMac(secret, payloadSegment) {
  return createHmac("sha256", secret)
    .update(`${RECEIPT_PREFIX}.${payloadSegment}`, "utf8")
    .digest();
}

function isSafeIdentifier(value, maxLength = 192) {
  return (
    typeof value === "string" &&
    value.length >= 8 &&
    value.length <= maxLength &&
    /^[A-Za-z0-9._:-]+$/u.test(value)
  );
}

function assertReceiptShape(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new ReceiptError();
  if (payload.v !== 1 || payload.type !== "phoenix_purchase") throw new ReceiptError();
  if (!isSafeIdentifier(payload.purchase_id, 80)) throw new ReceiptError();
  if (!isSafeIdentifier(payload.order_id)) throw new ReceiptError();
  if (!getTier(payload.tier)) throw new ReceiptError();
  if (!Number.isSafeInteger(payload.amount) || payload.amount <= 0) throw new ReceiptError();
  if (typeof payload.currency !== "string" || payload.currency.length !== 3) throw new ReceiptError();
  if (!isSafeIdentifier(payload.location_id)) throw new ReceiptError();
  if (!isSafeIdentifier(payload.application_id)) throw new ReceiptError();
  if (payload.square_environment !== "sandbox" && payload.square_environment !== "production") {
    throw new ReceiptError();
  }
  if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)) throw new ReceiptError();
  if (payload.exp <= payload.iat || payload.exp - payload.iat !== RECEIPT_LIFETIME_SECONDS) {
    throw new ReceiptError();
  }
}

export function createPurchaseReceipt(config, purchase, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!config.receiptSecret) throw new ReceiptError();
  const tier = getTier(purchase.tier);
  if (!tier) throw new ReceiptError();
  const payload = {
    v: 1,
    type: "phoenix_purchase",
    purchase_id: purchase.purchaseId,
    order_id: purchase.orderId,
    tier: tier.id,
    amount: tier.amount,
    currency: tier.currency,
    location_id: config.squareLocationId,
    application_id: config.squareApplicationId,
    square_environment: config.squareEnvironment,
    iat: nowSeconds,
    exp: nowSeconds + RECEIPT_LIFETIME_SECONDS,
  };
  assertReceiptShape(payload);
  const payloadSegment = base64UrlEncode(JSON.stringify(payload));
  const signatureSegment = base64UrlEncode(receiptMac(config.receiptSecret, payloadSegment));
  return `${RECEIPT_PREFIX}.${payloadSegment}.${signatureSegment}`;
}

export function verifyPurchaseReceipt(config, token, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!config.receiptSecret || typeof token !== "string" || token.length > 4096) {
    throw new ReceiptError();
  }
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== RECEIPT_PREFIX) throw new ReceiptError();
  let suppliedSignature;
  let payload;
  try {
    suppliedSignature = base64UrlDecode(parts[2]);
    const expectedSignature = receiptMac(config.receiptSecret, parts[1]);
    if (!constantTimeEqual(suppliedSignature, expectedSignature)) throw new ReceiptError();
    payload = JSON.parse(base64UrlDecode(parts[1]).toString("utf8"));
  } catch (error) {
    if (error instanceof ReceiptError) throw error;
    throw new ReceiptError();
  }
  assertReceiptShape(payload);
  const tier = getTier(payload.tier);
  if (
    payload.amount !== tier.amount ||
    payload.currency !== tier.currency ||
    payload.location_id !== config.squareLocationId ||
    payload.application_id !== config.squareApplicationId ||
    payload.square_environment !== config.squareEnvironment
  ) {
    throw new ReceiptError();
  }
  if (payload.iat > nowSeconds + 300 || payload.exp < nowSeconds - 60) throw new ReceiptError();
  return Object.freeze(payload);
}
