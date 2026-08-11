import { randomUUID } from "node:crypto";

import { AppError, PurchaseVerificationError } from "./errors.js";
import { createLicenseToken } from "./license.js";
import { createPurchaseReceipt, verifyPurchaseReceipt } from "./receipt.js";
import { getTier, LICENSE_PERIOD_SECONDS, RECEIPT_LIFETIME_SECONDS } from "./tiers.js";

const PURCHASE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function assertMoney(money, amount, currency) {
  if (!money || money.amount !== amount || money.currency !== currency) {
    throw new PurchaseVerificationError();
  }
}

function assertOrder(config, receipt, order) {
  if (!order || typeof order !== "object") throw new PurchaseVerificationError();
  if (
    order.id !== receipt.order_id ||
    order.location_id !== config.squareLocationId ||
    order.reference_id !== receipt.purchase_id ||
    order.metadata?.phoenix_purchase_id !== receipt.purchase_id ||
    order.metadata?.phoenix_tier !== receipt.tier ||
    order.metadata?.phoenix_application_id !== config.squareApplicationId
  ) {
    throw new PurchaseVerificationError();
  }
  assertMoney(order.total_money, receipt.amount, receipt.currency);
}

function assertPayment(config, receipt, payment, expectedPaymentId) {
  if (!payment || typeof payment !== "object") throw new PurchaseVerificationError();
  if (
    payment.id !== expectedPaymentId ||
    payment.order_id !== receipt.order_id ||
    payment.location_id !== config.squareLocationId ||
    payment.application_details?.application_id !== config.squareApplicationId
  ) {
    throw new PurchaseVerificationError();
  }
  assertMoney(payment.amount_money, receipt.amount, receipt.currency);
  assertMoney(payment.total_money, receipt.amount, receipt.currency);
}

function completionWindow(payment, nowSeconds) {
  const paidAtRaw = payment.completed_at || payment.created_at;
  const paidAt = Math.floor(Date.parse(paidAtRaw) / 1000);
  if (!Number.isFinite(paidAt) || paidAt > nowSeconds + 300) {
    throw new PurchaseVerificationError();
  }
  return {
    paidAt,
    expiresAt: paidAt + LICENSE_PERIOD_SECONDS,
  };
}

function safePurchaseId(candidate) {
  if (candidate === undefined || candidate === null || candidate === "") return randomUUID();
  if (typeof candidate !== "string" || !PURCHASE_ID_PATTERN.test(candidate)) {
    throw new AppError("invalid_purchase_id", "purchase_id must be a UUID", 400);
  }
  return candidate.toLowerCase();
}

export async function beginCheckout({
  config,
  squareClient,
  tierId,
  purchaseId: requestedPurchaseId,
  returnUrl = "",
  nowSeconds = Math.floor(Date.now() / 1000),
}) {
  const tier = getTier(tierId);
  if (!tier) throw new AppError("invalid_tier", "Unknown paid tier", 400);
  const purchaseId = safePurchaseId(requestedPurchaseId);
  const response = await squareClient.createPaymentLink({ tier, purchaseId, returnUrl });
  const paymentLink = response?.payment_link;
  if (
    !paymentLink ||
    typeof paymentLink.order_id !== "string" ||
    typeof paymentLink.url !== "string"
  ) {
    throw new PurchaseVerificationError();
  }
  let checkoutUrl;
  try {
    checkoutUrl = new URL(paymentLink.url);
  } catch {
    throw new PurchaseVerificationError();
  }
  if (checkoutUrl.protocol !== "https:") throw new PurchaseVerificationError();
  const purchaseReceipt = createPurchaseReceipt(
    config,
    { purchaseId, orderId: paymentLink.order_id, tier: tier.id },
    nowSeconds,
  );
  return {
    checkout_url: checkoutUrl.toString(),
    purchase_receipt: purchaseReceipt,
    purchase_id: purchaseId,
    tier: tier.id,
    amount: tier.amount,
    currency: tier.currency,
    receipt_expires_at: new Date((nowSeconds + RECEIPT_LIFETIME_SECONDS) * 1000).toISOString(),
  };
}

export async function verifyPurchase({
  config,
  squareClient,
  purchaseReceipt,
  nowSeconds = Math.floor(Date.now() / 1000),
}) {
  const receipt = verifyPurchaseReceipt(config, purchaseReceipt, nowSeconds);
  const orderResponse = await squareClient.retrieveOrder(receipt.order_id);
  const order = orderResponse?.order;
  assertOrder(config, receipt, order);

  if (order.state === "CANCELED") {
    return { state: "cancelled", receipt };
  }

  const paymentIds = [
    ...new Set(
      (Array.isArray(order.tenders) ? order.tenders : [])
        .map((tender) => tender?.payment_id)
        .filter((value) => typeof value === "string" && value.length > 0),
    ),
  ];
  if (paymentIds.length === 0) {
    return { state: "pending", receipt };
  }
  if (paymentIds.length !== 1) throw new PurchaseVerificationError();

  const tender = order.tenders.find((candidate) => candidate?.payment_id === paymentIds[0]);
  assertMoney(tender?.amount_money, receipt.amount, receipt.currency);
  const paymentResponse = await squareClient.getPayment(paymentIds[0]);
  const payment = paymentResponse?.payment;
  assertPayment(config, receipt, payment, paymentIds[0]);

  if (payment.status === "CANCELED" || payment.status === "FAILED") {
    return { state: "failed", receipt };
  }
  if (payment.status !== "COMPLETED" || order.state !== "COMPLETED") {
    return { state: "pending", receipt };
  }
  const refundedAmount = payment.refunded_money?.amount || 0;
  if (!Number.isSafeInteger(refundedAmount) || refundedAmount !== 0) {
    return { state: "refunded", receipt };
  }
  const { paidAt, expiresAt } = completionWindow(payment, nowSeconds);
  return {
    state: expiresAt > nowSeconds ? "active" : "expired",
    receipt,
    order,
    payment,
    paidAt,
    expiresAt,
  };
}

export function publicPurchaseStatus(verified) {
  const result = {
    state: verified.state,
    paid: verified.state === "active" || verified.state === "expired",
    active: verified.state === "active",
    tier: verified.receipt.tier,
  };
  if (Number.isSafeInteger(verified.paidAt)) {
    result.paid_at = new Date(verified.paidAt * 1000).toISOString();
    result.expires_at = new Date(verified.expiresAt * 1000).toISOString();
  }
  return result;
}

export function claimVerifiedPurchase(config, verified, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (verified.state !== "active") {
    throw new PurchaseVerificationError(
      verified.state === "expired" ? "Subscription has expired" : "Payment is not complete",
    );
  }
  const license = createLicenseToken(config, verified, nowSeconds);
  return {
    license_token: license.token,
    tier: verified.receipt.tier,
    issued_at: new Date(license.payload.iat * 1000).toISOString(),
    expires_at: new Date(license.payload.exp * 1000).toISOString(),
    license_key_id: license.keyId,
  };
}
