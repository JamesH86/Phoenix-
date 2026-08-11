import { createHmac } from "node:crypto";

import { constantTimeEqual, decodeBase64 } from "./encoding.js";

export function computeSquareWebhookSignature(rawBody, notificationUrl, signatureKey) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody);
  return createHmac("sha256", signatureKey)
    .update(Buffer.from(notificationUrl, "utf8"))
    .update(body)
    .digest("base64");
}

export function verifySquareWebhookSignature(rawBody, signatureHeader, config) {
  if (
    !Buffer.isBuffer(rawBody) ||
    typeof signatureHeader !== "string" ||
    !config.webhookNotificationUrl ||
    !config.webhookSignatureKey
  ) {
    return false;
  }
  try {
    const supplied = decodeBase64(signatureHeader);
    const expected = Buffer.from(
      computeSquareWebhookSignature(
        rawBody,
        config.webhookNotificationUrl,
        config.webhookSignatureKey,
      ),
      "base64",
    );
    return constantTimeEqual(supplied, expected);
  } catch {
    return false;
  }
}

export function classifySquareWebhook(rawBody) {
  try {
    const event = JSON.parse(rawBody.toString("utf8"));
    const payment = event?.data?.object?.payment;
    if (
      (event?.type === "payment.created" || event?.type === "payment.updated") &&
      payment?.status === "COMPLETED"
    ) {
      return "completed_payment";
    }
    return "ignored";
  } catch {
    return "ignored";
  }
}
