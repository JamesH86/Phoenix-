import { requireServiceConfig } from "../lib/config.js";
import { AppError, ConfigurationError } from "../lib/errors.js";
import { classifySquareWebhook, verifySquareWebhookSignature } from "../lib/webhook.js";

const MAX_WEBHOOK_BYTES = 256 * 1024;

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Cache-Control": "no-store, max-age=0",
      "Content-Type": "application/json; charset=utf-8",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
    },
  });
}

export async function POST(request) {
  try {
    const gatewayConfig = requireServiceConfig();
    if (!gatewayConfig.webhookReady) throw new ConfigurationError();
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (Number.isFinite(contentLength) && contentLength > MAX_WEBHOOK_BYTES) {
      return json(413, { accepted: false });
    }
    const rawBody = Buffer.from(await request.arrayBuffer());
    if (rawBody.length > MAX_WEBHOOK_BYTES) return json(413, { accepted: false });
    const signature = request.headers.get("x-square-hmacsha256-signature") || "";
    if (!verifySquareWebhookSignature(rawBody, signature, gatewayConfig)) {
      return json(403, { accepted: false });
    }

    // No storage or fulfillment side effect: valid duplicate, replayed,
    // unrelated, and out-of-order deliveries are safe and idempotent.
    return json(200, {
      accepted: true,
      result: classifySquareWebhook(rawBody),
    });
  } catch (error) {
    if (error instanceof AppError) return json(error.status, { error: error.code });
    return json(500, { error: "internal_error" });
  }
}
