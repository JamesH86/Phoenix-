import { SquareApiError } from "./errors.js";

const MAX_SQUARE_RESPONSE_BYTES = 1024 * 1024;

async function parseSquareResponse(response) {
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAX_SQUARE_RESPONSE_BYTES) {
    throw new SquareApiError(response.status, "RESPONSE_TOO_LARGE");
  }
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new SquareApiError(response.status, "INVALID_RESPONSE");
  }
}

export class SquareClient {
  constructor(config, fetchImpl = globalThis.fetch) {
    if (typeof fetchImpl !== "function") throw new TypeError("fetch implementation is required");
    this.config = config;
    this.fetchImpl = fetchImpl;
  }

  async request(method, path, body) {
    let response;
    try {
      response = await this.fetchImpl(`${this.config.squareBaseUrl}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${this.config.squareAccessToken}`,
          "Content-Type": "application/json",
          "Square-Version": this.config.squareApiVersion,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "error",
        signal: typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(8_000) : undefined,
      });
    } catch {
      throw new SquareApiError(0, "NETWORK_ERROR");
    }
    const payload = await parseSquareResponse(response);
    if (!response.ok) {
      const squareCode = Array.isArray(payload.errors) && payload.errors[0]?.code
        ? String(payload.errors[0].code)
        : "UPSTREAM_ERROR";
      throw new SquareApiError(response.status, squareCode);
    }
    return payload;
  }

  createPaymentLink({ tier, purchaseId, returnUrl = "" }) {
    const checkoutOptions = { allow_tipping: false };
    if (returnUrl) checkoutOptions.redirect_url = returnUrl;
    return this.request("POST", "/online-checkout/payment-links", {
      idempotency_key: `phoenix-${purchaseId}`,
      description: `Phoenix Guardian ${tier.name} - 30 days`,
      order: {
        location_id: this.config.squareLocationId,
        reference_id: purchaseId,
        metadata: {
          phoenix_purchase_id: purchaseId,
          phoenix_tier: tier.id,
          phoenix_application_id: this.config.squareApplicationId,
        },
        line_items: [
          {
            name: `Phoenix Guardian ${tier.name} - 30 days`,
            quantity: "1",
            item_type: "ITEM",
            base_price_money: {
              amount: tier.amount,
              currency: tier.currency,
            },
          },
        ],
      },
      checkout_options: checkoutOptions,
      payment_note: `Phoenix Guardian ${tier.id} purchase ${purchaseId}`,
    });
  }

  retrieveOrder(orderId) {
    return this.request("GET", `/orders/${encodeURIComponent(orderId)}`);
  }

  getPayment(paymentId) {
    return this.request("GET", `/payments/${encodeURIComponent(paymentId)}`);
  }
}
