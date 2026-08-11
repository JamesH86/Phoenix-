import { requireServiceConfig, resolveReturnUrl } from "../lib/config.js";
import { AppError } from "../lib/errors.js";
import {
  applyCors,
  handleOptions,
  readJsonBody,
  rejectMethod,
  requestHeader,
  sendError,
  sendJson,
} from "../lib/http.js";
import { beginCheckout } from "../lib/purchase-service.js";
import { SquareClient } from "../lib/square-client.js";

export default async function handler(req, res) {
  let gatewayConfig;
  try {
    gatewayConfig = requireServiceConfig();
    if (req.method === "OPTIONS") {
      handleOptions(req, res, gatewayConfig);
      return;
    }
    if (req.method !== "POST") {
      rejectMethod(res, ["POST", "OPTIONS"]);
      return;
    }
    if (!applyCors(req, res, gatewayConfig)) {
      sendJson(res, 403, { error: "origin_not_allowed" });
      return;
    }
    const body = await readJsonBody(req);
    const returnUrl = resolveReturnUrl(
      gatewayConfig,
      body.return_url,
      requestHeader(req, "origin"),
    );
    if (returnUrl === null) throw new AppError("invalid_return_url", "Invalid return URL", 400);
    const checkout = await beginCheckout({
      config: gatewayConfig,
      squareClient: new SquareClient(gatewayConfig),
      tierId: body.tier,
      purchaseId: body.purchase_id,
      returnUrl,
    });
    sendJson(res, 201, checkout);
  } catch (error) {
    sendError(res, error);
  }
}
