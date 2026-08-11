import { requireServiceConfig } from "../lib/config.js";
import {
  applyCors,
  handleOptions,
  readJsonBody,
  rejectMethod,
  sendError,
  sendJson,
} from "../lib/http.js";
import { publicPurchaseStatus, verifyPurchase } from "../lib/purchase-service.js";
import { SquareClient } from "../lib/square-client.js";

export default async function handler(req, res) {
  try {
    const gatewayConfig = requireServiceConfig();
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
    const verified = await verifyPurchase({
      config: gatewayConfig,
      squareClient: new SquareClient(gatewayConfig),
      purchaseReceipt: body.purchase_receipt,
    });
    sendJson(res, 200, publicPurchaseStatus(verified));
  } catch (error) {
    sendError(res, error);
  }
}
