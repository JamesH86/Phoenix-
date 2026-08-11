import { loadConfig, publicConfigStatus } from "../lib/config.js";
import { applyCors, handleOptions, rejectMethod, sendJson } from "../lib/http.js";
import { publicTierCatalog } from "../lib/tiers.js";

export default async function handler(req, res) {
  const gatewayConfig = loadConfig();
  if (req.method === "OPTIONS") {
    handleOptions(req, res, gatewayConfig);
    return;
  }
  if (req.method !== "GET") {
    rejectMethod(res, ["GET", "OPTIONS"]);
    return;
  }
  if (!applyCors(req, res, gatewayConfig)) {
    sendJson(res, 403, { error: "origin_not_allowed" });
    return;
  }
  sendJson(res, 200, {
    ok: true,
    service: "phoenix-square-billing-gateway",
    ...publicConfigStatus(gatewayConfig),
    tiers: publicTierCatalog(),
    license_period_days: 30,
    persistence: "stateless",
  });
}
