import { rejectMethod, sendJson } from "../lib/http.js";

export default async function handler(req, res) {
  if (req.method !== "GET") {
    rejectMethod(res, ["GET"]);
    return;
  }
  sendJson(res, 200, {
    ok: true,
    service: "phoenix-square-billing-gateway",
    version: "1.0.0",
  });
}
