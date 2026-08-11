import { AppError } from "./errors.js";

const MAX_JSON_BODY_BYTES = 64 * 1024;

export function requestHeader(req, name) {
  const value = req.headers?.[name.toLowerCase()];
  if (Array.isArray(value)) return value.length === 1 ? value[0] : "";
  return typeof value === "string" ? value : "";
}

function requestOrigin(req) {
  return requestHeader(req, "origin");
}

function sameOrigin(req, origin) {
  const host = requestHeader(req, "x-forwarded-host") || requestHeader(req, "host");
  const protocol = requestHeader(req, "x-forwarded-proto") || "https";
  return Boolean(host && origin === `${protocol}://${host}`);
}

export function applyCors(req, res, config) {
  const origin = requestOrigin(req);
  if (!origin) return true;
  if (!config.allowedOrigins.has(origin) && !sameOrigin(req, origin)) return false;
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Vary", "Origin");
  return true;
}

export function setCommonHeaders(res) {
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
}

export function sendJson(res, status, body) {
  setCommonHeaders(res);
  res.statusCode = status;
  res.end(JSON.stringify(body));
}

export function sendError(res, error) {
  if (error instanceof AppError) {
    sendJson(res, error.status, { error: error.code });
    return;
  }
  sendJson(res, 500, { error: "internal_error" });
}

export function rejectMethod(res, allow) {
  res.setHeader("Allow", allow.join(", "));
  sendJson(res, 405, { error: "method_not_allowed" });
}

export function handleOptions(req, res, config) {
  if (!applyCors(req, res, config)) {
    sendJson(res, 403, { error: "origin_not_allowed" });
    return;
  }
  res.statusCode = 204;
  res.setHeader("Cache-Control", "no-store");
  res.end();
}

export async function readRawBody(req, maxBytes = MAX_JSON_BODY_BYTES) {
  if (Buffer.isBuffer(req.rawBody)) {
    if (req.rawBody.length > maxBytes) throw new AppError("body_too_large", "Body too large", 413);
    return req.rawBody;
  }
  if (Buffer.isBuffer(req.body)) {
    if (req.body.length > maxBytes) throw new AppError("body_too_large", "Body too large", 413);
    return req.body;
  }
  if (typeof req.body === "string") {
    const body = Buffer.from(req.body, "utf8");
    if (body.length > maxBytes) throw new AppError("body_too_large", "Body too large", 413);
    return body;
  }
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += buffer.length;
    if (length > maxBytes) throw new AppError("body_too_large", "Body too large", 413);
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

export async function readJsonBody(req) {
  if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) {
    return req.body;
  }
  const raw = await readRawBody(req);
  if (raw.length === 0) return {};
  try {
    const value = JSON.parse(raw.toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError();
    return value;
  } catch {
    throw new AppError("invalid_json", "Expected a JSON object", 400);
  }
}
