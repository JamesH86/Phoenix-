import {
  createHash,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";

import { base64UrlEncode, decodeBase64 } from "./encoding.js";
import { ConfigurationError } from "./errors.js";

export const DEFAULT_SQUARE_API_VERSION = "2026-07-15";

function text(value) {
  return typeof value === "string" ? value.trim() : "";
}

function addIssue(issues, name) {
  if (!issues.includes(name)) {
    issues.push(name);
  }
}

function parseUrl(value, { requireHttps = false } = {}) {
  if (!value) {
    return null;
  }
  try {
    const parsed = new URL(value);
    if (requireHttps && parsed.protocol !== "https:") {
      return null;
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return null;
    }
    if (parsed.username || parsed.password || parsed.hash) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function parseAllowedOrigins(raw, issues) {
  const result = new Set();
  if (!raw) {
    return result;
  }
  for (const candidate of raw.split(",").map((item) => item.trim()).filter(Boolean)) {
    const parsed = parseUrl(candidate);
    if (!parsed || parsed.origin !== candidate.replace(/\/$/u, "")) {
      addIssue(issues, "PHOENIX_ALLOWED_ORIGINS");
      continue;
    }
    result.add(parsed.origin);
  }
  return result;
}

function parseReceiptSecret(raw, issues) {
  if (!raw) {
    addIssue(issues, "PHOENIX_PURCHASE_RECEIPT_SECRET_B64");
    return null;
  }
  try {
    const secret = decodeBase64(raw);
    if (secret.length < 32) {
      throw new TypeError("Receipt secret is too short");
    }
    return secret;
  } catch {
    addIssue(issues, "PHOENIX_PURCHASE_RECEIPT_SECRET_B64");
    return null;
  }
}

function parseLicenseKey(raw, issues) {
  if (!raw) {
    addIssue(issues, "PHOENIX_LICENSE_ED25519_PRIVATE_KEY_B64");
    return { privateKey: null, publicKey: null, publicKeySpkiB64: "" };
  }
  try {
    const privateKey = createPrivateKey({
      key: decodeBase64(raw),
      format: "der",
      type: "pkcs8",
    });
    if (privateKey.asymmetricKeyType !== "ed25519") {
      throw new TypeError("License key is not Ed25519");
    }
    const publicKey = createPublicKey(privateKey);
    const publicDer = publicKey.export({ format: "der", type: "spki" });
    return {
      privateKey,
      publicKey,
      publicKeySpkiB64: publicDer.toString("base64"),
    };
  } catch {
    addIssue(issues, "PHOENIX_LICENSE_ED25519_PRIVATE_KEY_B64");
    return { privateKey: null, publicKey: null, publicKeySpkiB64: "" };
  }
}

export function loadConfig(env = process.env) {
  const issues = [];
  const squareEnvironment = text(env.SQUARE_ENVIRONMENT) || "sandbox";
  if (squareEnvironment !== "sandbox" && squareEnvironment !== "production") {
    addIssue(issues, "SQUARE_ENVIRONMENT");
  }
  const production = squareEnvironment === "production";
  const squareBaseUrl = production
    ? "https://connect.squareup.com/v2"
    : "https://connect.squareupsandbox.com/v2";

  const squareAccessToken = text(env.SQUARE_ACCESS_TOKEN);
  const squareApplicationId = text(env.SQUARE_APPLICATION_ID);
  const squareLocationId = text(env.SQUARE_LOCATION_ID);
  const squareApiVersion = text(env.SQUARE_API_VERSION) || DEFAULT_SQUARE_API_VERSION;
  if (!squareAccessToken) addIssue(issues, "SQUARE_ACCESS_TOKEN");
  if (!squareApplicationId) addIssue(issues, "SQUARE_APPLICATION_ID");
  if (!squareLocationId) addIssue(issues, "SQUARE_LOCATION_ID");
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(squareApiVersion)) addIssue(issues, "SQUARE_API_VERSION");

  const receiptSecret = parseReceiptSecret(text(env.PHOENIX_PURCHASE_RECEIPT_SECRET_B64), issues);
  const licenseKeys = parseLicenseKey(text(env.PHOENIX_LICENSE_ED25519_PRIVATE_KEY_B64), issues);

  const requestedKeyId = text(env.PHOENIX_LICENSE_KEY_ID);
  if (requestedKeyId && !/^[A-Za-z0-9._-]{1,64}$/u.test(requestedKeyId)) {
    addIssue(issues, "PHOENIX_LICENSE_KEY_ID");
  }
  const derivedKeyId = licenseKeys.publicKey
    ? base64UrlEncode(
        createHash("sha256")
          .update(licenseKeys.publicKey.export({ format: "der", type: "spki" }))
          .digest()
          .subarray(0, 9),
      )
    : "";
  const licenseKeyId = requestedKeyId || derivedKeyId;

  const licenseIssuer = text(env.PHOENIX_LICENSE_ISSUER) || "phoenix-guardian-billing";
  if (production) {
    const issuerUrl = parseUrl(licenseIssuer, { requireHttps: true });
    if (!issuerUrl) addIssue(issues, "PHOENIX_LICENSE_ISSUER");
  }

  const webhookNotificationUrl = text(env.SQUARE_WEBHOOK_NOTIFICATION_URL);
  const webhookSignatureKey = text(env.SQUARE_WEBHOOK_SIGNATURE_KEY);
  const webhookUrl = parseUrl(webhookNotificationUrl, { requireHttps: production });
  if (webhookNotificationUrl && !webhookUrl) {
    addIssue(issues, "SQUARE_WEBHOOK_NOTIFICATION_URL");
  }
  if (production && !webhookNotificationUrl) addIssue(issues, "SQUARE_WEBHOOK_NOTIFICATION_URL");
  if (production && !webhookSignatureKey) addIssue(issues, "SQUARE_WEBHOOK_SIGNATURE_KEY");

  const allowedOrigins = parseAllowedOrigins(text(env.PHOENIX_ALLOWED_ORIGINS), issues);
  const defaultReturnUrlText = text(env.PHOENIX_DEFAULT_RETURN_URL);
  const defaultReturnUrl = parseUrl(defaultReturnUrlText, { requireHttps: production });
  if (defaultReturnUrlText && !defaultReturnUrl) {
    addIssue(issues, "PHOENIX_DEFAULT_RETURN_URL");
  } else if (defaultReturnUrl && !allowedOrigins.has(defaultReturnUrl.origin)) {
    addIssue(issues, "PHOENIX_DEFAULT_RETURN_URL");
  }

  const squareReady = Boolean(
    squareAccessToken &&
      squareApplicationId &&
      squareLocationId &&
      /^\d{4}-\d{2}-\d{2}$/u.test(squareApiVersion),
  );
  const receiptReady = Boolean(receiptSecret);
  const licenseReady = Boolean(licenseKeys.privateKey && licenseKeys.publicKey && licenseKeyId);
  const webhookReady = Boolean(webhookUrl && webhookSignatureKey);
  const coreReady = squareReady && receiptReady && licenseReady;
  const serviceReady = coreReady && (!production || webhookReady);

  return Object.freeze({
    squareEnvironment,
    production,
    squareBaseUrl,
    squareAccessToken,
    squareApplicationId,
    squareLocationId,
    squareApiVersion,
    receiptSecret,
    licensePrivateKey: licenseKeys.privateKey,
    licensePublicKey: licenseKeys.publicKey,
    licensePublicKeySpkiB64: licenseKeys.publicKeySpkiB64,
    licenseKeyId,
    licenseIssuer,
    webhookNotificationUrl: webhookUrl?.toString() || "",
    webhookSignatureKey,
    allowedOrigins,
    defaultReturnUrl: defaultReturnUrl?.toString() || "",
    squareReady,
    receiptReady,
    licenseReady,
    webhookReady,
    coreReady,
    serviceReady,
    issues: Object.freeze([...issues]),
  });
}

export function requireServiceConfig(env = process.env) {
  const config = loadConfig(env);
  if (!config.serviceReady) {
    throw new ConfigurationError();
  }
  return config;
}

export function publicConfigStatus(config) {
  return {
    ready: config.serviceReady,
    square_environment: config.squareEnvironment,
    square_api_version: config.squareApiVersion,
    components: {
      square: config.squareReady,
      stateless_receipts: config.receiptReady,
      license_signing: config.licenseReady,
      live_webhook: config.webhookReady,
    },
    production_fail_closed: config.production,
    license_key_id: config.licenseKeyId || null,
    license_public_key_spki_b64: config.licensePublicKeySpkiB64 || null,
  };
}

export function resolveReturnUrl(config, requestedUrl, trustedRequestOrigin = "") {
  const candidate = text(requestedUrl) || config.defaultReturnUrl;
  if (!candidate) {
    return "";
  }
  const parsed = parseUrl(candidate, { requireHttps: config.production });
  if (
    !parsed ||
    (!config.allowedOrigins.has(parsed.origin) && parsed.origin !== trustedRequestOrigin)
  ) {
    return null;
  }
  return parsed.toString();
}
