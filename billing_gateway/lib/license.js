import { createHash, sign, verify } from "node:crypto";

import { base64UrlDecode, base64UrlEncode } from "./encoding.js";
import { PurchaseVerificationError } from "./errors.js";
import { LICENSE_PERIOD_SECONDS } from "./tiers.js";

function completionTime(payment) {
  const raw = payment.completed_at || payment.created_at;
  const millis = Date.parse(raw);
  if (!Number.isFinite(millis)) {
    throw new PurchaseVerificationError();
  }
  return Math.floor(millis / 1000);
}

export function createLicenseToken(config, verifiedPurchase, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!config.licensePrivateKey || !config.licenseKeyId) {
    throw new PurchaseVerificationError();
  }
  const paidAt = completionTime(verifiedPurchase.payment);
  if (paidAt > nowSeconds + 300) throw new PurchaseVerificationError();
  const expiresAt = paidAt + LICENSE_PERIOD_SECONDS;
  if (expiresAt <= nowSeconds) {
    throw new PurchaseVerificationError("Subscription has expired");
  }
  const paymentFingerprint = base64UrlEncode(
    createHash("sha256")
      .update(config.squareEnvironment, "utf8")
      .update("\0", "utf8")
      .update(verifiedPurchase.payment.id, "utf8")
      .digest()
      .subarray(0, 18),
  );
  const header = {
    alg: "EdDSA",
    kid: config.licenseKeyId,
    typ: "PHX-LICENSE",
    v: 1,
  };
  const payload = {
    iss: config.licenseIssuer,
    aud: "phoenix-guardian",
    sub: `square:${paymentFingerprint}`,
    jti: paymentFingerprint,
    purchase_id: verifiedPurchase.receipt.purchase_id,
    tier: verifiedPurchase.receipt.tier,
    iat: paidAt,
    nbf: paidAt,
    exp: expiresAt,
    license_days: 30,
  };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = sign(null, Buffer.from(signingInput, "utf8"), config.licensePrivateKey);
  return {
    token: `${signingInput}.${base64UrlEncode(signature)}`,
    payload,
    keyId: config.licenseKeyId,
  };
}

export function verifyLicenseToken(publicKey, token) {
  if (typeof token !== "string" || token.length > 8192) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const signingInput = `${parts[0]}.${parts[1]}`;
    if (!verify(null, Buffer.from(signingInput, "utf8"), publicKey, base64UrlDecode(parts[2]))) {
      return null;
    }
    const header = JSON.parse(base64UrlDecode(parts[0]).toString("utf8"));
    const payload = JSON.parse(base64UrlDecode(parts[1]).toString("utf8"));
    if (header.alg !== "EdDSA" || header.typ !== "PHX-LICENSE" || header.v !== 1) return null;
    return { header, payload };
  } catch {
    return null;
  }
}
